use crate::{download_file, format_url, upload_file_to_bucket};
use daedalus::minecraft::{Library, VersionManifest};
use daedalus::modded::{
    LoaderVersion, Manifest, PartialVersionInfo, Processor, SidedDataEntry,
};
use log::info;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Read;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

pub async fn retrieve_data(
    minecraft_versions: &VersionManifest,
    uploaded_files: &mut Vec<String>,
    semaphore: Arc<Semaphore>,
) -> Result<(), anyhow::Error> {
    let maven_metadata = fetch_maven_metadata(semaphore.clone()).await?;
    let old_manifest = daedalus::modded::fetch_manifest(&format_url(&format!(
        "neoforge/v{}/manifest.json",
        daedalus::modded::CURRENT_NEOFORGE_FORMAT_VERSION,
    )))
    .await
    .ok();

    let old_versions =
        Arc::new(Mutex::new(if let Some(old_manifest) = old_manifest {
            old_manifest.game_versions
        } else {
            Vec::new()
        }));

    let versions = Arc::new(Mutex::new(Vec::new()));

    let visited_assets_mutex = Arc::new(Mutex::new(Vec::new()));
    let uploaded_files_mutex = Arc::new(Mutex::new(Vec::new()));

    let mut version_futures = Vec::new();

    for (minecraft_version, loader_versions) in maven_metadata.clone() {
        let mut loaders = Vec::new();

        for (loader_version, new_forge) in loader_versions {
            let version = Version::parse(&loader_version)?;

            loaders.push((loader_version, version, new_forge.to_string()))
        }

        if !loaders.is_empty() {
            version_futures.push(async {
                let mut loaders_versions = Vec::new();

                {
                    let loaders_futures = loaders.into_iter().map(|(loader_version_full, _, new_forge)| async {
                        let versions_mutex = Arc::clone(&old_versions);
                        let visited_assets = Arc::clone(&visited_assets_mutex);
                        let uploaded_files_mutex = Arc::clone(&uploaded_files_mutex);
                        let semaphore = Arc::clone(&semaphore);
                        let minecraft_version = minecraft_version.clone();

                        async move {
                            {
                                let versions = versions_mutex.lock().await;
                                let version = versions.iter().find(|x|
                                    x.id == minecraft_version).and_then(|x| x.loaders.iter().find(|x| x.id == loader_version_full));

                                if let Some(version) = version {
                                    return Ok::<Option<LoaderVersion>, anyhow::Error>(Some(version.clone()));
                                }
                            }

                            info!("Neoforge - Installer Start {}", loader_version_full.clone());

                            let download_url = format!("https://maven.neoforged.net/net/neoforged/{1}/{0}/{1}-{0}-installer.jar", loader_version_full, if &*new_forge == "true" { "neoforge" } else { "forge" });

                            let bytes = download_file(&download_url, None, semaphore.clone()).await?;
                            let reader = std::io::Cursor::new(bytes);

                            if let Ok(archive) = zip::ZipArchive::new(reader) {
                                let mut archive_clone = archive.clone();
                                let mut profile = tokio::task::spawn_blocking(move || {
                                    let mut install_profile = archive_clone.by_name("install_profile.json")?;

                                    let mut contents = String::new();
                                    install_profile.read_to_string(&mut contents)?;

                                    Ok::<ForgeInstallerProfileV2, anyhow::Error>(serde_json::from_str::<ForgeInstallerProfileV2>(&contents)?)
                                }).await??;

                                let mut archive_clone = archive.clone();
                                let version_info = tokio::task::spawn_blocking(move || {
                                    let mut install_profile = archive_clone.by_name("version.json")?;

                                    let mut contents = String::new();
                                    install_profile.read_to_string(&mut contents)?;

                                    Ok::<PartialVersionInfo, anyhow::Error>(serde_json::from_str::<PartialVersionInfo>(&contents)?)
                                }).await??;


                                let mut libs : Vec<Library> = version_info.libraries.into_iter().chain(profile.libraries.into_iter().map(|x| Library {
                                    downloads: x.downloads,
                                    extract: x.extract,
                                    name: x.name,
                                    url: x.url,
                                    natives: x.natives,
                                    rules: x.rules,
                                    checksums: x.checksums,
                                    include_in_classpath: false,
                                    patched: false,
                                })).filter(|lib| !lib.name.is_log4j() ).collect();

                                let mut local_libs : HashMap<String, bytes::Bytes> = HashMap::new();

                                for lib in &libs {
                                    if lib.downloads.as_ref().and_then(|x| x.artifact.as_ref().and_then(|x| x.url.as_ref().map(|url| url.is_empty()))).unwrap_or(false) {
                                        let mut archive_clone = archive.clone();
                                        let lib_name_clone = lib.name.clone();

                                        let lib_bytes = tokio::task::spawn_blocking(move || {
                                            let mut lib_file = archive_clone.by_name(&format!("maven/{}", &lib_name_clone.path()))?;
                                            let mut lib_bytes =  Vec::new();
                                            lib_file.read_to_end(&mut lib_bytes)?;

                                            Ok::<bytes::Bytes, anyhow::Error>(bytes::Bytes::from(lib_bytes))
                                        }).await??;

                                        local_libs.insert(lib.name.to_string(), lib_bytes);
                                    }
                                }

                                let path = profile.path.clone();
                                let version = profile.version.clone();

                                for entry in profile.data.values_mut() {
                                    if entry.client.starts_with('/') || entry.server.starts_with('/') {
                                        macro_rules! read_data {
                                    ($value:expr) => {
                                        let mut archive_clone = archive.clone();
                                        let value_clone = $value.clone();
                                        let lib_bytes = tokio::task::spawn_blocking(move || {
                                            let mut lib_file = archive_clone.by_name(&value_clone[1..value_clone.len()])?;
                                            let mut lib_bytes =  Vec::new();
                                            lib_file.read_to_end(&mut lib_bytes)?;

                                            Ok::<bytes::Bytes, anyhow::Error>(bytes::Bytes::from(lib_bytes))
                                        }).await??;

                                        let split = $value.split('/').last();

                                        if let Some(last) = split {
                                            let mut file = last.split('.');

                                            if let Some(file_name) = file.next() {
                                                if let Some(ext) = file.next() {
                                                    let path = format!("{}:{}@{}", path.as_deref().unwrap_or(&*format!("net.minecraftforge:forge:{}", version)), file_name, ext);
                                                    $value = format!("[{}]", &path);
                                                    local_libs.insert(path.clone(), bytes::Bytes::from(lib_bytes));

                                                    libs.push(Library {
                                                        downloads: None,
                                                        extract: None,
                                                        name: path.as_str().try_into()?,
                                                        url: Some("".to_string()),
                                                        natives: None,
                                                        rules: None,
                                                        checksums: None,
                                                        include_in_classpath: false,
                                                        patched: false,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }

                                        if entry.client.starts_with('/') {
                                            read_data!(entry.client);
                                        }

                                        if entry.server.starts_with('/') {
                                            read_data!(entry.server);
                                        }
                                    }
                                }

                                let now = Instant::now();


                                let libs = futures::future::try_join_all(libs.into_iter().map(|mut lib| async {
                                    let artifact_path = &lib.name.path();

                                    {
                                        let mut visited_assets = visited_assets.lock().await;

                                        if visited_assets.contains(&lib.name) {
                                            if let Some(ref mut downloads) = lib.downloads {
                                                if let Some(ref mut artifact) = downloads.artifact {
                                                    artifact.url = Some(format_url(&format!("maven/{}", artifact_path)));
                                                }
                                            } else if lib.url.is_some() {
                                                lib.url = Some(format_url("maven/"));
                                            }

                                            return Ok::<Library, anyhow::Error>(lib);
                                        } else {
                                            visited_assets.push(lib.name.clone())
                                        }
                                    }

                                    let artifact_bytes = if let Some(ref mut downloads) = lib.downloads {
                                        if let Some(ref mut artifact) = downloads.artifact {
                                            let res = if let Some(ref mut url) = artifact.url.as_ref().and_then(|x| if x.is_empty() { None } else { Some(x) }) {
                                                Some(download_file(
                                                    url,
                                                    Some(&*artifact.sha1),
                                                    semaphore.clone(),
                                                )
                                                .await?)
                                            } else {
                                                local_libs.get(&lib.name.to_string()).cloned()
                                            };

                                            if res.is_some() {
                                                artifact.url = Some(format_url(&format!("maven/{}", artifact_path)));
                                            }

                                            res
                                        } else { None }
                                    } else if let Some(ref mut url) = lib.url {
                                        let res = if url.is_empty() {
                                            local_libs.get(&lib.name.to_string()).cloned()
                                        } else {
                                            Some(download_file(
                                                url,
                                                None,
                                                semaphore.clone(),
                                            )
                                                .await?)
                                        };

                                        if res.is_some() {
                                            lib.url = Some(format_url("maven/"));
                                        }

                                        res
                                    } else { None };

                                    if let Some(bytes) = artifact_bytes {
                                        upload_file_to_bucket(
                                            format!("{}/{}", "maven", artifact_path),
                                            bytes.to_vec(),
                                            Some("application/java-archive".to_string()),
                                            uploaded_files_mutex.as_ref(),
                                            semaphore.clone(),
                                        ).await?;
                                    }

                                    Ok::<Library, anyhow::Error>(lib)
                                })).await?;

                                let elapsed = now.elapsed();
                                info!("Elapsed lib DL: {:.2?}", elapsed);

                                let new_profile = PartialVersionInfo {
                                    id: version_info.id,
                                    inherits_from: version_info.inherits_from,
                                    release_time: version_info.release_time,
                                    time: version_info.time,
                                    main_class: version_info.main_class,
                                    minecraft_arguments: version_info.minecraft_arguments,
                                    arguments: version_info.arguments,
                                    libraries: libs,
                                    type_: version_info.type_,
                                    data: Some(profile.data),
                                    processors: Some(profile.processors),
                                    logging: None
                                };

                                let version_path = format!(
                                    "neoforge/v{}/versions/{}.json",
                                    daedalus::modded::CURRENT_NEOFORGE_FORMAT_VERSION,
                                    loader_version_full
                                );

                                upload_file_to_bucket(
                                    version_path.clone(),
                                    serde_json::to_vec(&new_profile)?,
                                    Some("application/json".to_string()),
                                    uploaded_files_mutex.as_ref(),
                                    semaphore.clone(),
                                ).await?;

                                return Ok(Some(LoaderVersion {
                                    id: loader_version_full,
                                    url: format_url(&version_path),
                                    stable: false
                                }));
                            }

                            Ok(None)
                        }.await
                    });

                    {
                        let len = loaders_futures.len();
                        let mut versions = loaders_futures.into_iter().peekable();
                        let mut chunk_index = 0;
                        while versions.peek().is_some() {
                            let now = Instant::now();

                            let chunk: Vec<_> = versions.by_ref().take(1).collect();
                            let res = futures::future::try_join_all(chunk).await?;
                            loaders_versions.extend(res.into_iter().flatten());

                            chunk_index += 1;

                            let elapsed = now.elapsed();
                            info!("Loader Chunk {}/{len} Elapsed: {:.2?}", chunk_index, elapsed);
                        }
                    }
                }

                versions.lock().await.push(daedalus::modded::Version {
                    id: minecraft_version,
                    stable: true,
                    loaders: loaders_versions
                });

                Ok::<(), anyhow::Error>(())
            });
        }
    }

    {
        let len = version_futures.len();
        let mut versions = version_futures.into_iter().peekable();
        let mut chunk_index = 0;
        while versions.peek().is_some() {
            let now = Instant::now();

            let chunk: Vec<_> = versions.by_ref().take(1).collect();
            futures::future::try_join_all(chunk).await?;

            chunk_index += 1;

            let elapsed = now.elapsed();
            info!("Chunk {}/{len} Elapsed: {:.2?}", chunk_index, elapsed);
        }
    }

    if let Ok(versions) = Arc::try_unwrap(versions) {
        let mut versions = versions.into_inner();

        versions.sort_by(|x, y| {
            minecraft_versions
                .versions
                .iter()
                .position(|z| x.id == z.id)
                .unwrap_or_default()
                .cmp(
                    &minecraft_versions
                        .versions
                        .iter()
                        .position(|z| y.id == z.id)
                        .unwrap_or_default(),
                )
        });

        for version in &mut versions {
            let loader_versions = maven_metadata.get(&version.id);
            if let Some(loader_versions) = loader_versions {
                version.loaders.sort_by(|x, y| {
                    loader_versions
                        .iter()
                        .position(|z| y.id == z.0)
                        .unwrap_or_default()
                        .cmp(
                            &loader_versions
                                .iter()
                                .position(|z| x.id == z.0)
                                .unwrap_or_default(),
                        )
                });
            }
        }

        upload_file_to_bucket(
            format!(
                "neoforge/v{}/manifest.json",
                daedalus::modded::CURRENT_NEOFORGE_FORMAT_VERSION,
            ),
            serde_json::to_vec(&Manifest {
                game_versions: versions,
            })?,
            Some("application/json".to_string()),
            uploaded_files_mutex.as_ref(),
            semaphore,
        )
        .await?;
    }

    if let Ok(uploaded_files_mutex) = Arc::try_unwrap(uploaded_files_mutex) {
        uploaded_files.extend(uploaded_files_mutex.into_inner());
    }

    Ok(())
}

const DEFAULT_MAVEN_METADATA_URL_1: &str =
    "https://maven.neoforged.net/net/neoforged/forge/maven-metadata.xml";
const DEFAULT_MAVEN_METADATA_URL_2: &str =
    "https://maven.neoforged.net/net/neoforged/neoforge/maven-metadata.xml";

#[derive(Debug, Deserialize)]
struct Metadata {
    versioning: Versioning,
}

#[derive(Debug, Deserialize)]
struct Versioning {
    versions: Versions,
}

#[derive(Debug, Deserialize)]
struct Versions {
    version: Vec<String>,
}

pub async fn fetch_maven_metadata(
    semaphore: Arc<Semaphore>,
) -> Result<HashMap<String, Vec<(String, bool)>>, anyhow::Error> {
    async fn fetch_values(
        url: &str,
        semaphore: Arc<Semaphore>,
    ) -> Result<Metadata, anyhow::Error> {
        Ok(serde_xml_rs::from_str(
            &String::from_utf8(
                download_file(url, None, semaphore).await?.to_vec(),
            )
            .unwrap_or_default(),
        )?)
    }

    let forge_values =
        fetch_values(DEFAULT_MAVEN_METADATA_URL_1, semaphore.clone()).await?;
    let neo_values =
        fetch_values(DEFAULT_MAVEN_METADATA_URL_2, semaphore).await?;

    let mut map: HashMap<String, Vec<(String, bool)>> = HashMap::new();

    for value in forge_values.versioning.versions.version {
        let is_snapshot = value.contains('w') || 
                          value.contains("-pre") || 
                          value.contains("-rc");

        if is_snapshot {
            log::info!("Skipping snapshot version: {}", value);
            continue;
        }
        let original = value.clone();

        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() == 2 {
            map.entry(parts[0].to_string())
                .or_default()
                .push((original, false));
        }
    }

    for value in neo_values.versioning.versions.version {
        let is_snapshot = value.contains('w') || 
                          value.contains("-pre") || 
                          value.contains("-rc");

        if is_snapshot {
            log::info!("Skipping snapshot version: {}", value);
            continue;
        }
        
        let original = value.clone();

        let mut parts = value.split('.');

        if let Some(minor) = parts.next() {
            if let Some(patch) = parts.next() {
                let mut game_version = format!("1.{}", minor);

                if patch != "0" {
                    game_version.push_str(&format!(".{}", patch));
                }

                map.entry(game_version.clone())
                    .or_default()
                    .push((original.clone(), true));
            }
        }
    }

    Ok(map)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ForgeInstallerProfileV2 {
    pub profile: String,
    pub version: String,
    pub json: String,
    pub path: Option<String>,
    pub minecraft: String,
    pub data: HashMap<String, SidedDataEntry>,
    pub libraries: Vec<Library>,
    pub processors: Vec<Processor>,
}
