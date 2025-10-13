use crate::{download_file, format_url};
use crate::services::upload::UploadQueue;
use dashmap::DashSet;
use daedalus::minecraft::{Library, VersionManifest};
use daedalus::modded::{
    LoaderVersion, PartialVersionInfo, Processor, SidedDataEntry,
};
use daedalus::get_hash;
use tracing::{info, warn};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::io::Read;
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

/// Skip list for known broken NeoForge/Forge versions
/// These versions have permanent issues (missing files, corrupted archives, etc.)
static NEOFORGE_SKIP_LIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    vec![
        // Add known broken versions here as they're discovered
        // Example: "21.3.0-beta",  // Missing universal JAR
    ]
    .into_iter()
    .collect()
});

fn extract_hash_from_cas_url(url: &str) -> Option<String> {
    let parts: Vec<&str> = url.rsplitn(3, '/').collect();
    if parts.len() >= 2 {
        let hash_suffix = parts[0];
        let hash_prefix = parts[1];
        Some(format!("{}{}", hash_prefix, hash_suffix))
    } else {
        None
    }
}

pub async fn retrieve_data(
    minecraft_versions: &VersionManifest,
    upload_queue: &UploadQueue,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    info!("Retrieving NeoForge data ...");

    let maven_metadata = fetch_maven_metadata(semaphore.clone()).await?;
    let old_manifest = daedalus::modded::fetch_manifest(&format_url(&format!(
        "neoforge/v{}/manifest.json",
        crate::services::cas::CAS_VERSION,
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

    let visited_assets = Arc::new(DashSet::new());

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
                        let visited_assets = Arc::clone(&visited_assets);
                        let semaphore = Arc::clone(&semaphore);
                        let minecraft_version = minecraft_version.clone();

                        async move {
                            // Check skip list first
                            if NEOFORGE_SKIP_LIST.contains(loader_version_full.as_str()) {
                                info!("⏭️  NeoForge - Skipping excluded version: {}", loader_version_full);
                                return Ok::<Option<LoaderVersion>, crate::infrastructure::error::Error>(None);
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

                                    Ok::<ForgeInstallerProfileV2, crate::infrastructure::error::Error>(serde_json::from_str::<ForgeInstallerProfileV2>(&contents)?)
                                }).await??;

                                let mut archive_clone = archive.clone();
                                let version_info = tokio::task::spawn_blocking(move || {
                                    let mut install_profile = archive_clone.by_name("version.json")?;

                                    let mut contents = String::new();
                                    install_profile.read_to_string(&mut contents)?;

                                    Ok::<PartialVersionInfo, crate::infrastructure::error::Error>(serde_json::from_str::<PartialVersionInfo>(&contents)?)
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

                                            Ok::<bytes::Bytes, crate::infrastructure::error::Error>(bytes::Bytes::from(lib_bytes))
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

                                            Ok::<bytes::Bytes, crate::infrastructure::error::Error>(bytes::Bytes::from(lib_bytes))
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

                                    // Check if we've already processed this artifact (lock-free)
                                    if !visited_assets.insert(lib.name.clone()) {
                                        // Already processed, skip download
                                        if let Some(ref mut downloads) = lib.downloads {
                                            if let Some(ref mut artifact) = downloads.artifact {
                                                artifact.url = Some(format_url(&format!("maven/{}", artifact_path)));
                                            }
                                        } else if lib.url.is_some() {
                                            lib.url = Some(format_url("maven/"));
                                        }

                                        return Ok::<Library, crate::infrastructure::error::Error>(lib);
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
                                        upload_queue.enqueue_path(
                                            format!("{}/{}", "maven", artifact_path),
                                            bytes.to_vec(),
                                            Some("application/java-archive".to_string()),
                                        );
                                    }

                                    Ok::<Library, crate::infrastructure::error::Error>(lib)
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

                                let version_bytes = serde_json::to_vec(&new_profile)?;
                                let new_hash = get_hash(bytes::Bytes::from(version_bytes.clone())).await?;

                                let old_loader_version = {
                                    let versions = versions_mutex.lock().await;
                                    versions.iter()
                                        .find(|v| v.id == minecraft_version)
                                        .and_then(|v| v.loaders.iter().find(|l| l.id == loader_version_full))
                                        .cloned()
                                };

                                let should_upload = if let Some(old_version) = &old_loader_version {
                                    if let Some(old_hash) = extract_hash_from_cas_url(&old_version.url) {
                                        if old_hash == new_hash {
                                            info!("✓ NeoForge {} unchanged (hash: {})", loader_version_full, &new_hash[..8]);
                                            false
                                        } else {
                                            info!("↻ NeoForge {} changed (old: {}, new: {})", loader_version_full, &old_hash[..8], &new_hash[..8]);
                                            true
                                        }
                                    } else {
                                        true
                                    }
                                } else {
                                    info!("+ NeoForge {} is new", loader_version_full);
                                    true
                                };

                                let version_hash = if should_upload {
                                    upload_queue.enqueue(
                                        version_bytes.clone(),
                                        Some("application/json".to_string()),
                                    )
                                } else {
                                    new_hash.clone()
                                };

                                manifest_builder.add_version(
                                    "neoforge",
                                    loader_version_full.to_string(),
                                    version_hash.clone(),
                                    version_bytes.len() as u64,
                                );

                                let base_url = dotenvy::var("BASE_URL").unwrap();
                                let cas_url = format!(
                                    "{}/v{}/objects/{}/{}",
                                    base_url,
                                    crate::services::cas::CAS_VERSION,
                                    &version_hash[..2],
                                    &version_hash[2..]
                                );

                                return Ok(Some(LoaderVersion {
                                    id: loader_version_full,
                                    url: cas_url,
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
                        let mut successful = 0;
                        let mut failed = 0;

                        while versions.peek().is_some() {
                            let now = Instant::now();

                            let chunk: Vec<_> = versions.by_ref().take(1).collect();

                            // Process each version and handle errors individually
                            for future in chunk {
                                match future.await {
                                    Ok(result) => {
                                        if let Some(version) = result {
                                            loaders_versions.push(version);
                                            successful += 1;
                                        }
                                    }
                                    Err(e) => {
                                        warn!("⚠️  NeoForge - Failed to process version: {}", e);
                                        failed += 1;
                                        // Continue processing other versions
                                    }
                                }
                            }

                            chunk_index += 1;

                            let elapsed = now.elapsed();
                            info!("Loader Chunk {}/{len} Elapsed: {:.2?} ({} succeeded, {} failed)",
                                chunk_index, elapsed, successful, failed);
                        }

                        if failed > 0 {
                            warn!("⚠️  NeoForge - Skipped {} versions due to errors, {} succeeded", failed, successful);
                        }
                    }
                }

                versions.lock().await.push(daedalus::modded::Version {
                    id: minecraft_version,
                    stable: true,
                    loaders: loaders_versions
                });

                Ok::<(), crate::infrastructure::error::Error>(())
            });
        }
    }

    {
        let len = version_futures.len();
        let mut versions = version_futures.into_iter().peekable();
        let mut chunk_index = 0;
        let mut successful_mc_versions = 0;
        let mut failed_mc_versions = 0;

        while versions.peek().is_some() {
            let now = Instant::now();

            let chunk: Vec<_> = versions.by_ref().take(1).collect();

            // Process each Minecraft version and handle errors individually
            for future in chunk {
                match future.await {
                    Ok(()) => {
                        successful_mc_versions += 1;
                    }
                    Err(e) => {
                        warn!("⚠️  NeoForge - Failed to process Minecraft version: {}", e);
                        failed_mc_versions += 1;
                        // Continue processing other Minecraft versions
                    }
                }
            }

            chunk_index += 1;

            let elapsed = now.elapsed();
            info!("Chunk {}/{len} Elapsed: {:.2?} ({} MC versions succeeded, {} failed)",
                chunk_index, elapsed, successful_mc_versions, failed_mc_versions);
        }

        if failed_mc_versions > 0 {
            warn!("⚠️  NeoForge - {} Minecraft versions failed to process, {} succeeded",
                failed_mc_versions, successful_mc_versions);
        }
    }

    if let Ok(versions) = Arc::try_unwrap(versions) {
        let new_versions = versions.into_inner();

        // Get old versions for merging
        let old_manifest_versions = if let Ok(old_versions) = Arc::try_unwrap(old_versions) {
            old_versions.into_inner()
        } else {
            Vec::new()
        };

        // Merge new versions with old ones: keep old versions + add/update new ones
        let mut final_versions = old_manifest_versions;

        for new_version in new_versions {
            // Find if this Minecraft version already exists
            if let Some(existing) = final_versions.iter_mut().find(|v| v.id == new_version.id) {
                // Merge loaders: keep old loaders + add/update new ones
                for new_loader in new_version.loaders {
                    if let Some(existing_loader) = existing.loaders.iter_mut().find(|l| l.id == new_loader.id) {
                        // Update existing loader
                        let loader_id = new_loader.id.clone();
                        *existing_loader = new_loader;
                        info!("✅ NeoForge - Updated loader: {}/{}", existing.id, loader_id);
                    } else {
                        // Add new loader
                        info!("✅ NeoForge - Added new loader: {}/{}", existing.id, new_loader.id);
                        existing.loaders.push(new_loader);
                    }
                }
            } else {
                // Add new Minecraft version
                info!("✅ NeoForge - Added new Minecraft version: {}", new_version.id);
                final_versions.push(new_version);
            }
        }

        // Sort by Minecraft version order
        final_versions.sort_by(|x, y| {
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

        // Sort loaders within each version
        for version in &mut final_versions {
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

        // Note: Versions are now tracked in ManifestBuilder and uploaded separately
        // in the main loop via manifest_builder.build_loader_manifest()

        info!(
            "✅ NeoForge - Processed {} Minecraft versions",
            final_versions.len()
        );
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
) -> Result<HashMap<String, Vec<(String, bool)>>, crate::infrastructure::error::Error> {
    async fn fetch_values(
        url: &str,
        semaphore: Arc<Semaphore>,
    ) -> Result<Metadata, crate::infrastructure::error::Error> {
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
            info!("Skipping snapshot version: {}", value);
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
            info!("Skipping snapshot version: {}", value);
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
