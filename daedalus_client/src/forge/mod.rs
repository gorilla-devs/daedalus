//! Forge loader metadata retrieval and processing

pub mod types;
pub mod archive;
pub mod libraries;
pub mod version;

// Re-export commonly used types
pub use types::{
    ForgeInstallerProfileV1,
    ForgeInstallerProfileV2,
    MinecraftVersionLibraryCache,
};

use crate::{
    download_file, download_file_mirrors, format_url,
};
use crate::services::upload::BatchUploader;
use dashmap::DashSet;
use daedalus::minecraft::{
    Argument, ArgumentType, Library, VersionManifest,
};
use daedalus::modded::{
    LoaderVersion, PartialVersionInfo,
};
use daedalus::{get_hash, GradleSpecifier};
use tracing::{info, warn};
use semver::{Version, VersionReq};
use std::collections::HashMap;
use std::convert::{TryInto, TryFrom};
use std::io::Read;
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

static FORGE_MANIFEST_V1_QUERY: LazyLock<VersionReq> = LazyLock::new(|| {
    VersionReq::parse(">=8.0.684, <23.5.2851").unwrap()
});

static FORGE_MANIFEST_V2_QUERY_P1: LazyLock<VersionReq> = LazyLock::new(|| {
    VersionReq::parse(">=23.5.2851, <31.2.52").unwrap()
});

static FORGE_MANIFEST_V2_QUERY_P2: LazyLock<VersionReq> = LazyLock::new(|| {
    VersionReq::parse(">=32.0.1, <37.0.0").unwrap()
});

static FORGE_MANIFEST_V3_QUERY: LazyLock<VersionReq> = LazyLock::new(|| {
    VersionReq::parse(">=37.0.0").unwrap()
});

// Re-export version utilities for convenience
pub use version::{extract_hash_from_cas_url, fetch_generated_version_info, should_ignore_artifact};

// Temporary: Keep retrieve_data here until we refactor it
// This will be broken down in Phase 1.5
pub async fn retrieve_data(
    minecraft_versions: &VersionManifest,
    uploader: &BatchUploader,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    s3_client: &s3::Bucket,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    info!("Retrieving Forge data ...");

    let maven_metadata = fetch_maven_metadata(None, semaphore.clone()).await?;

    let old_manifest = daedalus::modded::fetch_manifest(&format_url(&format!(
        "forge/v{}/manifest.json",
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

    let mc_library_cache_mutex =
        Arc::new(Mutex::new(MinecraftVersionLibraryCache::new()));

    let versions = Arc::new(Mutex::new(Vec::new()));

    let visited_assets = Arc::new(DashSet::new());

    let mut version_futures = Vec::new();

    for (minecraft_version, loader_versions) in maven_metadata.clone() {
        let mut loaders = Vec::new();

        for loader_version_full in loader_versions {

            let is_snapshot = minecraft_version.contains('w') ||
                              minecraft_version.contains("-pre") ||
                              minecraft_version.contains("-rc");

            if is_snapshot {
                info!("Skipping snapshot version: {}", loader_version_full);
                continue;
            }

            let loader_version = loader_version_full.split('-').nth(1);

            if let Some(loader_version_raw) = loader_version {
                let split =
                    loader_version_raw.split('.').collect::<Vec<&str>>();
                let loader_version = if split.len() >= 4 {
                    if split[0].parse::<i32>().unwrap_or(0) < 6 {
                        format!("{}.{}.{}", split[0], split[1], split[3])
                    } else {
                        format!("{}.{}.{}", split[1], split[2], split[3])
                    }
                } else {
                    loader_version_raw.to_string()
                };

                let version = Version::parse(&loader_version)?;

                if FORGE_MANIFEST_V1_QUERY.matches(&version)
                    || FORGE_MANIFEST_V2_QUERY_P1.matches(&version)
                    || FORGE_MANIFEST_V2_QUERY_P2.matches(&version)
                    || FORGE_MANIFEST_V3_QUERY.matches(&version)
                {
                    loaders.push((loader_version_full, version))
                }
            }
        }

        if !loaders.is_empty() {
            version_futures.push(async {
                let mut loaders_versions = Vec::new();

                {
                    let loaders_futures = loaders.into_iter().map(|(loader_version_full, version)| async {
                        let mc_library_cache_mutex = Arc::clone(&mc_library_cache_mutex);
                        let versions_mutex = Arc::clone(&old_versions);
                        let visited_assets = Arc::clone(&visited_assets);
                        let semaphore = Arc::clone(&semaphore);
                        let minecraft_version = minecraft_version.clone();

                        async move {
                            /// These forge versions are not worth supporting!
                            const FORGE_SKIP_LIST : &[&str] = &[
                                // Not supported due to `data` field being `[]` even though the type is a map
                                "1.12.2-14.23.5.2851",
                                // Malformed Archives
                                "1.6.1-8.9.0.749",
                                "1.6.1-8.9.0.751",
                                "1.6.4-9.11.1.960",
                                "1.6.4-9.11.1.961",
                                "1.6.4-9.11.1.963",
                                "1.6.4-9.11.1.964",
                            ];

                            if FORGE_SKIP_LIST.contains(&&*loader_version_full) {
                                info!("⏭️  Forge - Skipping excluded version: {}", loader_version_full);
                                return Ok::<Option<LoaderVersion>, crate::infrastructure::error::Error>(None);
                            }


                            info!("Forge - Installer Start {}", loader_version_full.clone());
                            let bytes = download_file(&format!("https://maven.minecraftforge.net/net/minecraftforge/forge/{0}/forge-{0}-installer.jar", loader_version_full), None, semaphore.clone()).await?;

                            let reader = std::io::Cursor::new(bytes);

                            if let Ok(archive) = zip::ZipArchive::new(reader) {
                                if FORGE_MANIFEST_V1_QUERY.matches(&version) {
                                    let mut archive_clone = archive.clone();
                                    let profile = tokio::task::spawn_blocking(move || {
                                        let mut install_profile = archive_clone.by_name("install_profile.json")?;

                                        let mut contents = String::new();
                                        install_profile.read_to_string(&mut contents)?;

                                        Ok::<ForgeInstallerProfileV1, crate::infrastructure::error::Error>(serde_json::from_str::<ForgeInstallerProfileV1>(&contents)?)
                                    }).await??;

                                    let mut archive_clone = archive.clone();
                                    let file_path = profile.install.file_path.clone();
                                    let forge_universal_bytes = tokio::task::spawn_blocking(move || {
                                        let mut forge_universal_file = archive_clone.by_name(&file_path)?;
                                        let mut forge_universal =  Vec::new();
                                        forge_universal_file.read_to_end(&mut forge_universal)?;


                                        Ok::<bytes::Bytes, crate::infrastructure::error::Error>(bytes::Bytes::from(forge_universal))
                                    }).await??;
                                    let forge_universal_path = profile.install.path.clone();

                                    let now = Instant::now();

                                    let minecraft_libs_filter = {
                                        let mut mc_library_cache = mc_library_cache_mutex.lock().await;
                                        mc_library_cache.load_minecraft_version_libs(&profile.install.minecraft).await?.clone()
                                    };
                                    let libs = futures::future::try_join_all(profile.version_info.libraries.into_iter().map(|mut lib| {
                                        let semaphore = semaphore.clone();
                                        let visited_assets = visited_assets.clone();
                                        let forge_universal_bytes = forge_universal_bytes.clone();
                                        let forge_universal_path = forge_universal_path.clone();
                                        let minecraft_libs_filter = minecraft_libs_filter.clone();

                                        async move {
                                        if lib.name.is_lwjgl() || lib.name.is_log4j() || should_ignore_artifact(&minecraft_libs_filter, &lib.name) {
                                            return Ok::<Option<Library>, crate::infrastructure::error::Error>(None);
                                        }

                                        // let mut repo_url
                                        if let Some(url) = lib.url {
                                            // Check if we've already processed this artifact (lock-free)
                                            if !visited_assets.insert(lib.name.clone()) {
                                                // Already processed, skip download
                                                let base_url = dotenvy::var("BASE_URL").unwrap();
                                                lib.url = Some(format!(
                                                    "{}/v{}/objects/",
                                                    base_url,
                                                    crate::services::cas::CAS_VERSION
                                                ));
                                                return Ok::<Option<Library>, crate::infrastructure::error::Error>(Some(lib));
                                            }

                                            let artifact_path = lib.name.path();
                                            let mirrors = vec![url.as_str(), "https://maven.creeperhost.net/", "https://libraries.minecraft.net/"];
                                            let artifact = if lib.name.to_string() == forge_universal_path {
                                                forge_universal_bytes.clone()
                                            } else {
                                                download_file_mirrors(
                                                    &artifact_path,
                                                    &mirrors,
                                                    None,
                                                    semaphore.clone(),
                                                )
                                                .await?
                                            };

                                            // Upload to CAS and get hash
                                            let hash = uploader.upload_cas(
                                                artifact.to_vec(),
                                                Some("application/java-archive".to_string()),
                                                s3_client,
                                                semaphore.clone(),
                                            ).await?;

                                            // Store full CAS URL
                                            let base_url = dotenvy::var("BASE_URL").unwrap();
                                            lib.url = Some(format!(
                                                "{}/v{}/objects/{}/{}",
                                                base_url,
                                                crate::services::cas::CAS_VERSION,
                                                &hash[..2],
                                                &hash[2..]
                                            ));
                                        } else if lib.downloads.is_none() {
                                            lib.url = Some(String::from("https://libraries.minecraft.net/"));
                                        }


                                        Ok::<Option<Library>, crate::infrastructure::error::Error>(Some(lib))
                                    }})).await?;

                                    let elapsed = now.elapsed();
                                    info!("Elapsed lib DL: {:.2?}", elapsed);

                                    let new_profile = PartialVersionInfo {
                                        id: profile.version_info.id,
                                        inherits_from: profile.install.minecraft,
                                        release_time: profile.version_info.release_time,
                                        time: profile.version_info.time,
                                        main_class: profile.version_info.main_class,
                                        minecraft_arguments: profile.version_info.minecraft_arguments.clone(),
                                        arguments: profile.version_info.minecraft_arguments.map(|x| [(ArgumentType::Game, x.split(' ').map(|x| Argument::Normal(x.to_string())).collect())].iter().cloned().collect()),
                                        libraries: libs.into_iter().flatten().collect(),
                                        type_: profile.version_info.type_,
                                        logging: None,
                                        data: None,
                                        processors: None
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

                                    // Use common change detection logic
                                    let change_result = crate::common::change_detection::detect_version_change(
                                        "Forge",
                                        &loader_version_full,
                                        old_loader_version.as_ref().map(|v| v.url.as_str()),
                                        &new_hash,
                                    );
                                    let should_upload = change_result.should_upload;

                                    let version_hash = if should_upload {
                                        uploader.upload_cas(
                                            version_bytes.clone(),
                                            Some("application/json".to_string()),
                                            s3_client,
                                            semaphore.clone(),
                                        ).await?
                                    } else {
                                        new_hash.clone()
                                    };

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
                                } else if FORGE_MANIFEST_V2_QUERY_P1.matches(&version) || FORGE_MANIFEST_V2_QUERY_P2.matches(&version) || FORGE_MANIFEST_V3_QUERY.matches(&version) {
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


                                    let mut libs : Vec<Library> = version_info.libraries
                                        .into_iter()
                                        .chain(profile.libraries
                                            .into_iter()
                                            .map(|x| Library {
                                                downloads: x.downloads,
                                                extract: x.extract,
                                                name: x.name,
                                                url: x.url,
                                                natives: x.natives,
                                                rules: x.rules,
                                                checksums: x.checksums,
                                                include_in_classpath: false,
                                                version_hashes: None,
                                                patched: false,
                                            })
                                        )
                                        .filter(|lib| !lib.name.is_log4j() )
                                        .collect();

                                    let mut local_libs : HashMap<String, Option<bytes::Bytes>> = HashMap::new();

                                    let mut i = 0;
                                    loop {
                                        let Some(lib) = &libs.get(i) else {
                                            break;
                                        };

                                        if libraries::is_local_lib(lib) {
                                            let mut archive_clone = archive.clone();
                                            let lib_name_clone = lib.name.clone();

                                            let lib_bytes = tokio::task::spawn_blocking(move || {
                                                let entry_name = format!("maven/{}", lib_name_clone.path());
                                                let lib_file = archive_clone.by_name(&entry_name).map_err(|err| {
                                                    crate::infrastructure::error::invalid_input(format!("Failed to find entry {} in installer jar: {}", entry_name, err))
                                                });

                                                // Thank you forge for always making it hard to parse your data
                                                // 1.20.4+ has a local lib that doesn't exist in the installer jar
                                                // Not sure what it does, but it doesn't seem to be needed
                                                if lib_file.is_err() && &*lib_name_clone.artifact == "forge" {
                                                    return Ok::<_, crate::infrastructure::error::Error>(None);
                                                }

                                                let mut lib_file = lib_file?;

                                                let mut lib_bytes =  Vec::new();
                                                lib_file.read_to_end(&mut lib_bytes)?;

                                                let result = Some(bytes::Bytes::from(lib_bytes));

                                                Ok::<_, crate::infrastructure::error::Error>(result)
                                            }).await??;

                                            local_libs.insert(lib.name.to_string(), lib_bytes);

                                        }

                                        i += 1;
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
                                                                // We need to append tne entry to the forge path
                                                                // Since new versions (1.20.4?) forge started filling the `path` key with a valid maven path (was previously empty)
                                                                // To avoid having multiple classifiers (invalid maven path) we parse it as a GradleSpecifier
                                                                // which will consider multiple classifiers as a single classifier replacing the `:` with a `-`
                                                                let unsanitized_path = format!("{}:{}@{}", path.as_deref().unwrap_or(&*format!("net.minecraftforge:forge:{}", version)), file_name, ext);
                                                                let path = GradleSpecifier::try_from(&*unsanitized_path)?.to_string();
                                                                $value = format!("[{}]", &path);
                                                                local_libs.insert(path.clone(), Some(bytes::Bytes::from(lib_bytes)));

                                                                libs.push(Library {
                                                                    downloads: None,
                                                                    extract: None,
                                                                    name: path.as_str().try_into()?,
                                                                    url: Some("".to_string()),
                                                                    natives: None,
                                                                    rules: None,
                                                                    checksums: None,
                                                                    include_in_classpath: false,
                                                                    version_hashes: None,
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


                                    let libs = futures::future::try_join_all(libs.into_iter().map(|mut lib| {
                                        let semaphore = semaphore.clone();
                                        let visited_assets = visited_assets.clone();
                                        let local_libs = local_libs.clone();

                                        async move {
                                        let artifact_path = lib.name.path();

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

                                            return Ok::<Option<Library>, crate::infrastructure::error::Error>(Some(lib));
                                        }

                                        let artifact_bytes = if let Some(ref mut downloads) = lib.downloads {
                                            if let Some(ref mut artifact) = downloads.artifact {
                                                let res = if let Some(url) = artifact.url.as_ref().filter(|x| !x.is_empty()) {
                                                    Some(download_file(
                                                        url,
                                                        Some(&*artifact.sha1),
                                                        semaphore.clone(),
                                                    ).await?)
                                                } else {
                                                    local_libs.get(&lib.name.to_string()).cloned().flatten()
                                                };

                                                if res.is_some() {
                                                    artifact.url = Some(format_url(&format!("maven/{}", artifact_path)));
                                                } else {
                                                    artifact.url = None;
                                                }

                                                res
                                            } else { None }
                                        } else if let Some(ref mut url) = lib.url {
                                            let res = if url.is_empty() {
                                                local_libs.get(&lib.name.to_string()).cloned().flatten()
                                            } else {
                                                let lib_url = format!("{}/{}", url, lib.name.path());
                                                Some(download_file(
                                                    &lib_url,
                                                    None,
                                                    semaphore.clone(),
                                                ).await?)
                                            };

                                            if res.is_some() {
                                                lib.url = Some(format_url("maven/"));
                                            } else {
                                                lib.url = None;
                                            }

                                            res
                                        } else {
                                            // assume its a mojang provided lib
                                            info!("Forge library dependency {} has no url, assuming it is mojang provided", lib.name.to_string());

                                            lib.url = Some(String::from("https://libraries.minecraft.net/"));

                                            None
                                        };

                                        if let Some(bytes) = artifact_bytes {
                                            // Upload to CAS and get hash
                                            let hash = uploader.upload_cas(
                                                bytes.to_vec(),
                                                Some("application/java-archive".to_string()),
                                                s3_client,
                                                semaphore.clone(),
                                            ).await?;

                                            // Store full CAS URL
                                            let base_url = dotenvy::var("BASE_URL").unwrap();
                                            let cas_url = format!(
                                                "{}/v{}/objects/{}/{}",
                                                base_url,
                                                crate::services::cas::CAS_VERSION,
                                                &hash[..2],
                                                &hash[2..]
                                            );

                                            // Update library URL with CAS URL
                                            if let Some(ref mut downloads) = lib.downloads {
                                                if let Some(ref mut artifact) = downloads.artifact {
                                                    artifact.url = Some(cas_url);
                                                }
                                            } else if lib.url.is_some() {
                                                lib.url = Some(cas_url);
                                            }
                                        }

                                        Ok::<Option<Library>, crate::infrastructure::error::Error>(Some(lib))
                                    }})).await?;

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
                                        libraries: libs.into_iter().flatten().collect(),
                                        type_: version_info.type_,
                                        logging: None,
                                        data: Some(profile.data),
                                        processors: Some(profile.processors),
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

                                    // Use common change detection logic
                                    let change_result = crate::common::change_detection::detect_version_change(
                                        "Forge",
                                        &loader_version_full,
                                        old_loader_version.as_ref().map(|v| v.url.as_str()),
                                        &new_hash,
                                    );
                                    let should_upload = change_result.should_upload;

                                    let version_hash = if should_upload {
                                        uploader.upload_cas(
                                            version_bytes.clone(),
                                            Some("application/json".to_string()),
                                            s3_client,
                                            semaphore.clone(),
                                        ).await?
                                    } else {
                                        new_hash.clone()
                                    };

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

                            // Handle each future individually to prevent crashing on errors
                            for future in chunk {
                                match future.await {
                                    Ok(result) => {
                                        if let Some(loader_version) = result {
                                            loaders_versions.push(loader_version);
                                            successful += 1;
                                        }
                                    }
                                    Err(e) => {
                                        warn!("⚠️  Forge - Failed to process version: {}", e);
                                        failed += 1;
                                        // Continue processing other versions
                                    }
                                }
                            }

                            chunk_index += 1;

                            let elapsed = now.elapsed();
                            info!("Loader Chunk {}/{len} Elapsed: {:.2?} (✓ {} ✗ {})", chunk_index, elapsed, successful, failed);
                        }

                        info!("📊 Forge - Loader processing complete: {} successful, {} failed", successful, failed);
                    }
                    //futures::future::try_join_all(loaders_futures).await?;
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
        let mut successful = 0;
        let mut failed = 0;

        while versions.peek().is_some() {
            let now = Instant::now();

            let chunk: Vec<_> = versions.by_ref().take(1).collect();

            // Handle each future individually to prevent crashing on errors
            for future in chunk {
                match future.await {
                    Ok(_) => {
                        successful += 1;
                    }
                    Err(e) => {
                        warn!("⚠️  Forge - Failed to process Minecraft version: {}", e);
                        failed += 1;
                        // Continue processing other versions
                    }
                }
            }

            chunk_index += 1;

            let elapsed = now.elapsed();
            info!("Chunk {}/{len} Elapsed: {:.2?} (✓ {} ✗ {})", chunk_index, elapsed, successful, failed);
        }

        info!("📊 Forge - Minecraft version processing complete: {} successful, {} failed", successful, failed);
    }
    //futures::future::try_join_all(version_futures).await?;

    // Get old manifest versions for merging
    let old_manifest_versions = if let Ok(old_versions) = Arc::try_unwrap(old_versions) {
        old_versions.into_inner()
    } else {
        Vec::new()
    };

    if let Ok(versions) = Arc::try_unwrap(versions) {
        let new_versions = versions.into_inner();

        // Merge new versions with old ones to preserve existing data
        let mut final_versions = old_manifest_versions;

        for new_version in new_versions {
            if let Some(existing) = final_versions.iter_mut().find(|v| v.id == new_version.id) {
                // Merge loaders: keep old loaders + add/update new ones
                for new_loader in new_version.loaders {
                    if let Some(existing_loader) = existing.loaders.iter_mut().find(|l| l.id == new_loader.id) {
                        let loader_id = new_loader.id.clone();
                        *existing_loader = new_loader;
                        info!("✅ Forge - Updated loader: {}/{}", existing.id, loader_id);
                    } else {
                        info!("✅ Forge - Added new loader: {}/{}", existing.id, new_loader.id);
                        existing.loaders.push(new_loader);
                    }
                }
            } else {
                info!("✅ Forge - Added new Minecraft version: {}", new_version.id);
                final_versions.push(new_version);
            }
        }

        // Sort versions
        final_versions.sort_by(|x, y| {
            minecraft_versions
                .versions
                .iter()
                .position(|z| {
                    x.id.replace("1.7.10_pre4", "1.7.10-pre4") == z.id
                })
                .unwrap_or_default()
                .cmp(
                    &minecraft_versions
                        .versions
                        .iter()
                        .position(|z| {
                            y.id.replace("1.7.10_pre4", "1.7.10-pre4") == z.id
                        })
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
                        .position(|z| &y.id == z)
                        .unwrap_or_default()
                        .cmp(
                            &loader_versions
                                .iter()
                                .position(|z| &x.id == z)
                                .unwrap_or_default(),
                        )
                })
            }
        }

        // Set the full Forge versions JSON in manifest_builder with nested structure
        // This preserves game version -> loader version mappings
        let versions_json = serde_json::to_value(&final_versions)?;
        manifest_builder.set_loader_versions("forge", versions_json);
        info!(version_count = final_versions.len(), "Set Forge versions with nested structure in CAS manifest builder");
    }

    Ok(())
}

const DEFAULT_MAVEN_METADATA_URL: &str =
    "https://files.minecraftforge.net/net/minecraftforge/forge/maven-metadata.json";

/// Fetches the forge maven metadata from the specified URL. If no URL is specified, the default is used.
/// Returns a hashmap specifying the versions of the forge mod loader
/// The hashmap key is a Minecraft version, and the value is the loader versions that work on
/// the specified Minecraft version
pub async fn fetch_maven_metadata(
    url: Option<&str>,
    semaphore: Arc<Semaphore>,
) -> Result<HashMap<String, Vec<String>>, crate::infrastructure::error::Error> {
    Ok(serde_json::from_slice(
        &download_file(
            url.unwrap_or(DEFAULT_MAVEN_METADATA_URL),
            None,
            semaphore,
        )
        .await?,
    )?)
}
