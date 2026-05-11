//! NeoForge loader processing
//!
//! This module handles NeoForge version retrieval and processing,
//! using common utilities shared with other loaders.

pub mod types;

use crate::{download_file, format_url};
use crate::services::upload::BatchUploader;
use crate::common::{change_detection::detect_version_change, manifest_merge::{merge_loader_versions, sort_by_minecraft_order, sort_loaders_by_metadata}};
use dashmap::DashSet;
use daedalus::minecraft::{Library, VersionManifest};
use daedalus::modded::{
    LoaderVersion, PartialVersionInfo, SidedDataEntry,
};
use daedalus::get_hash;
use tracing::{info, warn};
// Note: Using lenient_semver instead of semver::Version to handle
// non-standard NeoForge versions like "26.1.0.0-alpha.1+snapshot-1"
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryInto;
use std::io::Read;
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

// Re-export types
pub use types::NeoForgeInstallerProfile;

/// Skip list for known broken NeoForge/Forge versions
/// These versions have permanent issues (missing files, corrupted archives, etc.)
static NEOFORGE_SKIP_LIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    vec![
        // Unreachable / 404 versions (synced from Modrinth daedalus)
        "1.20.1-47.1.7",
        "47.1.82",
    ]
    .into_iter()
    .collect()
});

pub async fn retrieve_data(
    minecraft_versions: &VersionManifest,
    uploader: &BatchUploader,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    s3_client: &s3::Bucket,
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

    let versions: Arc<Mutex<Vec<daedalus::modded::Version>>> = Arc::new(Mutex::new(Vec::new()));

    let visited_assets = Arc::new(DashSet::new());

    let mut version_futures = Vec::new();

    // The maven-metadata grouping by inferred MC is still used to scope the inner futures,
    // but the actual published Minecraft id comes from each installer's profile.minecraft.
    for (_inferred_mc_version, loader_versions) in maven_metadata.clone() {
        let mut loaders = Vec::new();

        for (loader_version, new_forge) in loader_versions {
            // Validate version format using lenient_semver (handles 4+ component versions like "26.1.0.0-alpha.1")
            if let Err(e) = lenient_semver::parse(&loader_version) {
                warn!("Skipping NeoForge version '{}' with invalid format: {}", loader_version, e);
                continue;
            }

            loaders.push((loader_version, new_forge.to_string()))
        }

        if !loaders.is_empty() {
            version_futures.push(async {
                let mut loaders_versions = Vec::new();

                {
                    let loaders_futures = loaders.into_iter().map(|(loader_version_full, new_forge)| async {
                        let versions_mutex = Arc::clone(&old_versions);
                        let visited_assets = Arc::clone(&visited_assets);
                        let semaphore = Arc::clone(&semaphore);

                        async move {
                            // Check skip list first
                            if NEOFORGE_SKIP_LIST.contains(loader_version_full.as_str()) {
                                info!("⏭️  NeoForge - Skipping excluded version: {}", loader_version_full);
                                return Ok::<Option<(String, LoaderVersion)>, crate::infrastructure::error::Error>(None);
                            }

                            info!("Neoforge - Installer Start {}", loader_version_full.clone());

                            let download_url = format!("https://maven.neoforged.net/releases/net/neoforged/{1}/{0}/{1}-{0}-installer.jar", loader_version_full, if &*new_forge == "true" { "neoforge" } else { "forge" });

                            let bytes = download_file(&download_url, None, semaphore.clone()).await?;
                            let reader = std::io::Cursor::new(bytes);

                            if let Ok(archive) = zip::ZipArchive::new(reader) {
                                let mut archive_clone = archive.clone();
                                let mut profile = tokio::task::spawn_blocking(move || {
                                    let mut install_profile = archive_clone.by_name("install_profile.json")?;

                                    let mut contents = String::new();
                                    install_profile.read_to_string(&mut contents)?;

                                    Ok::<NeoForgeInstallerProfile, crate::infrastructure::error::Error>(serde_json::from_str::<NeoForgeInstallerProfile>(&contents)?)
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
                                    version_hashes: None,
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

                                let version = profile.version.clone();

                                // Use BTreeMap iteration order for determinism — pushed library order
                                // ends up in `libs` and is later included in the version JSON we hash.
                                let profile_data: BTreeMap<String, SidedDataEntry> =
                                    profile.data.into_iter().collect();
                                profile.data = HashMap::new();

                                let mut sorted_data: BTreeMap<String, SidedDataEntry> = BTreeMap::new();

                                for (key, mut entry) in profile_data {
                                    if entry.client.starts_with('/') || entry.server.starts_with('/') {
                                        // Tag artifact identifier with the side so client/server data
                                        // entries that share a filename don't collide on the same coord.
                                        macro_rules! read_data {
                                            ($value:expr, $side:literal) => {
                                                let mut archive_clone = archive.clone();
                                                let value_clone = $value.clone();
                                                // Validate path has content after the leading slash
                                                if value_clone.len() <= 1 {
                                                    warn!("Skipping invalid NeoForge data path '{}' (key: {}, side: {})", value_clone, key, $side);
                                                } else {
                                                    let lib_bytes = tokio::task::spawn_blocking(move || {
                                                        let mut lib_file = archive_clone.by_name(&value_clone[1..])?;
                                                        let mut lib_bytes =  Vec::new();
                                                        lib_file.read_to_end(&mut lib_bytes)?;

                                                        Ok::<bytes::Bytes, crate::infrastructure::error::Error>(bytes::Bytes::from(lib_bytes))
                                                    }).await??;

                                                    let split = $value.rsplit('/').next();

                                                    if let Some(last) = split {
                                                        // rsplit_once handles `foo.tar.gz` (file_name = "foo.tar", ext = "gz")
                                                        if let Some((file_name, ext)) = last.rsplit_once('.') {
                                                            let path = format!(
                                                                "gg.gdl.daedalus:neoforge-installer-extracts:{}:{}-{}@{}",
                                                                version, $side, file_name, ext
                                                            );
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
                                                                version_hashes: None,
                                                                patched: false,
                                                            });
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if entry.client.starts_with('/') {
                                            read_data!(entry.client, "client");
                                        }

                                        if entry.server.starts_with('/') {
                                            read_data!(entry.server, "server");
                                        }
                                    }
                                    sorted_data.insert(key, entry);
                                }

                                // Re-collect data into a HashMap for the PartialVersionInfo (keys ordered via the BTreeMap walk above).
                                profile.data = sorted_data.into_iter().collect();

                                let now = Instant::now();


                                let libs = futures::future::try_join_all(libs.into_iter().map(|mut lib| {
                                    let semaphore = semaphore.clone();
                                    let visited_assets = visited_assets.clone();
                                    let local_libs = local_libs.clone();

                                    async move {
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
                                        // Upload to CAS and get hash
                                        let hash = uploader.upload_cas(
                                            bytes.to_vec(),
                                            Some("application/java-archive".to_string()),
                                            s3_client,
                                            semaphore.clone(),
                                        ).await?;

                                        // Use common CAS URL building
                                        let cas_url = crate::common::cas::build_cas_url(&hash)?;

                                        // Update library URL with CAS URL
                                        if let Some(ref mut downloads) = lib.downloads {
                                            if let Some(ref mut artifact) = downloads.artifact {
                                                artifact.url = Some(cas_url);
                                            }
                                        } else if lib.url.is_some() {
                                            lib.url = Some(cas_url);
                                        }
                                    }

                                    Ok::<Library, crate::infrastructure::error::Error>(lib)
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
                                    libraries: libs,
                                    type_: version_info.type_,
                                    data: Some(profile.data),
                                    processors: Some(profile.processors),
                                    logging: None
                                };

                                let version_bytes = serde_json::to_vec(&new_profile)?;
                                let new_hash = get_hash(bytes::Bytes::from(version_bytes.clone())).await?;

                                // Loader IDs are globally unique, so look up by loader id alone.
                                // This is robust against migrations of the MC-version grouping
                                // (e.g. inferred maven-derived id → profile.minecraft).
                                let old_loader_version = {
                                    let versions = versions_mutex.lock().await;
                                    versions.iter()
                                        .flat_map(|v| v.loaders.iter())
                                        .find(|l| l.id == loader_version_full)
                                        .cloned()
                                };

                                // Use common change detection logic
                                let change_result = detect_version_change(
                                    "NeoForge",
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

                                // Use common CAS URL building
                                let cas_url = crate::common::cas::build_cas_url(&version_hash)?;

                                // Trust profile.minecraft over the maven-derived inferred id —
                                // Mojang's "no 1.x prefix" versioning makes reverse-engineering
                                // from the NeoForge coordinate brittle.
                                return Ok(Some((profile.minecraft.clone(), LoaderVersion {
                                    id: loader_version_full,
                                    url: cas_url,
                                    stable: false
                                })));
                            }

                            Ok(None)
                        }.await
                    });

                    {
                        let len = loaders_futures.len();
                        let mut successful = 0;
                        let mut failed = 0;

                        for (idx, result) in futures::future::join_all(loaders_futures).await.into_iter().enumerate() {
                            match result {
                                Ok(Some(entry)) => {
                                    loaders_versions.push(entry);
                                    successful += 1;
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    warn!("⚠️  NeoForge - Failed to process version {}/{len}: {}", idx + 1, e);
                                    failed += 1;
                                }
                            }
                        }

                        if failed > 0 {
                            warn!("⚠️  NeoForge - Skipped {} versions due to errors, {} succeeded", failed, successful);
                        }
                    }
                }

                // Group loaders by the actual Minecraft version each installer reports
                // in `profile.minecraft`. The maven-derived `minecraft_version` is only
                // used as a coarse maven-metadata bucket key — installers may collapse
                // into a different MC id at install_profile.json read time.
                let mut by_actual_mc: BTreeMap<String, Vec<LoaderVersion>> = BTreeMap::new();
                for (actual_mc, loader) in loaders_versions {
                    by_actual_mc.entry(actual_mc).or_default().push(loader);
                }

                let mut versions_guard = versions.lock().await;
                for (actual_mc, loaders) in by_actual_mc {
                    let is_stable = !(actual_mc.contains("-snapshot-")
                        || actual_mc.contains("-pre-")
                        || actual_mc.contains("-rc-"));
                    if let Some(existing) = versions_guard.iter_mut().find(|v| v.id == actual_mc) {
                        existing.loaders.extend(loaders);
                    } else {
                        versions_guard.push(daedalus::modded::Version {
                            id: actual_mc,
                            stable: is_stable,
                            loaders,
                        });
                    }
                }

                Ok::<(), crate::infrastructure::error::Error>(())
            });
        }
    }

    {
        let len = version_futures.len();
        let mut successful_mc_versions = 0;
        let mut failed_mc_versions = 0;

        for (idx, result) in futures::future::join_all(version_futures).await.into_iter().enumerate() {
            match result {
                Ok(()) => successful_mc_versions += 1,
                Err(e) => {
                    warn!("⚠️  NeoForge - Failed to process Minecraft version {}/{len}: {}", idx + 1, e);
                    failed_mc_versions += 1;
                }
            }
        }

        if failed_mc_versions > 0 {
            warn!("⚠️  NeoForge - {} Minecraft versions failed to process, {} succeeded",
                failed_mc_versions, successful_mc_versions);
        }
    }

    // Extract versions by locking the mutex instead of try_unwrap
    // This avoids silent failures when Arc still has strong references from async closures
    let new_versions = {
        let mut guard = versions.lock().await;
        std::mem::take(&mut *guard)
    };

    // Get old versions for merging
    let old_manifest_versions = {
        let mut guard = old_versions.lock().await;
        std::mem::take(&mut *guard)
    };

    // Use common version merging logic
    let mut final_versions = merge_loader_versions(
        old_manifest_versions,
        new_versions,
        "NeoForge"
    );

    // Use common sorting utilities
    sort_by_minecraft_order(&mut final_versions, minecraft_versions);

    // Sort loaders within each version using metadata order
    for version in &mut final_versions {
        if let Some(loader_versions) = maven_metadata.get(&version.id) {
            let loader_order: Vec<String> = loader_versions.iter().map(|(id, _)| id.clone()).collect();
            sort_loaders_by_metadata(version, &loader_order);
        }
    }

    // Set the full NeoForge versions JSON in manifest_builder with nested structure
    // This preserves game version -> loader version mappings
    let versions_json = serde_json::to_value(&final_versions)?;
    manifest_builder.set_loader_versions("neoforge", versions_json);
    info!(version_count = final_versions.len(), "Set NeoForge versions with nested structure in CAS manifest builder");

    Ok(())
}

const DEFAULT_MAVEN_METADATA_URL_1: &str =
    "https://maven.neoforged.net/releases/net/neoforged/forge/maven-metadata.xml";
const DEFAULT_MAVEN_METADATA_URL_2: &str =
    "https://maven.neoforged.net/releases/net/neoforged/neoforge/maven-metadata.xml";

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
        let original = value.clone();
        let mut parts = value.split('.');

        let Some(major) = parts.next() else { continue };
        let Some(minor) = parts.next() else { continue };
        let major_num: u32 = major.parse().unwrap_or(0);

        if major_num > 21 {
            // New MC versioning (YY.D.H) — MC dropped the "1." prefix after 1.21
            // NeoForge format: YY.D.H.build[-prerelease][+phase-N]
            // e.g. 26.1.2.11-beta -> MC 26.1.2
            // e.g. 26.1.0.0-alpha.1+snapshot-1 -> MC 26.1-snapshot-1
            // e.g. 26.1.0.0-alpha.15+pre-3 -> MC 26.1-pre-3
            let hotfix = parts.next()
                .and_then(|h| h.split(|c: char| !c.is_ascii_digit()).next())
                .unwrap_or("0");

            let base = match (minor, hotfix) {
                ("0", _) => major.to_string(),
                (_, "0") => format!("{}.{}", major, minor),
                _ => format!("{}.{}.{}", major, minor, hotfix),
            };

            // Extract MC phase suffix: +snapshot-N, +pre-N, +rc-N
            let game_version = if let Some((_, phase)) = original.split_once('+') {
                format!("{}-{}", base, phase)
            } else {
                base
            };

            map.entry(game_version)
                .or_default()
                .push((original, true));
        } else {
            // Old MC versioning (1.x.y) — skip weekly snapshots, pre-releases, RCs
            if original.contains('w') || original.contains("-pre") || original.contains("-rc") {
                info!("Skipping old snapshot version: {}", original);
                continue;
            }

            let game_version = if minor == "0" {
                format!("1.{}", major)
            } else {
                format!("1.{}.{}", major, minor)
            };

            map.entry(game_version)
                .or_default()
                .push((original, true));
        }
    }

    Ok(map)
}
