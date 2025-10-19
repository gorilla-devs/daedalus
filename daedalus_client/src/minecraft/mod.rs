//! Minecraft version processing and metadata management
//!
//! This module handles the complete Minecraft version processing pipeline:
//! - Fetching and processing vanilla Minecraft versions
//! - LWJGL library variant detection and validation
//! - Log4j security patching (CVE-2021-44228, CVE-2021-44832, CVE-2021-45046)
//! - Library patching and dependency management
//! - Split natives handling
//! - Assets index processing and CAS upload
//!
//! # Module Structure
//!
//! - `types`: Type definitions for patches and LWJGL configuration
//! - `log4j`: Security patching for Log4j vulnerabilities
//! - `library_patches`: Library patching system with override and injection
//! - `helpers`: Utility functions for version and library processing
//! - `lwjgl`: LWJGL variant processing and validation
//!
//! # Main Entry Point
//!
//! The primary function is `retrieve_data()` which orchestrates the entire
//! Minecraft version processing pipeline.

pub mod helpers;
pub mod library_patches;
pub mod log4j;
pub mod lwjgl;
pub mod types;

// Re-export commonly used types
pub use types::{LibraryPatch, LWJGLVariantConfig, LWJGLVariantMarker};

use crate::download_file;
use crate::format_url;
use crate::services::upload::BatchUploader;
use dashmap::DashSet;
use daedalus::minecraft::{
    Dependency, DependencyRule, JavaVersion, LWJGLEntry, Library, LibraryDownload,
    LibraryDownloads, LibraryGroup, MinecraftJavaProfile, Os, Rule, RuleAction, VersionInfo,
    VersionManifest, VersionType,
};
use daedalus::{get_hash, GradleSpecifier};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, info, warn};

/// Retrieve and process all Minecraft version data
///
/// This is the main entry point for Minecraft version processing. It:
/// 1. Fetches the Minecraft version manifest
/// 2. Processes each version in parallel (with chunking)
/// 3. Handles LWJGL variant detection and validation
/// 4. Applies Log4j security patches
/// 5. Applies library patches
/// 6. Processes assets and uploads to CAS
/// 7. Builds the final manifest with all processed versions
///
/// # Arguments
/// - `uploader`: Batch uploader for CAS uploads
/// - `manifest_builder`: CAS manifest builder for tracking versions
/// - `s3_client`: S3 bucket client for uploads
/// - `semaphore`: Concurrency control semaphore
/// - `is_first_run`: Whether this is the first run (skips old manifest loading)
///
/// # Returns
/// The processed Minecraft version manifest with all versions and metadata
pub async fn retrieve_data(
    uploader: &BatchUploader,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    s3_client: &s3::Bucket,
    semaphore: Arc<Semaphore>,
    is_first_run: bool,
) -> Result<VersionManifest, crate::infrastructure::error::Error> {
    info!(is_first_run = is_first_run, "Retrieving Minecraft data");

    // TODO: Old manifest doesn't take LWJGL meta into account
    let old_manifest = if is_first_run {
        None
    } else {
        daedalus::minecraft::fetch_version_manifest(Some(&format_url(&format!(
            "minecraft/v{}/manifest.json",
            daedalus::minecraft::CURRENT_FORMAT_VERSION
        ))))
        .await
        .ok()
    };

    let mut manifest = daedalus::minecraft::fetch_version_manifest(None).await?;

    let cloned_manifest = Arc::new(Mutex::new(manifest.clone()));

    let patches = library_patches::get_library_patches().await?;
    let cloned_patches = Arc::new(&patches);

    let lwjgl_config = lwjgl::get_lwjgl_config().await?;

    let visited_assets = Arc::new(DashSet::new());

    let lwjgl_version_variants_mutex: Arc<Mutex<BTreeMap<String, Vec<LWJGLEntry>>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    let lwjgl_reject_reasons: HashMap<String, Option<String>> = lwjgl_config
        .reject
        .clone()
        .into_iter()
        .map(|mark| (mark.match_, mark.reason))
        .collect();
    let reject_lwjgl_variants: HashSet<String> = lwjgl_config
        .reject
        .into_iter()
        .map(|mark| mark.match_)
        .collect();
    let accept_lwjgl_variants: HashSet<String> = lwjgl_config
        .accept
        .into_iter()
        .map(|mark| mark.match_)
        .collect();

    let now = Instant::now();

    let mut version_futures = Vec::new();

    for version in manifest.versions.iter_mut().rev() {
        version_futures.push(async {
            let old_version = if let Some(old_manifest) = &old_manifest {
                old_manifest.versions.iter().find(|x| x.id == version.id)
            } else {
                None
            };

            if let Some(old_version) = old_version {
                if old_version.sha1 == version.sha1 {
                    return Ok(());
                }
            }

            let visited_assets = Arc::clone(&visited_assets);
            let cloned_manifest_mutex = Arc::clone(&cloned_manifest);
            let semaphore = Arc::clone(&semaphore);
            let patches = Arc::clone(&cloned_patches);

            let lwjgl_version_variants_mutex = Arc::clone(&lwjgl_version_variants_mutex);

            let assets_hash = old_version.and_then(|x| x.assets_index_sha1.clone());

            async move {
                let mut version_info = daedalus::minecraft::fetch_version_info(version).await?;

                let has_split_natives = helpers::version_has_split_natives(&version_info);
                let mut is_lwjgl_3 = false;
                let mut lwjgl_buckets: HashMap<Option<Vec<Rule>>, LibraryGroup> =
                    HashMap::new();

                let mut new_libraries = Vec::new();
                info!("Processing libraries for version {}", version_info.id);
                for library in version_info.libraries.iter_mut() {
                    if helpers::lib_is_split_natives(library) {
                        if let Some(identifier) = &library.name.identifier {
                            info!(
                                "Splitting library {} into artifact {}",
                                library.name, identifier
                            );
                            library.name.artifact =
                                format!("{}-{}", library.name.artifact, identifier);
                            library.name.identifier = None;
                        }
                    }
                    let spec = &mut library.name;

                    if spec.is_lwjgl() {
                        let mut rules = None;
                        let set_version: Option<String> = if has_split_natives {
                            // implies lwjgl3
                            is_lwjgl_3 = true;
                            debug!(
                                "lwlgl library {} has split natives, version {}",
                                spec, spec.version
                            );

                            Some(spec.version.clone())
                        } else {
                            debug!("lwlgl library {} is not split, package: {} artifact:{} version: {}", spec, spec.package, spec.artifact, spec.version);
                            rules = library.rules.clone();
                            library.rules = None;
                            if helpers::is_macos_only(&rules) {
                                info!(
                                    "Candidate library {} is only for macOS and is therefore ignored",
                                    spec
                                );
                                continue;
                            }
                            if spec.package == "org.lwjgl.lwjgl" && spec.artifact == "lwjgl" {
                                Some(spec.version.clone())
                            } else if spec.package == "org.lwjgl" && spec.artifact == "lwjgl" {
                                is_lwjgl_3 = true;
                                Some(spec.version.clone())
                            } else {
                                None
                            }
                        };
                        debug!("lwjgl library {} is setting version {:?}", spec, set_version);

                        let version_id = &version_info.id;
                        let version_release_time = version_info.release_time;

                        info!(
                            "Setting lwjgl bucket {:?} for {} with release {}",
                            &rules, version_id, version_release_time
                        );
                        let bucket = lwjgl_buckets.entry(rules.clone()).or_insert_with(|| {
                            LibraryGroup {
                                id: "LWJGL".to_string(),
                                version: "undetermined".to_string(),
                                uid: "org.lwjgl".to_string(),
                                release_time: version_release_time,
                                libraries: Vec::new(),
                                requires: None,
                                conflicts: None,
                                type_: VersionType::Release,
                                has_split_natives: Some(has_split_natives),
                            }
                        });
                        bucket.has_split_natives = Some(has_split_natives);

                        if let Some(version) = set_version {
                            debug!(
                                "Setting bucket version {} for {}",
                                version, version_info.id
                            );
                            bucket.version = version;
                        }
                        bucket.libraries.push(library.clone());
                        if version_info.release_time > bucket.release_time {
                            bucket.release_time = version_info.release_time;
                        }
                    } else if spec.is_log4j() {
                        if let Some((version_override, maven_override)) =
                            log4j::map_log4j_artifact(&spec.version)?
                        {
                            let replacement_library = log4j::create_log4j_replacement_library(
                                &spec.artifact,
                                &version_override,
                                &maven_override,
                                library.include_in_classpath,
                            )?;
                            new_libraries.push(replacement_library);
                        } else {
                            new_libraries.push(library.clone())
                        }
                    } else {
                        let mut libs = library_patches::patch_library(&patches, library.clone());
                        new_libraries.append(&mut libs)
                    }
                }

                if lwjgl_buckets.len() == 1 {
                    for (key, lwjgl) in lwjgl_buckets.iter_mut() {
                        lwjgl.libraries.sort_by_key(|lib| lib.name.clone());
                        lwjgl::add_lwjgl_version(lwjgl_version_variants_mutex.clone(), lwjgl)
                            .await;
                        info!("Found only candidate LWJGL {:?} {:?}", lwjgl.version, key);
                    }
                } else {
                    let common_bucket = lwjgl_buckets.get(&None).cloned();
                    for (key, lwjgl) in lwjgl_buckets.iter_mut() {
                        if key.is_none() {
                            continue;
                        }
                        if let Some(mut common_bucket) = common_bucket.clone() {
                            lwjgl.libraries.append(&mut common_bucket.libraries);
                        }
                        lwjgl.libraries.sort_by_key(|lib| lib.name.clone());
                        lwjgl::add_lwjgl_version(lwjgl_version_variants_mutex.clone(), lwjgl)
                            .await;
                        info!("Found candidate LWJGL {:?} {:?}", lwjgl.version, key);
                    }
                    lwjgl_buckets.remove(&None);
                }

                version_info.libraries = new_libraries;

                let suggested_lwjgl_version = if lwjgl_buckets.len() == 1 {
                    if is_lwjgl_3 {
                        Ok(lwjgl_buckets
                            .values()
                            .next()
                            .expect("Safe to unwrap because there is one item present")
                            .version
                            .clone())
                    } else {
                        Ok("2.9.4-nightly-20150209".to_string())
                    }
                } else {
                    let bad_versions: HashSet<&str> =
                        vec!["3.1.6", "3.2.1"].into_iter().collect();
                    let our_versions: HashSet<&str> = lwjgl_buckets
                        .values()
                        .map(|lwjgl| lwjgl.version.as_str())
                        .collect();

                    if our_versions == bad_versions {
                        info!(
                            "Found broken 3.1.6/3.2.1 LWJGL combo in version {} , forcing LWJGL. 3.2.1",
                            &version_info.id
                        );
                        Ok("3.2.1".to_string())
                    } else {
                        Err(crate::infrastructure::error::invalid_input(format!(
                            "Can not determine a single suggested LWJGL version in version {} from among {:?}",
                            &version_info.id, our_versions
                        )))
                    }
                }?;

                let lwjgl_dependency = if is_lwjgl_3 {
                    Dependency {
                        name: "lwjgl".to_string(),
                        uid: "org.lwjgl3".to_string(),
                        rule: Some(DependencyRule::Suggests(suggested_lwjgl_version)),
                    }
                } else {
                    Dependency {
                        name: "lwjgl".to_string(),
                        uid: "org.lwjgl2".to_string(),
                        rule: Some(DependencyRule::Suggests(suggested_lwjgl_version)),
                    }
                };

                if version_info.requires.is_none() {
                    version_info.requires = Some(Vec::new());
                }
                version_info
                    .requires
                    .as_mut()
                    .expect("Safe to unwrap because we just ensured it's creation")
                    .push(lwjgl_dependency);

                // Patch java version
                version_info.java_version = {
                    if let Some(java_version) = &version_info.java_version {
                        match MinecraftJavaProfile::try_from(&*java_version.component) {
                            Ok(java_version) => Some(JavaVersion {
                                component: java_version.as_str().expect("MinecraftJavaProfile::try_from is not handling unknown variant as error").to_string(),
                                major_version: 0,
                            }),
                            Err(err) => {
                                #[cfg(feature = "sentry")]
                                sentry::capture_message(
                                    &format!(
                                        "Unknown java version \"{}\": {}",
                                        java_version.component, err
                                    ),
                                    sentry::Level::Warning,
                                );
                                println!(
                                    "Unknown java version \"{}\": {}",
                                    java_version.component, err
                                );
                                None
                            }
                        }
                    } else {
                        Some(JavaVersion {
                            component: MinecraftJavaProfile::JreLegacy
                                .as_str()
                                .unwrap()
                                .to_string(),
                            major_version: 0,
                        })
                    }
                };

                let assets_path = format!(
                    "minecraft/v{}/assets/{}.json",
                    daedalus::minecraft::CURRENT_FORMAT_VERSION,
                    version_info.asset_index.id
                );
                let assets_index_url = version_info.asset_index.url.clone();

                let mut download_assets = false;

                if visited_assets.insert(version_info.asset_index.id.clone()) {
                    if let Some(assets_hash) = assets_hash {
                        if version_info.asset_index.sha1 != assets_hash {
                            download_assets = true;
                        }
                    } else {
                        download_assets = true;
                    }
                }

                if download_assets {
                    let assets_index = download_file(
                        &assets_index_url,
                        Some(&version_info.asset_index.sha1),
                        semaphore.clone(),
                    )
                    .await?;

                    let asset_bytes = assets_index.to_vec();
                    let asset_hash = uploader
                        .upload_cas(
                            asset_bytes.clone(),
                            Some("application/json".to_string()),
                            s3_client,
                            semaphore.clone(),
                        )
                        .await?;

                    let base_url = dotenvy::var("BASE_URL").unwrap();
                    version_info.asset_index.url = format!(
                        "{}/v{}/objects/{}/{}",
                        base_url,
                        crate::services::cas::CAS_VERSION,
                        &asset_hash[..2],
                        &asset_hash[2..]
                    );
                }

                let version_bytes = serde_json::to_vec(&version_info)?;
                let version_hash = uploader
                    .upload_cas(
                        version_bytes.clone(),
                        Some("application/json".to_string()),
                        s3_client,
                        semaphore.clone(),
                    )
                    .await?;

                // Update manifest with CAS URL
                {
                    let mut cloned_manifest = cloned_manifest_mutex.lock().await;

                    if let Some(position) = cloned_manifest
                        .versions
                        .iter()
                        .position(|x| version.id == x.id)
                    {
                        let base_url = dotenvy::var("BASE_URL").unwrap();
                        cloned_manifest.versions[position].url = format!(
                            "{}/v{}/objects/{}/{}",
                            base_url,
                            crate::services::cas::CAS_VERSION,
                            &version_hash[..2],
                            &version_hash[2..]
                        );
                        cloned_manifest.versions[position].assets_index_sha1 =
                            Some(version_info.asset_index.sha1.clone());
                        cloned_manifest.versions[position].assets_index_url =
                            Some(format_url(&assets_path));
                        cloned_manifest.versions[position].java_profile =
                            version_info.java_version.as_ref().map(|x| {
                                MinecraftJavaProfile::try_from(&*x.component).expect(
                                    "Safe to unwrap since we ensure it's valid in version_json already",
                                )
                            });
                        cloned_manifest.versions[position].sha1 = version_hash.clone();
                    } else {
                        let base_url = dotenvy::var("BASE_URL").unwrap();
                        cloned_manifest.versions.insert(
                            0,
                            daedalus::minecraft::Version {
                                id: version_info.id.clone(),
                                type_: version_info.type_.clone(),
                                url: format!(
                                    "{}/v{}/objects/{}/{}",
                                    base_url,
                                    crate::services::cas::CAS_VERSION,
                                    &version_hash[..2],
                                    &version_hash[2..]
                                ),
                                time: version_info.time,
                                release_time: version_info.release_time,
                                sha1: version_hash.clone(),
                                java_profile: version_info.java_version.as_ref().map(|x| {
                                    MinecraftJavaProfile::try_from(&*x.component).expect(
                                        "Safe to unwrap since we ensure it's valid in version_json already",
                                    )
                                }),
                                compliance_level: 1,
                                assets_index_url: Some(format_url(&assets_path)),
                                assets_index_sha1: Some(version_info.asset_index.sha1.clone()),
                            },
                        )
                    }
                }

                // NOTE: We don't call manifest_builder.add_version() for minecraft here.
                // Instead, we use set_loader_versions() with the full VersionManifest at the end
                // to preserve rich metadata (type, url, time, releaseTime, sha1, etc.)

                Ok::<(), crate::infrastructure::error::Error>(())
            }
            .await?;

            Ok::<(), crate::infrastructure::error::Error>(())
        })
    }

    {
        let mut versions = version_futures.into_iter().peekable();
        let mut chunk_index = 0;
        let mut successful = 0;
        let mut failed = 0;

        while versions.peek().is_some() {
            let now = Instant::now();

            let chunk: Vec<_> = versions.by_ref().take(100).collect();

            for future in chunk {
                match future.await {
                    Ok(_) => {
                        successful += 1;
                    }
                    Err(e) => {
                        warn!("⚠️  Minecraft - Failed to process version: {}", e);
                        failed += 1;
                    }
                }
            }

            chunk_index += 1;

            let elapsed = now.elapsed();
            info!(
                "Chunk {} Elapsed: {:.2?} (✓ {} ✗ {})",
                chunk_index, elapsed, successful, failed
            );
        }

        info!(
            "📊 Minecraft - Processing complete: {} successful, {} failed",
            successful, failed
        );
    }

    {
        let lwjgl_version_variants = lwjgl_version_variants_mutex.lock().await;

        info!("Processing LWJGL variants");
        for (lwjgl_version_variant, lwjgl_variant_entries) in lwjgl_version_variants.iter() {
            info!(
                "{} variant(s) for LWJGL {}",
                lwjgl_variant_entries.len(),
                lwjgl_version_variant
            );

            let mut decided_variant = None;
            let mut accepted_variants = 0;
            let mut unknown_variants = 0;

            for variant in lwjgl_variant_entries {
                if reject_lwjgl_variants.contains(&variant.sha1) {
                    let reason = lwjgl_reject_reasons
                        .get(&variant.sha1)
                        .expect("Unwrap to be safe because sha was present in config")
                        .clone()
                        .unwrap_or("unspecified".to_string());
                    info!("LWJGL Variant {} for version {} ignored because it was marked as bad. Reason: {}", variant.sha1, lwjgl_version_variant, &reason);
                    continue;
                }
                if accept_lwjgl_variants.contains(&variant.sha1) {
                    info!(
                        "LWJGL Variant {} for version {} accepted",
                        variant.sha1, lwjgl_version_variant
                    );
                    decided_variant = Some(variant);
                    accepted_variants += 1;
                    continue;
                }

                let natives = variant
                    .group
                    .libraries
                    .iter()
                    .filter_map(|lib| {
                        lib.natives
                            .as_ref()
                            .map(|natives| natives.keys().cloned().collect::<Vec<_>>())
                    })
                    .collect::<Vec<_>>();

                #[cfg(feature = "sentry")]
                sentry::capture_message(
                    &format!(
                        "Unmarked LWJGL variant {}, #{} ({}) natives: {:?} Split: {}",
                        variant.sha1,
                        lwjgl_version_variant,
                        variant.group.release_time,
                        natives,
                        variant
                            .group
                            .has_split_natives
                            .map_or("unknown".to_string(), |b| b.to_string()),
                    ),
                    sentry::Level::Warning,
                );

                warn!(
                    "Unmarked LWJGL variant {}, #{} ({}) natives: {:?} Split: {}",
                    variant.sha1,
                    lwjgl_version_variant,
                    variant.group.release_time,
                    natives,
                    variant
                        .group
                        .has_split_natives
                        .map_or("unknown".to_string(), |b| b.to_string()),
                );
                unknown_variants += 1;
            }

            let patches = Arc::clone(&cloned_patches);
            let semaphore = semaphore.clone();

            async move {
                if decided_variant.is_some() && accepted_variants == 1 && unknown_variants == 0 {
                    if let Some((lwjgl_path, lwjgl)) = lwjgl::process_single_lwjgl_variant(
                        &decided_variant
                            .expect("Unwrap to be safe inside is_some")
                            .group,
                        &patches,
                    )? {
                        debug!("Uploading {}", lwjgl_path);

                        let lwjgl_bytes = serde_json::to_vec(&lwjgl)?;
                        let lwjgl_hash = uploader
                            .upload_cas(
                                lwjgl_bytes.clone(),
                                Some("application/json".to_string()),
                                s3_client,
                                semaphore.clone(),
                            )
                            .await?;

                        let loader = if lwjgl.version.starts_with("2") {
                            "minecraft-lwjgl2"
                        } else if lwjgl.version.starts_with("3") {
                            "minecraft-lwjgl3"
                        } else {
                            return Err(crate::infrastructure::error::invalid_input(format!(
                                "Unknown LWJGL version {}",
                                lwjgl.version
                            )));
                        };

                        manifest_builder.add_version(
                            loader,
                            lwjgl.version.clone(),
                            lwjgl_hash,
                            lwjgl_bytes.len() as u64,
                        );
                    } else {
                        info!(
                            "Skipped LWJGL {}",
                            &decided_variant
                                .expect("Unwrap to be safe inside is_some")
                                .group
                                .version
                        );
                    }
                } else {
                    #[cfg(feature = "sentry")]
                    sentry::capture_message(
                        &format!(
                            "No variant decided for version {} of out {} possible and {} unknown",
                            lwjgl_version_variant, accepted_variants, unknown_variants
                        ),
                        sentry::Level::Warning,
                    );
                    error!("No variant decided for version {} of out {} possible and {} unknown", lwjgl_version_variant, accepted_variants, unknown_variants);
                }

                Ok::<(), crate::infrastructure::error::Error>(())
            }
            .await?
        }
    }

    let elapsed = now.elapsed();
    info!("Elapsed: {:.2?}", elapsed);

    // Get the final manifest with all processed versions
    let final_manifest = Arc::try_unwrap(cloned_manifest)
        .map_err(|err| {
            crate::infrastructure::error::invalid_input(format!(
                "Failed to unwrap Arc<Mutex<VersionManifest>>: {:?}",
                err
            ))
        })?
        .into_inner();

    // Set the full Minecraft versions JSON in manifest_builder
    // This preserves rich metadata (type, url, time, releaseTime, sha1, complianceLevel, etc.)
    let versions_json = serde_json::to_value(&final_manifest.versions)?;
    manifest_builder.set_loader_versions("minecraft", versions_json);
    info!(
        version_count = final_manifest.versions.len(),
        "Set Minecraft versions with rich metadata in CAS manifest builder"
    );

    Ok(final_manifest)
}
