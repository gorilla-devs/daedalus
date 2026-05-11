//! Minecraft version processing and metadata management
//!
//! This module handles the complete Minecraft version processing pipeline:
//! - Fetching and processing vanilla Minecraft versions
//! - Log4j security patching (CVE-2021-44228, CVE-2021-44832, CVE-2021-45046)
//! - Library patching and dependency management (including LWJGL fixes)
//! - Split natives handling
//! - Assets index processing and CAS upload
//!
//! # Module Structure
//!
//! - `types`: Type definitions for library patches
//! - `log4j`: Security patching for Log4j vulnerabilities
//! - `library_patches`: Library patching system with override and injection
//! - `helpers`: Utility functions for version and library processing
//!
//! # Main Entry Point
//!
//! The primary function is `retrieve_data()` which orchestrates the entire
//! Minecraft version processing pipeline.

pub mod helpers;
pub mod library_patches;
pub mod log4j;
pub mod types;

// Re-export commonly used types
pub use library_patches::LibraryPatchIndex;
pub use types::LibraryPatch;

use crate::download_file;
use crate::format_url;
use crate::services::upload::BatchUploader;
use dashmap::DashSet;
use daedalus::minecraft::{JavaVersion, MinecraftJavaProfile, VersionManifest};
use futures::future::join_all;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};
use tracing::{info, warn};

/// Retrieve and process all Minecraft version data
///
/// This is the main entry point for Minecraft version processing. It:
/// 1. Fetches the Minecraft version manifest
/// 2. Processes each version in parallel (with chunking)
/// 3. Applies Log4j security patches
/// 4. Applies library patches (e.g., LWJGL-related fixes via generic patching; no LWJGL variant processing)
/// 5. Processes assets and uploads to CAS
/// 6. Builds the final manifest with all processed versions
///
/// LWJGL libraries are kept inline in version manifests and fixed via library patches,
/// not extracted as separate components.
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

    // Pre-build an id → original-index map so the per-version mutex section can do an
    // O(1) lookup instead of an O(N) `position(...)` scan. New versions inserted at the
    // front of the Vec shift original indices forward by `inserts_count`, which we track
    // alongside the manifest while holding the mutex.
    let id_to_original_index: Arc<HashMap<String, usize>> = Arc::new(
        manifest
            .versions
            .iter()
            .enumerate()
            .map(|(i, v)| (v.id.clone(), i))
            .collect(),
    );
    let cloned_manifest = Arc::new(Mutex::new((manifest.clone(), 0usize)));

    // Own the prebuilt patch index and share as an Arc to avoid borrowed refs in futures.
    let patches: Arc<LibraryPatchIndex> =
        Arc::new(library_patches::get_library_patches().await?);

    let visited_assets = Arc::new(DashSet::new());

    let now = Instant::now();

    let mut version_futures = Vec::new();

    for version in manifest.versions.iter_mut().rev() {
        version_futures.push(async {
            let old_version = if let Some(old_manifest) = &old_manifest {
                old_manifest.versions.iter().find(|x| x.id == version.id)
            } else {
                None
            };

            // Compare upstream Mojang SHA1 (`version.sha1` straight from the manifest)
            // against the `original_sha1` we stored in our previous publish. Comparing
            // against `old_version.sha1` was wrong: that value is the hash of OUR
            // post-processed JSON, which never matches Mojang's upstream sha1, so every
            // version was reprocessed every run.
            if let Some(old_version) = old_version {
                if old_version
                    .original_sha1
                    .as_deref()
                    .map(|orig| orig == version.sha1)
                    .unwrap_or(false)
                {
                    return Ok(());
                }
            }

            // Capture upstream sha1 before we mutate `version.sha1` later in the loop.
            let upstream_sha1 = version.sha1.clone();

            let visited_assets = Arc::clone(&visited_assets);
            let cloned_manifest_mutex = Arc::clone(&cloned_manifest);
            let id_to_original_index = Arc::clone(&id_to_original_index);
            let semaphore = Arc::clone(&semaphore);
            let patches = Arc::clone(&patches);

            let assets_hash = old_version.and_then(|x| x.assets_index_sha1.clone());

            async move {
                let mut version_info = daedalus::minecraft::fetch_version_info(version).await?;

                // Process libraries: apply patches (including LWJGL fixes)
                let mut new_libraries = Vec::new();
                info!("Processing libraries for version {}", version_info.id);
                for library in version_info.libraries.iter_mut() {
                    // Handle split natives (modern Minecraft native library format)
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

                    let spec = &library.name;

                    // Handle log4j security patches (CVE-2021-44228, CVE-2021-44832, CVE-2021-45046)
                    if spec.is_log4j() {
                        if let Some((version_override, maven_override)) =
                            log4j::map_log4j_artifact(&spec.version)?
                        {
                            let mut replacement_library = log4j::create_log4j_replacement_library(
                                &spec.artifact,
                                &version_override,
                                &maven_override,
                                library.include_in_classpath,
                            )?;
                            // Mark for traceability and run through patcher for consistency
                            replacement_library.patched = true;
                            let mut libs = library_patches::patch_library(
                                &patches,
                                replacement_library,
                            );
                            new_libraries.append(&mut libs);
                        } else {
                            new_libraries.push(library.clone())
                        }
                    } else {
                        // Apply library patches to ALL libraries (including LWJGL!)
                        // Patches handle: ARM64 natives, missing tinyfd, bad LWJGL variants, etc.
                        let mut libs = library_patches::patch_library(&patches, library.clone());
                        new_libraries.append(&mut libs);
                    }
                }

                version_info.libraries = new_libraries;

                // Patch java version
                version_info.java_version = {
                    if let Some(java_version) = &version_info.java_version {
                        // try_from is now infallible — unknown strings come back as
                        // MinecraftJavaProfile::Unknown(...). Branch on is_known()
                        // and handle the unknown case the same way the old Err arm did.
                        let parsed = MinecraftJavaProfile::try_from(&*java_version.component)
                            .expect("MinecraftJavaProfile::try_from is infallible");
                        if parsed.is_known() {
                            Some(JavaVersion {
                                component: parsed
                                    .as_str()
                                    .expect("known variants always have an as_str")
                                    .to_string(),
                                major_version: 0,
                            })
                        } else {
                            #[cfg(feature = "sentry")]
                            sentry::capture_message(
                                &format!(
                                    "Unknown java version \"{}\"",
                                    java_version.component
                                ),
                                sentry::Level::Warning,
                            );
                            warn!(
                                java_version = %java_version.component,
                                "Unknown java version, omitting from manifest"
                            );
                            None
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

                    version_info.asset_index.url = format!(
                        "{}/v{}/objects/{}/{}",
                        crate::common::BASE_URL.as_str(),
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
                    let mut guard = cloned_manifest_mutex.lock().await;
                    let (cloned_manifest, inserts_count) = &mut *guard;

                    let position = id_to_original_index
                        .get(&version.id)
                        .map(|orig| orig + *inserts_count);

                    if let Some(position) = position {
                            cloned_manifest.versions[position].url = format!(
                            "{}/v{}/objects/{}/{}",
                            crate::common::BASE_URL.as_str(),
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
                                MinecraftJavaProfile::try_from(&*x.component)
                                    .expect("MinecraftJavaProfile::try_from is infallible")
                            });
                        cloned_manifest.versions[position].sha1 = version_hash.clone();
                        cloned_manifest.versions[position].original_sha1 = Some(upstream_sha1.clone());
                    } else {
                        cloned_manifest.versions.insert(
                            0,
                            daedalus::minecraft::Version {
                                id: version_info.id.clone(),
                                type_: version_info.type_.clone(),
                                url: format!(
                                    "{}/v{}/objects/{}/{}",
                                    crate::common::BASE_URL.as_str(),
                                    crate::services::cas::CAS_VERSION,
                                    &version_hash[..2],
                                    &version_hash[2..]
                                ),
                                time: version_info.time,
                                release_time: version_info.release_time,
                                sha1: version_hash.clone(),
                                original_sha1: Some(upstream_sha1.clone()),
                                java_profile: version_info.java_version.as_ref().map(|x| {
                                    MinecraftJavaProfile::try_from(&*x.component).expect(
                                        "Safe to unwrap since we ensure it's valid in version_json already",
                                    )
                                }),
                                compliance_level: 1,
                                assets_index_url: Some(format_url(&assets_path)),
                                assets_index_sha1: Some(version_info.asset_index.sha1.clone()),
                            },
                        );
                        *inserts_count += 1;
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

            // Process chunk concurrently (semaphore controls actual I/O parallelism)
            for result in join_all(chunk).await {
                match result {
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

    let elapsed = now.elapsed();
    info!("Elapsed: {:.2?}", elapsed);

    // Get the final manifest with all processed versions
    let final_manifest = Arc::try_unwrap(cloned_manifest)
        .map_err(|err| {
            crate::infrastructure::error::invalid_input(format!(
                "Failed to unwrap Arc<Mutex<(VersionManifest, _)>>: {:?}",
                err
            ))
        })?
        .into_inner()
        .0;

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
