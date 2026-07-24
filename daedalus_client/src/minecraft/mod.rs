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
use crate::services::upload::BatchUploader;
use daedalus::minecraft::{JavaVersion, MinecraftJavaProfile, VersionManifest};
use futures::future::join_all;
use std::collections::HashSet;
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
/// The processed Minecraft manifest together with the set of version ids Mojang
/// currently publishes.
///
/// Loaders prune groups whose Minecraft version does not exist. They must test
/// against `upstream_version_ids` rather than `manifest`, which legitimately
/// omits versions this cycle failed to process.
pub struct MinecraftData {
    pub manifest: VersionManifest,
    pub upstream_version_ids: HashSet<String>,
}

pub async fn retrieve_data(
    uploader: &BatchUploader,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    s3_client: &s3::Bucket,
    semaphore: Arc<Semaphore>,
    is_first_run: bool,
) -> Result<MinecraftData, crate::infrastructure::error::Error> {
    info!(is_first_run = is_first_run, "Retrieving Minecraft data");

    // Previous publish's minecraft entries, resolved through the previous root
    // manifest — they carry the original_sha1/assets/java fields the skip-reuse
    // path below depends on.
    //
    // Loaded on every cycle, including the first after a process start. The
    // baseline serves two independent purposes and only one of them should be
    // off on a first run: skip-reuse (which `is_first_run` disables at its own
    // site, so the full version set reprocesses and self-heals) and
    // carry-forward, which repairs a version whose processing failed. Without a
    // baseline the repair has nothing to restore from and the failed version is
    // dropped from the published manifest outright, so a single non-retryable
    // flake — `should_retry_download` treats any 404 as final — erased an
    // established version on the first cycle after every restart.
    //
    // Unlike the merge-based loaders (forge/neoforge/fabric/quilt), minecraft
    // rebuilds from the full upstream Mojang manifest every cycle, so an
    // unreadable baseline cannot silently drop entries the way an empty merge
    // base can, and aborting here would skip the entire publish cycle (minecraft
    // gates every other loader). Both Absent and Unreadable therefore fall back
    // to "no baseline", which costs the repair but never publishes something
    // wrong.
    let old_versions: Option<Vec<daedalus::minecraft::Version>> =
        match crate::services::cas::fetch_previous_loader_versions(
            s3_client,
            "minecraft",
        )
        .await
        {
            crate::services::cas::PreviousVersions::Loaded(v) => Some(v),
            crate::services::cas::PreviousVersions::Absent
            | crate::services::cas::PreviousVersions::Unreadable => None,
        };

    let mut manifest =
        daedalus::minecraft::fetch_version_manifest(None).await?;

    // Captured before the filters below narrow the manifest, so it records every
    // id Mojang publishes rather than the subset this cycle managed to process.
    let upstream_version_ids: HashSet<String> =
        manifest.versions.iter().map(|v| v.id.clone()).collect();

    // §1.2(a/b): Tolerant parsing + never-publish-unknowns.
    // `VersionType` has an `Unknown(String)` catch-all so the whole manifest
    // doesn't fail to parse on a new upstream type. But we must NOT publish
    // versions we don't understand — see policy in §1.2(b). Warn per unique
    // unknown type (Discord layer deduplicates across cycles), then remove
    // all affected versions from the manifest before we do anything else.
    {
        use std::collections::HashSet;
        let mut seen_unknown: HashSet<String> = HashSet::new();
        let before = manifest.versions.len();
        manifest.versions.retain(|v| {
            if let daedalus::minecraft::VersionType::Unknown(s) = &v.type_ {
                if seen_unknown.insert(s.clone()) {
                    warn!(
                        version_type = %s,
                        example_version_id = %v.id,
                        "Mojang shipped a new VersionType we don't recognise; \
                         skipping version from manifest until support is added \
                         in daedalus::minecraft::VersionType"
                    );
                }
                false // exclude from published manifest
            } else {
                true
            }
        });
        let removed = before - manifest.versions.len();
        if removed > 0 {
            warn!(
                removed_count = removed,
                "Excluded {} Minecraft version(s) with unknown VersionType from manifest",
                removed
            );
        }
    }

    // Detect new vanilla Minecraft versions against our previously-published
    // manifest. Fired exactly once per (publish-cycle, new-version), and
    // suppressed whenever there is no baseline to compare against — a genuine
    // cold start, or a transient failure reading the previous publish — because
    // every historical version would otherwise look new and send one message
    // each.
    if let Some(old) = &old_versions {
        if let Some(notifier) = crate::services::discord::notifier() {
            let known_ids: std::collections::HashSet<&str> =
                old.iter().map(|v| v.id.as_str()).collect();
            for v in &manifest.versions {
                if !known_ids.contains(v.id.as_str()) {
                    notifier.report_new_mc_version(
                        &v.id,
                        &format!("{:?}", v.type_).to_lowercase(),
                        Some(&v.release_time.to_rfc3339()),
                    );
                }
            }
        }
    }

    // Every manifest write below locates its entry by id at write time. A
    // prebuilt index map cannot be used here: the unknown-DownloadType path
    // removes entries mid-run, which would shift every higher index and make
    // frozen positions write into the wrong version's entry (or run out of
    // bounds).
    let cloned_manifest = Arc::new(Mutex::new(manifest.clone()));

    // Own the prebuilt patch index and share as an Arc to avoid borrowed refs in futures.
    let patches: Arc<LibraryPatchIndex> =
        Arc::new(library_patches::get_library_patches().await?);

    // Asset-index CAS URLs, keyed by "{id}:{sha1}" so an index Mojang updates
    // in place under the same id still gets its own object. Every version
    // sharing an index resolves to the same URL; a map miss re-sources the
    // bytes (identical bytes hash to the same object, so concurrent misses
    // are merely duplicate work, never divergent output).
    let asset_cas_urls: Arc<dashmap::DashMap<String, String>> =
        Arc::new(dashmap::DashMap::new());

    // Number of versions that ran the full library-patch pass this cycle.
    // When it equals the published version count (a clean full reprocess),
    // every patch anchor had the chance to match — see the dead-anchor check
    // after processing.
    let patched_versions = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let now = Instant::now();

    let mut version_futures = Vec::new();

    for version in manifest.versions.iter_mut().rev() {
        version_futures.push(async {
            // The id is returned alongside the result so a failure can be
            // repaired in the shared manifest (carry forward the previous
            // published entry, or drop the raw Mojang entry).
            let version_id = version.id.clone();
            let result = async {
            let old_version = old_versions
                .as_ref()
                .and_then(|old| old.iter().find(|x| x.id == version.id));

            // Compare upstream Mojang SHA1 (`version.sha1` straight from the manifest)
            // against the `original_sha1` we stored in our previous publish. Comparing
            // against `old_version.sha1` was wrong: that value is the hash of OUR
            // post-processed JSON, which never matches Mojang's upstream sha1, so every
            // version was reprocessed every run.
            //
            // Skipped entirely on the first cycle after a process start: that
            // run reprocesses the full version set so a bad entry published by
            // an earlier revision is repaired. The baseline itself stays loaded
            // either way — carry-forward needs it when a version fails.
            let old_version = old_version.filter(|_| !is_first_run);
            if let Some(old_version) = old_version {
                if old_version
                    .original_sha1
                    .as_deref()
                    .map(|orig| orig == version.sha1)
                    .unwrap_or(false)
                    // Only reuse entries whose assets pointer already targets a
                    // CAS object; older publishes carried a legacy assets path
                    // here, and reusing those would keep the legacy pointer
                    // alive forever. Reprocessing once upgrades the entry.
                    && old_version
                        .assets_index_url
                        .as_deref()
                        .is_some_and(|u| u.contains("/objects/"))
                {
                    // Content is unchanged since our last publish, so reuse the
                    // previously-processed entry — CAS url, original_sha1,
                    // assets-index, and java-profile — instead of leaving the
                    // raw upstream Mojang entry in the published manifest. This
                    // mirrors the non-skip write-back below; without it a
                    // skipped version would ship Mojang's piston-meta URL with
                    // original_sha1 cleared, and would flip-flop every other
                    // cycle because the cleared original_sha1 forces a reprocess.
                    let new_url = old_version.url.clone();
                    let new_sha1 = old_version.sha1.clone();
                    let new_original_sha1 = old_version.original_sha1.clone();
                    let new_assets_index_url =
                        old_version.assets_index_url.clone();
                    let new_assets_index_sha1 =
                        old_version.assets_index_sha1.clone();
                    let new_java_profile = old_version.java_profile.clone();

                    let mut guard = cloned_manifest.lock().await;
                    if let Some(entry) = guard
                        .versions
                        .iter_mut()
                        .find(|v| v.id == version.id)
                    {
                        entry.url = new_url;
                        entry.sha1 = new_sha1;
                        entry.original_sha1 = new_original_sha1;
                        entry.assets_index_url = new_assets_index_url;
                        entry.assets_index_sha1 = new_assets_index_sha1;
                        entry.java_profile = new_java_profile;
                    }

                    return Ok(());
                }
            }

            // Capture upstream sha1 before we mutate `version.sha1` later in the loop.
            let upstream_sha1 = version.sha1.clone();

            let asset_cas_urls = Arc::clone(&asset_cas_urls);
            let cloned_manifest_mutex = Arc::clone(&cloned_manifest);
            let semaphore = Arc::clone(&semaphore);
            let patches = Arc::clone(&patches);
            let patched_versions = Arc::clone(&patched_versions);

            let assets_hash = old_version.and_then(|x| x.assets_index_sha1.clone());
            let old_assets_index_url =
                old_version.and_then(|x| x.assets_index_url.clone());

            async move {
                let mut version_info = daedalus::minecraft::fetch_version_info(version).await?;

                // §1.2(b) — Never-publish-unknowns for DownloadType.
                // A new download key (e.g. some future "android_client") deserialises
                // to DownloadType::Unknown(...) instead of failing the parse, but we
                // must not publish a version we don't fully understand. Warn, remove
                // this version from the manifest, and skip further processing.
                {
                    let unknown_keys: Vec<String> = version_info
                        .downloads
                        .keys()
                        .filter_map(|k| {
                            if let daedalus::minecraft::DownloadType::Unknown(s) = k {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !unknown_keys.is_empty() {
                        for key in &unknown_keys {
                            warn!(
                                version_id = %version_info.id,
                                download_key = %key,
                                "Mojang shipped a new DownloadType we don't recognise; \
                                 not publishing a fresh entry for this version until \
                                 support is added in daedalus::minecraft::DownloadType"
                            );
                        }
                        // Bail via Err so the shared failure handler below carries the
                        // previously-published entry forward instead of dropping the
                        // version outright: a bulk upstream re-publish that adds an
                        // unknown download key to existing versions must not unpublish
                        // them. Only a version with no baseline is removed from the
                        // manifest (the failure handler does that when there is nothing
                        // to carry forward).
                        return Err(crate::infrastructure::error::invalid_input(
                            format!(
                                "version {} has unrecognised DownloadType key(s): {:?}",
                                version_info.id, unknown_keys
                            ),
                        ));
                    }
                }

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
                patched_versions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                // Patch java version. Known components are normalised; an
                // unknown component (a runtime name Mojang ships before we
                // know it) passes through VERBATIM — degrading it to None
                // would publish a version whose launcher falls back to the
                // wrong Java and fails at launch, silently, every cycle.
                version_info.java_version = {
                    if let Some(java_version) = &version_info.java_version {
                        let parsed = MinecraftJavaProfile::try_from(&*java_version.component)
                            .expect("MinecraftJavaProfile::try_from is infallible");
                        if !parsed.is_known() {
                            #[cfg(feature = "sentry")]
                            sentry::capture_message(
                                &format!(
                                    "Unknown java runtime component \"{}\" — publishing it verbatim; add it to MinecraftJavaProfile",
                                    java_version.component
                                ),
                                sentry::Level::Warning,
                            );
                            warn!(
                                java_version = %java_version.component,
                                "Unknown java runtime component; publishing it verbatim"
                            );
                        }
                        Some(JavaVersion {
                            component: match parsed.as_str() {
                                Ok(s) => s.to_string(),
                                Err(_) => java_version.component.clone(),
                            },
                            // Mojang's major version passes through unchanged.
                            major_version: java_version.major_version,
                        })
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

                // Resolve the CAS URL for this version's asset index. Every
                // version sharing the same (id, sha1) gets the identical URL
                // — there is no winner race and a published version JSON can
                // never silently revert to the piston-meta URL.
                let asset_index_key = format!(
                    "{}:{}",
                    version_info.asset_index.id, version_info.asset_index.sha1
                );
                let asset_cas_url = if let Some(url) =
                    asset_cas_urls.get(&asset_index_key)
                {
                    url.clone()
                } else {
                    // The previous publish already has the object when the
                    // index is unchanged — reuse its URL instead of
                    // re-downloading the index for nothing.
                    let reused = assets_hash
                        .as_deref()
                        .filter(|prev_sha| {
                            *prev_sha == version_info.asset_index.sha1
                        })
                        .and_then(|_| old_assets_index_url.as_deref())
                        .filter(|prev_url| prev_url.contains("/objects/"))
                        .map(str::to_string);

                    let url = match reused {
                        Some(url) => url,
                        None => {
                            let assets_index = download_file(
                                &version_info.asset_index.url,
                                Some(&version_info.asset_index.sha1),
                                semaphore.clone(),
                            )
                            .await?;

                            let asset_hash = uploader
                                .upload_cas(
                                    assets_index.to_vec(),
                                    Some("application/json".to_string()),
                                    s3_client,
                                    semaphore.clone(),
                                )
                                .await?;

                            crate::common::cas::build_cas_url(&asset_hash)?
                        }
                    };
                    asset_cas_urls.insert(asset_index_key, url.clone());
                    url
                };

                version_info.asset_index.url = asset_cas_url.clone();

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
                    if let Some(entry) = guard
                        .versions
                        .iter_mut()
                        .find(|v| v.id == version_info.id)
                    {
                        entry.url = format!(
                            "{}/v{}/objects/{}/{}",
                            crate::common::BASE_URL.as_str(),
                            crate::services::cas::CAS_VERSION,
                            &version_hash[..2],
                            &version_hash[2..]
                        );
                        entry.assets_index_sha1 =
                            Some(version_info.asset_index.sha1.clone());
                        entry.assets_index_url = Some(asset_cas_url.clone());
                        // Unknown(...) serialises as the raw component string,
                        // so manifest consumers see a new runtime name instead
                        // of an absent java_profile.
                        entry.java_profile =
                            version_info.java_version.as_ref().map(|x| {
                                MinecraftJavaProfile::try_from(&*x.component)
                                    .unwrap_or(MinecraftJavaProfile::Unknown(x.component.clone()))
                            });
                        entry.sha1 = version_hash.clone();
                        entry.original_sha1 = Some(upstream_sha1.clone());
                    } else {
                        // The processing set is the manifest's own version list,
                        // so an id can only be missing if something removed it —
                        // and the only removal path (unknown DownloadType)
                        // returns before reaching this write. Surface loudly
                        // instead of inventing an entry.
                        warn!(
                            version_id = %version_info.id,
                            "Processed Minecraft version is no longer in the manifest; dropping its result"
                        );
                    }
                }

                // NOTE: We don't call manifest_builder.add_version() for minecraft here.
                // Instead, we use set_loader_versions() with the full VersionManifest at the end
                // to preserve rich metadata (type, url, time, releaseTime, sha1, etc.)

                Ok::<(), crate::infrastructure::error::Error>(())
            }
            .await?;

            Ok::<(), crate::infrastructure::error::Error>(())
            }
            .await;

            (version_id, result)
        })
    }

    let mut successful = 0;
    let mut failed = 0;
    {
        let mut versions = version_futures.into_iter().peekable();
        let mut chunk_index = 0;

        while versions.peek().is_some() {
            let now = Instant::now();

            let chunk: Vec<_> = versions.by_ref().take(100).collect();

            // Process chunk concurrently (semaphore controls actual I/O parallelism)
            for (version_id, result) in join_all(chunk).await {
                match result {
                    Ok(_) => {
                        successful += 1;
                    }
                    Err(e) => {
                        warn!(
                            version_id = %version_id,
                            "⚠️  Minecraft - Failed to process version: {}",
                            e
                        );
                        failed += 1;

                        // The shared manifest still holds the raw Mojang entry
                        // for this version (piston-meta URL, no patches, no
                        // CAS fields) — publishing that would hand launchers
                        // an unprocessed version. Restore the previously
                        // published entry when a baseline has one, otherwise
                        // drop the version from this cycle's manifest; the
                        // next cycle retries it.
                        let previous = old_versions.as_ref().and_then(|old| {
                            old.iter().find(|v| v.id == version_id).cloned()
                        });
                        let mut guard = cloned_manifest.lock().await;
                        match previous {
                            Some(prev_entry) => {
                                if let Some(entry) = guard
                                    .versions
                                    .iter_mut()
                                    .find(|v| v.id == version_id)
                                {
                                    *entry = prev_entry;
                                    warn!(
                                        version_id = %version_id,
                                        "Carried the previously published entry forward for the failed version"
                                    );
                                }
                            }
                            None => {
                                guard.versions.retain(|v| v.id != version_id);
                                warn!(
                                    version_id = %version_id,
                                    "No previous publish to carry forward; version is absent from this cycle's manifest"
                                );
                            }
                        }
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

    // Drain the manifest by acquiring the lock and `mem::take`ing it out.
    // Avoids the previous `Arc::try_unwrap` failure mode: if any future
    // panicked mid-await holding the Arc, try_unwrap returned Err and the
    // entire Minecraft cycle aborted, which made every loader skip. Now a
    // partial-failure cycle still produces a usable (possibly stale-in-spots)
    // manifest.
    let final_manifest = {
        let mut guard = cloned_manifest.lock().await;
        let placeholder = daedalus::minecraft::VersionManifest {
            latest: guard.latest.clone(),
            versions: Vec::new(),
        };
        std::mem::replace(&mut *guard, placeholder)
    };

    // Dead-anchor detection. Patch anchors are exact coordinate strings, so
    // an upstream rename silently disconnects them (this exact class hid the
    // Vulkan renderer when org.lwjgl:lwjgl:3.4.1 became :3.4.1:unsafe). On a
    // clean FULL reprocess — every published version went through the patch
    // pass — any patch that matched nothing is dead and must be surfaced.
    // Incremental cycles skip the check: their unexercised patches are just
    // skip-reused versions.
    let fully_patched = patched_versions
        .load(std::sync::atomic::Ordering::Relaxed)
        == final_manifest.versions.len();
    if failed == 0 && fully_patched {
        for patch in patches.never_matched() {
            #[cfg(feature = "sentry")]
            sentry::capture_message(
                &format!(
                    "Library patch matched no libraries across a full reprocess: {}",
                    patch._comment
                ),
                sentry::Level::Warning,
            );
            warn!(
                patch = %patch._comment,
                anchors = ?patch.match_,
                "Library patch matched no libraries across a full reprocess — its anchors may be dead (coordinate renamed or reclassified upstream)"
            );
        }
    }

    // Set the full Minecraft versions JSON in manifest_builder
    // This preserves rich metadata (type, url, time, releaseTime, sha1, complianceLevel, etc.)
    let versions_json = serde_json::to_value(&final_manifest.versions)?;
    manifest_builder.set_loader_versions("minecraft", versions_json);
    info!(
        version_count = final_manifest.versions.len(),
        "Set Minecraft versions with rich metadata in CAS manifest builder"
    );

    Ok(MinecraftData {
        manifest: final_manifest,
        upstream_version_ids,
    })
}

#[cfg(test)]
mod schema_drift_tests {
    use super::*;
    use chrono::Utc;

    /// Build a minimal `daedalus::minecraft::Version` with a given `VersionType`.
    fn make_version(
        id: &str,
        type_: daedalus::minecraft::VersionType,
    ) -> daedalus::minecraft::Version {
        daedalus::minecraft::Version {
            id: id.to_string(),
            type_,
            url: format!("https://example.com/{id}.json"),
            time: Utc::now(),
            release_time: Utc::now(),
            sha1: "deadbeef".to_string(),
            compliance_level: 1,
            original_sha1: None,
            assets_index_url: None,
            assets_index_sha1: None,
            java_profile: None,
        }
    }

    /// Simulates the §1.2(b) retain logic used inside `retrieve_data`.
    /// Returns the list of version ids that survive the filter.
    fn filter_unknown_version_types(
        versions: Vec<daedalus::minecraft::Version>,
    ) -> Vec<String> {
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = versions;
        out.retain(|v| {
            if let daedalus::minecraft::VersionType::Unknown(s) = &v.type_ {
                seen.insert(s.clone());
                false
            } else {
                true
            }
        });
        out.into_iter().map(|v| v.id).collect()
    }

    #[test]
    fn unknown_version_type_is_excluded_from_manifest() {
        let versions = vec![
            make_version("1.20.4", daedalus::minecraft::VersionType::Release),
            make_version(
                "24w99a",
                daedalus::minecraft::VersionType::Unknown(
                    "experiment".to_string(),
                ),
            ),
            make_version("1.20.3", daedalus::minecraft::VersionType::Release),
            make_version(
                "1.20.4-rc1",
                daedalus::minecraft::VersionType::Unknown(
                    "pre_release".to_string(),
                ),
            ),
        ];

        let surviving = filter_unknown_version_types(versions);

        // Only known-type versions survive.
        assert_eq!(surviving, vec!["1.20.4", "1.20.3"]);
    }

    #[test]
    fn all_known_version_types_survive_filter() {
        let versions = vec![
            make_version("1.20.4", daedalus::minecraft::VersionType::Release),
            make_version("24w04a", daedalus::minecraft::VersionType::Snapshot),
            make_version("b1.8", daedalus::minecraft::VersionType::OldBeta),
            make_version("a1.2.6", daedalus::minecraft::VersionType::OldAlpha),
        ];

        let surviving = filter_unknown_version_types(versions.clone());
        assert_eq!(surviving.len(), 4);
    }

    #[test]
    fn unknown_java_profile_passes_through_verbatim() {
        // An unknown runtime component parses to Unknown(...) without panicking
        // and survives into the published data as the raw string — never
        // silently degraded to an absent field.
        let java_version = daedalus::minecraft::JavaVersion {
            component: "java-runtime-omega".to_string(),
            major_version: 26,
        };

        // The version-JSON normalisation keeps the verbatim component.
        let parsed = MinecraftJavaProfile::try_from(&*java_version.component)
            .expect("try_from is infallible");
        assert!(!parsed.is_known());
        let published_component = match parsed.as_str() {
            Ok(s) => s.to_string(),
            Err(_) => java_version.component.clone(),
        };
        assert_eq!(published_component, "java-runtime-omega");

        // The manifest java_profile carries Unknown(...), which serialises as
        // the raw string.
        let profile = MinecraftJavaProfile::try_from(&*java_version.component)
            .unwrap_or(MinecraftJavaProfile::Unknown(
                java_version.component.clone(),
            ));
        assert_eq!(
            serde_json::to_string(&profile).unwrap(),
            "\"java-runtime-omega\""
        );
    }
}
