//! NeoForge loader processing
//!
//! This module handles NeoForge version retrieval and processing,
//! using common utilities shared with other loaders.

pub mod types;

use crate::common::{
    change_detection::detect_version_change,
    manifest_merge::{
        merge_loader_versions, sort_by_minecraft_order,
        sort_loaders_by_metadata,
    },
};
use crate::services::upload::BatchUploader;
use crate::download_file;
use crate::{BUILDS_IN_FLIGHT, MC_GROUPS_IN_FLIGHT};
use daedalus::GradleSpecifier;
use daedalus::minecraft::{Library, VersionManifest};
use daedalus::modded::{LoaderVersion, PartialVersionInfo, SidedDataEntry};
use dashmap::{DashMap, DashSet};
use futures::StreamExt;
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
static NEOFORGE_SKIP_LIST: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| {
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
    upstream_mc_version_ids: &HashSet<String>,
    uploader: &BatchUploader,
    manifest_builder: &crate::services::cas::ManifestBuilder,
    s3_client: &s3::Bucket,
    semaphore: Arc<Semaphore>,
    is_first_run: bool,
) -> Result<(), crate::infrastructure::error::Error> {
    info!(is_first_run, "Retrieving NeoForge data ...");

    // Build a fast lookup of MC version ids from the published manifest. Any
    // NeoForge installer whose profile.minecraft doesn't appear in this set
    // would publish a Version entry that no MC version can `inherits_from`,
    // so the launcher couldn't actually use it. Skip those.
    let valid_mc_versions: Arc<HashSet<String>> = Arc::new(
        minecraft_versions
            .versions
            .iter()
            .map(|v| v.id.clone())
            .collect(),
    );

    let maven_metadata = fetch_maven_metadata(semaphore.clone()).await?;
    // Previous publish's neoforge versions, resolved through the previous
    // root manifest — loader manifests live at timestamped keys that only the
    // root records, so this is the only path that can actually find them.
    let old_versions: Vec<daedalus::modded::Version> =
        match crate::services::cas::fetch_previous_loader_versions(
            s3_client, "neoforge",
        )
        .await
        {
            crate::services::cas::PreviousVersions::Loaded(v) => v,
            crate::services::cas::PreviousVersions::Absent => Vec::new(),
            crate::services::cas::PreviousVersions::Unreadable => {
                return Err(crate::infrastructure::error::invalid_input(
                    "neoforge: previous manifest baseline is unreadable (transient S3 \
                     error or parse failure); aborting this cycle so carry-forward \
                     keeps the last-good manifest instead of rebuilding from an empty base",
                ));
            }
        };
    let old_versions = Arc::new(Mutex::new(old_versions));

    let versions: Arc<Mutex<Vec<daedalus::modded::Version>>> =
        Arc::new(Mutex::new(Vec::new()));

    let visited_assets = Arc::new(DashSet::new());
    // Coordinate -> CAS hash, shared across every version processed this
    // run. When a library is referenced by more than one version, later
    // versions reuse the first upload's real CAS URL instead of emitting a
    // `maven/` URL that nothing is ever uploaded to (which 404s clients).
    let visited_lib_hashes: Arc<DashMap<GradleSpecifier, String>> =
        Arc::new(DashMap::new());

    let mut version_futures = Vec::new();

    // The maven-metadata grouping by inferred MC is still used to scope the inner futures,
    // but the actual published Minecraft id comes from each installer's profile.minecraft.
    for (_inferred_mc_version, loader_versions) in maven_metadata.clone() {
        let mut loaders = Vec::new();

        for (loader_version, new_forge) in loader_versions {
            // No upfront version-format validation: lenient_semver accepts essentially
            // any string (including non-semver garbage), so a format gate here would
            // reject nothing meaningful. Trust the maven-metadata XML and let
            // downstream processing surface real errors per version.
            loaders.push((loader_version, new_forge.to_string()))
        }

        if !loaders.is_empty() {
            let valid_mc_versions = Arc::clone(&valid_mc_versions);
            let versions = Arc::clone(&versions);
            let old_versions = Arc::clone(&old_versions);
            let visited_assets = Arc::clone(&visited_assets);
            let visited_lib_hashes = Arc::clone(&visited_lib_hashes);
            let semaphore = semaphore.clone();
            let is_first_run = is_first_run;
            version_futures.push(async move {
                let mut loaders_versions = Vec::new();

                {
                    let loaders_futures = loaders.into_iter().map(|(loader_version_full, new_forge)| async {
                        // Completion order is not input order, so the build id
                        // travels with its own result rather than being inferred
                        // from position.
                        let build_id = loader_version_full.clone();
                        let versions_mutex = Arc::clone(&old_versions);
                        let visited_assets = Arc::clone(&visited_assets);
                        let visited_lib_hashes = Arc::clone(&visited_lib_hashes);
                        let semaphore = Arc::clone(&semaphore);

                        let outcome = async move {
                            // Check skip list first
                            if NEOFORGE_SKIP_LIST.contains(loader_version_full.as_str()) {
                                info!("⏭️  NeoForge - Skipping excluded version: {}", loader_version_full);
                                return Ok::<Option<(String, LoaderVersion)>, crate::infrastructure::error::Error>(None);
                            }

                            let download_url = format!("https://maven.neoforged.net/releases/net/neoforged/{1}/{0}/{1}-{0}-installer.jar", loader_version_full, if &*new_forge == "true" { "neoforge" } else { "forge" });

                            // D3: skip an already-published version without
                            // re-downloading its immutable installer. Loader ids are
                            // globally unique, so find the existing entry (and the MC
                            // it was published under) by id. Steady cycles trust
                            // immutability; the first cycle after a restart verifies
                            // via the .sha1 sidecar to catch a re-publish.
                            let existing = {
                                let versions = versions_mutex.lock().await;
                                versions.iter().find_map(|v| {
                                    v.loaders
                                        .iter()
                                        .find(|l| l.id == loader_version_full)
                                        .map(|l| (v.id.clone(), l.clone()))
                                })
                            };
                            if let Some((existing_mc, existing_loader)) =
                                existing.filter(|(_, l)| l.url.contains("/objects/"))
                            {
                                let unchanged = if is_first_run {
                                    match (
                                        existing_loader.original_sha1.as_deref(),
                                        crate::fetch_sha1_sidecar(&download_url, semaphore.clone()).await,
                                    ) {
                                        (Some(s), Ok(u)) => s == u,
                                        _ => false,
                                    }
                                } else {
                                    true
                                };
                                if unchanged {
                                    let stable = &*new_forge == "true"
                                        && !loader_version_full.contains('-');
                                    info!("↩️  NeoForge - {} unchanged; re-emitting without re-download", loader_version_full);
                                    return Ok(Some((
                                        existing_mc,
                                        LoaderVersion {
                                            id: loader_version_full,
                                            url: existing_loader.url,
                                            stable,
                                            original_sha1: existing_loader.original_sha1,
                                        },
                                    )));
                                }
                            }

                            info!("Neoforge - Installer Start {}", loader_version_full.clone());

                            let bytes = download_file(&download_url, None, semaphore.clone()).await?;
                            // Upstream SHA-1 of the installer, stored so the next
                            // first-run sidecar check can detect a re-publish.
                            let installer_sha1 = daedalus::get_hash(bytes.clone()).await.ok();
                            let reader = std::io::Cursor::new(bytes);

                            let archive = match zip::ZipArchive::new(reader) {
                                Ok(a) => Some(a),
                                Err(e) => {
                                    warn!(
                                        neoforge_id = %loader_version_full,
                                        error = %e,
                                        "NeoForge - installer JAR is not a valid zip (corrupt download or upstream error page); skipping"
                                    );
                                    None
                                }
                            };

                            if let Some(archive) = archive {
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
                                    sha1: x.sha1,
                                    size: x.size,
                                    natives: x.natives,
                                    rules: x.rules,
                                    checksums: x.checksums,
                                    include_in_classpath: false,
                                    version_hashes: None,
                                    patched: false,
                                })).filter(|lib| !lib.name.is_log4j() ).collect();

                                let mut local_libs : HashMap<String, Option<bytes::Bytes>> = HashMap::new();

                                // Same predicate as the forge pipeline: bundled libraries are
                                // declared either with an empty downloads.artifact.url or with
                                // the maven-style url field, and both forms source their bytes
                                // from the installer jar's maven/ tree.
                                for lib in &libs {
                                    if crate::forge::libraries::is_local_lib(lib) {
                                        let mut archive_clone = archive.clone();
                                        let lib_name_clone = lib.name.clone();

                                        let lib_bytes = tokio::task::spawn_blocking(move || {
                                            let entry_name = format!("maven/{}", lib_name_clone.path());
                                            let lib_file = archive_clone.by_name(&entry_name).map_err(|err| {
                                                crate::infrastructure::error::invalid_input(format!("Failed to find entry {} in installer jar: {}", entry_name, err))
                                            });

                                            // NeoForge tracks Forge's installer layout, which since
                                            // 1.20.4 declares a self-referencing library whose jar is
                                            // not bundled under maven/ — tolerate the missing entry
                                            // for the loader's own artifacts instead of failing the
                                            // version on every cycle.
                                            if lib_file.is_err()
                                                && (&*lib_name_clone.artifact == "neoforge"
                                                    || &*lib_name_clone.artifact == "forge")
                                            {
                                                return Ok::<_, crate::infrastructure::error::Error>(None);
                                            }

                                            let mut lib_file = lib_file?;
                                            let mut lib_bytes =  Vec::new();
                                            lib_file.read_to_end(&mut lib_bytes)?;

                                            Ok::<_, crate::infrastructure::error::Error>(Some(bytes::Bytes::from(lib_bytes)))
                                        }).await??;

                                        local_libs.insert(lib.name.to_string(), lib_bytes);
                                    }
                                }

                                let version = profile.version.clone();

                                // profile.data is a BTreeMap, so iteration order is deterministic —
                                // pushed library order ends up in `libs` and is later included in
                                // the version JSON we hash.
                                let profile_data = std::mem::take(&mut profile.data);
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
                                                    return Err(crate::infrastructure::error::invalid_input(
                                                        format!(
                                                            "Invalid data path in NeoForge installer: '{}' (key: {}, side: {})",
                                                            value_clone, key, $side
                                                        ),
                                                    ));
                                                }
                                                {
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
                                                            // The map key must be the GradleSpecifier's canonical Display
                                                            // form — that is what the consumption lookup uses, and Display
                                                            // omits a plain '@jar' extension, so the raw formatted string
                                                            // would never match for .jar data files.
                                                            let name: GradleSpecifier = format!(
                                                                "gg.gdl.daedalus:neoforge-installer-extracts:{}:{}-{}@{}",
                                                                version, $side, file_name, ext
                                                            ).as_str().try_into()?;
                                                            let path = name.to_string();
                                                            $value = format!("[{}]", &path);
                                                            local_libs.insert(path.clone(), Some(bytes::Bytes::from(lib_bytes)));

                                                            libs.push(Library {
                                                                downloads: None,
                                                                extract: None,
                                                                name,
                                                                url: Some("".to_string()),
                                                                sha1: None,
                                                                size: None,
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

                                profile.data = sorted_data;

                                let now = Instant::now();


                                let libs = futures::future::try_join_all(libs.into_iter().map(|mut lib| {
                                    let semaphore = semaphore.clone();
                                    let visited_assets = visited_assets.clone();
                                    let visited_lib_hashes = visited_lib_hashes.clone();
                                    let local_libs = local_libs.clone();

                                    async move {
                                    // Reuse the CAS URL when another version this run already
                                    // uploaded this exact artifact.
                                    if let Some(hash) = crate::common::cas::claim_or_reuse(&visited_assets, &visited_lib_hashes, &lib.name) {
                                        crate::common::cas::set_library_url(&mut lib, crate::common::cas::build_cas_url(&hash)?);
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
                                                local_libs.get(&lib.name.to_string()).cloned().flatten()
                                            };

                                            if res.is_none() {
                                                artifact.url = None;
                                            }

                                            res
                                        } else { None }
                                    } else if let Some(ref mut url) = lib.url {
                                        let res = if url.is_empty() {
                                            local_libs.get(&lib.name.to_string()).cloned().flatten()
                                        } else {
                                            // The url field is a maven repository base — join the
                                            // artifact path like the forge pipeline does; fetching
                                            // the base verbatim downloads the repository's index
                                            // page as 'jar bytes'.
                                            let lib_url = format!("{}/{}", url, lib.name.path());
                                            let checksum = lib
                                                .checksums
                                                .as_ref()
                                                .and_then(|c| c.first())
                                                .cloned();
                                            Some(download_file(
                                                &lib_url,
                                                checksum.as_deref(),
                                                semaphore.clone(),
                                            )
                                                .await?)
                                        };

                                        if res.is_none() {
                                            lib.url = None;
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

                                        // Cache the hash so other versions referencing this same artifact
                                        // this run dedup to the CAS URL above.
                                        visited_lib_hashes.insert(lib.name.clone(), hash.clone());

                                        // Use common CAS URL building
                                        crate::common::cas::set_library_url(&mut lib, crate::common::cas::build_cas_url(&hash)?);
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
                                // The CAS content hash: comparable against the hash inside the
                                // previous manifest's object URL, and reusable as the object key
                                // when the version is unchanged.
                                let new_hash = BatchUploader::compute_hash(&version_bytes);

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

                                // NeoForge's own versioning marks prereleases with a dash
                                // suffix ("26.1.2.70-beta", "...-alpha.1+snapshot-1"); plain
                                // dotted versions are releases. Legacy forge-alias ids
                                // ("1.20.1-47.x") stay unstable — no promotions data exists
                                // for that coordinate.
                                let stable = &*new_forge == "true"
                                    && !loader_version_full.contains('-');

                                // Trust profile.minecraft over the maven-derived inferred id —
                                // Mojang's "no 1.x prefix" versioning makes reverse-engineering
                                // from the NeoForge coordinate brittle.
                                return Ok(Some((profile.minecraft.clone(), LoaderVersion {
                                    id: loader_version_full,
                                    url: cas_url,
                                    stable,
                                    original_sha1: installer_sha1.clone(),
                                })));
                            }

                            Ok(None)
                        }.await;

                        (build_id, outcome)
                    });

                    {
                        let mut successful = 0;
                        let mut failed = 0;

                        // Bounded rather than joined: each future holds its installer
                        // and the jars it extracted from download until its libraries
                        // finish uploading, so an unbounded fan-out parks the entire
                        // installer corpus in memory before the first library uploads.
                        let mut builds = futures::stream::iter(loaders_futures)
                            .buffer_unordered(BUILDS_IN_FLIGHT);

                        while let Some((build_id, result)) = builds.next().await {
                            match result {
                                Ok(Some(entry)) => {
                                    loaders_versions.push(entry);
                                    successful += 1;
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    warn!("NeoForge - Failed to process build {build_id}: {e}");
                                    failed += 1;
                                }
                            }
                        }

                        if failed > 0 {
                            warn!("NeoForge - Skipped {} versions due to errors, {} succeeded", failed, successful);
                        }
                    }
                }

                // Group loaders by the actual Minecraft version each installer reports
                // in `profile.minecraft`. The maven-derived `minecraft_version` is only
                // used as a coarse maven-metadata bucket key — installers may collapse
                // into a different MC id at install_profile.json read time.
                let mut by_actual_mc: BTreeMap<String, Vec<LoaderVersion>> = BTreeMap::new();
                let mut dropped_unknown_mc = 0usize;
                for (actual_mc, loader) in loaders_versions {
                    if !valid_mc_versions.contains(&actual_mc) {
                        // Mojang doesn't (yet) publish this MC version, so the
                        // launcher would have nothing to inherit_from. Drop the
                        // entry rather than emit a manifest reference that
                        // can't resolve.
                        warn!(
                            "NeoForge - Dropping loader {} for unknown MC version '{}'",
                            loader.id, actual_mc
                        );
                        dropped_unknown_mc += 1;
                        continue;
                    }
                    by_actual_mc.entry(actual_mc).or_default().push(loader);
                }
                if dropped_unknown_mc > 0 {
                    warn!(
                        "NeoForge - Dropped {} loader(s) referencing unpublished MC versions",
                        dropped_unknown_mc
                    );
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
        let mut successful_mc_versions = 0;
        let mut failed_mc_versions = 0;

        // Every group in flight multiplies the builds in flight beneath it, so
        // this bound and BUILDS_IN_FLIGHT together set the ceiling on resident
        // installers. The group's own id is carried by the error.
        let mut groups = futures::stream::iter(version_futures)
            .buffer_unordered(MC_GROUPS_IN_FLIGHT);

        while let Some(result) = groups.next().await {
            match result {
                Ok(()) => successful_mc_versions += 1,
                Err(e) => {
                    warn!("NeoForge - Failed to process a Minecraft version: {e}");
                    failed_mc_versions += 1;
                }
            }
        }

        if failed_mc_versions > 0 {
            warn!(
                "NeoForge - {} Minecraft versions failed to process, {} succeeded",
                failed_mc_versions, successful_mc_versions
            );
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
    let mut final_versions =
        merge_loader_versions(old_manifest_versions, new_versions, "NeoForge");

    // Drop phantom MC-version groups: entries whose id is not a Minecraft
    // version Mojang publishes at all. The fresh path filters builds to ids in
    // this cycle's processed manifest, but merge_loader_versions only adds and
    // updates, so groups published under an earlier inference heuristic's bogus
    // ids would otherwise persist forever.
    //
    // The test is Mojang's upstream id set, not this cycle's processed manifest:
    // a version whose processing fails with no baseline to carry forward is
    // absent from the processed manifest while still being a real version (see
    // minecraft::retrieve_data), so pruning against that would delete an
    // established group over one transient fetch failure. Keeping such a group
    // leaves it briefly unusable until the version processes again, which the
    // next cycle repairs; deleting it is not recoverable.
    //
    // NOTE: a one-time cleanup of a LARGE pre-existing phantom set can trip the
    // sanity gate's MC-coverage check (a big drop looks like a regression); that
    // is the gate working as designed and may need an operator to inspect once.
    let pruned =
        prune_phantom_mc_groups(&mut final_versions, upstream_mc_version_ids);
    if pruned > 0 {
        warn!(
            "NeoForge - Pruned {} phantom MC-version group(s) absent from Mojang's version manifest",
            pruned
        );
    }

    // Use common sorting utilities
    sort_by_minecraft_order(&mut final_versions, minecraft_versions);

    // Sort loaders within each version using metadata order
    for version in &mut final_versions {
        if let Some(loader_versions) = maven_metadata.get(&version.id) {
            let loader_order: Vec<String> =
                loader_versions.iter().map(|(id, _)| id.clone()).collect();
            sort_loaders_by_metadata(version, &loader_order);
        }
    }

    // Set the full NeoForge versions JSON in manifest_builder with nested structure
    // This preserves game version -> loader version mappings
    let versions_json = serde_json::to_value(&final_versions)?;
    manifest_builder.set_loader_versions("neoforge", versions_json);
    info!(
        version_count = final_versions.len(),
        "Set NeoForge versions with nested structure in CAS manifest builder"
    );

    Ok(())
}

const DEFAULT_MAVEN_METADATA_URL_1: &str = "https://maven.neoforged.net/releases/net/neoforged/forge/maven-metadata.xml";
const DEFAULT_MAVEN_METADATA_URL_2: &str = "https://maven.neoforged.net/releases/net/neoforged/neoforge/maven-metadata.xml";

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
) -> Result<
    HashMap<String, Vec<(String, bool)>>,
    crate::infrastructure::error::Error,
> {
    async fn fetch_values(
        url: &str,
        semaphore: Arc<Semaphore>,
    ) -> Result<Metadata, crate::infrastructure::error::Error> {
        let bytes = download_file(url, None, semaphore).await?;
        // Propagate UTF-8 conversion failures instead of `unwrap_or_default()`
        // which silently produced an empty string — a proxy returning a binary
        // / latin1 error page would feed empty XML to serde and we'd see a
        // generic parse error with no transport-level context.
        let xml = String::from_utf8(bytes.to_vec()).map_err(|e| {
            crate::infrastructure::error::invalid_input(format!(
                "NeoForge maven metadata at {url} returned non-UTF-8 bytes: {e}"
            ))
        })?;
        Ok(serde_xml_rs::from_str(&xml)?)
    }

    // Fetch both maven-metadata files concurrently. The legacy `forge` alias
    // (URL_1) failing must not block the actual `neoforge` (URL_2) processing,
    // since URL_2 is the load-bearing endpoint — empty forge alias map is fine,
    // an empty neoforge map publishes nothing.
    let (forge_result, neo_result) = tokio::join!(
        fetch_values(DEFAULT_MAVEN_METADATA_URL_1, semaphore.clone()),
        fetch_values(DEFAULT_MAVEN_METADATA_URL_2, semaphore),
    );
    let forge_values = match forge_result {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, url = DEFAULT_MAVEN_METADATA_URL_1, "Legacy forge maven metadata fetch failed; continuing with neoforge only");
            // Empty placeholder so the rest of the function operates as
            // "no legacy forge versions present" rather than failing.
            Metadata {
                versioning: Versioning {
                    versions: Versions {
                        version: Vec::new(),
                    },
                },
            }
        }
    };
    let neo_values = neo_result?;

    let mut map: HashMap<String, Vec<(String, bool)>> = HashMap::new();

    for value in forge_values.versioning.versions.version {
        let is_snapshot = value.contains('w')
            || value.contains("-pre")
            || value.contains("-rc");

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
        // If `major` isn't numeric we can't reliably classify which MC-version
        // scheme (1.x.y vs YY.D.H) this NeoForge build belongs to. Surface
        // and drop rather than fall back to `0` + the old-versioning branch,
        // which would produce nonsense MC ids like `1.26.1.2.11-beta` and
        // then drop them later via the "unknown MC version" filter — masking
        // the real upstream change behind two unrelated warnings.
        let Ok(major_num) = major.parse::<u32>() else {
            warn!(
                neoforge_id = %original,
                major = %major,
                "NeoForge - non-numeric major version; skipping (upstream versioning scheme may have changed)"
            );
            continue;
        };

        if major_num > 21 {
            // New MC versioning (YY.D.H) — MC dropped the "1." prefix after 1.21
            // NeoForge format: YY.D.H.build[-prerelease][+phase-N]
            // e.g. 26.1.2.11-beta -> MC 26.1.2
            // e.g. 26.1.0.0-alpha.1+snapshot-1 -> MC 26.1-snapshot-1
            // e.g. 26.1.0.0-alpha.15+pre-3 -> MC 26.1-pre-3
            let hotfix = parts
                .next()
                .and_then(|h| h.split(|c: char| !c.is_ascii_digit()).next())
                .unwrap_or("0");

            let base = match (minor, hotfix) {
                ("0", _) => major.to_string(),
                (_, "0") => format!("{}.{}", major, minor),
                _ => format!("{}.{}.{}", major, minor, hotfix),
            };

            // Extract MC phase suffix: +snapshot-N, +pre-N, +rc-N
            let game_version =
                if let Some((_, phase)) = original.split_once('+') {
                    format!("{}-{}", base, phase)
                } else {
                    base
                };

            map.entry(game_version).or_default().push((original, true));
        } else {
            // Old MC versioning (1.x.y) — skip weekly snapshots, pre-releases, RCs
            if original.contains('w')
                || original.contains("-pre")
                || original.contains("-rc")
            {
                info!("Skipping old snapshot version: {}", original);
                continue;
            }

            let game_version = if minor == "0" {
                format!("1.{}", major)
            } else {
                format!("1.{}.{}", major, minor)
            };

            map.entry(game_version).or_default().push((original, true));
        }
    }

    Ok(map)
}

/// Removes groups whose Minecraft version id Mojang does not publish, returning
/// how many were dropped.
///
/// `upstream_mc_version_ids` must come from Mojang's manifest rather than a
/// processed one, so that a version this cycle failed to process keeps its
/// group instead of having it deleted.
fn prune_phantom_mc_groups(
    versions: &mut Vec<daedalus::modded::Version>,
    upstream_mc_version_ids: &HashSet<String>,
) -> usize {
    let before = versions.len();
    versions.retain(|v| upstream_mc_version_ids.contains(&v.id));
    before - versions.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(id: &str) -> daedalus::modded::Version {
        daedalus::modded::Version {
            id: id.to_string(),
            stable: true,
            loaders: Vec::new(),
        }
    }

    fn ids(values: &[&str]) -> HashSet<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn prunes_groups_whose_mc_version_never_existed() {
        let mut versions =
            vec![group("1.20.1"), group("1.20.256"), group("1.21")];

        let pruned =
            prune_phantom_mc_groups(&mut versions, &ids(&["1.20.1", "1.21"]));

        assert_eq!(pruned, 1);
        assert_eq!(
            versions.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
            vec!["1.20.1", "1.21"]
        );
    }

    #[test]
    fn keeps_a_real_version_missing_from_this_cycles_processed_manifest() {
        // 1.20.1 failed to process this cycle with no baseline to carry forward,
        // so it is absent from the processed manifest while still being a real
        // Mojang version. Pruning it here would delete an established group over
        // one transient fetch failure.
        let mut versions = vec![group("1.20.1"), group("1.21")];

        let pruned = prune_phantom_mc_groups(
            &mut versions,
            &ids(&["1.20.1", "1.21", "1.21.1"]),
        );

        assert_eq!(pruned, 0);
        assert_eq!(versions.len(), 2);
    }
}
