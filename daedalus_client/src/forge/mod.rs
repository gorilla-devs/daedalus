//! Forge loader metadata retrieval and processing

pub mod libraries;
pub mod types;
pub mod version;

// Re-export commonly used types
pub use types::{
    ForgeInstallerProfileV1, ForgeInstallerProfileV2,
    MinecraftVersionLibraryCache,
};

use crate::common::manifest_merge::{
    merge_loader_versions, sort_by_minecraft_order, sort_loaders_by_metadata,
};
use crate::services::upload::BatchUploader;
use crate::{download_file, download_file_mirrors};
use daedalus::GradleSpecifier;
use daedalus::minecraft::{Argument, ArgumentType, Library, VersionManifest};
use daedalus::modded::{LoaderVersion, PartialVersionInfo};
use dashmap::{DashMap, DashSet};
use semver::{Version, VersionReq};
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::io::Read;
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};
use tracing::{info, warn};

static FORGE_MANIFEST_V1_QUERY: LazyLock<VersionReq> =
    LazyLock::new(|| VersionReq::parse(">=8.0.684, <23.5.2851").unwrap());

/// install_profile.json format 2, one contiguous range: 1.12.2's
/// 14.23.5.2851 through the 1.16.x line. The 1.15.2 tail (31.2.52–31.2.60,
/// including the upstream-recommended 31.2.57) sits inside it and is handled
/// identically to its neighbours.
static FORGE_MANIFEST_V2_QUERY: LazyLock<VersionReq> =
    LazyLock::new(|| VersionReq::parse(">=23.5.2851, <37.0.0").unwrap());

static FORGE_MANIFEST_V3_QUERY: LazyLock<VersionReq> =
    LazyLock::new(|| VersionReq::parse(">=37.0.0").unwrap());

// Re-export version utilities for convenience
pub use version::{
    extract_hash_from_cas_url, fetch_generated_version_info,
    should_ignore_artifact,
};

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

    // Forge publishes a small JSON file marking each MC version's "recommended"
    // and "latest" build. We mirror Prism's approach and surface "recommended"
    // as LoaderVersion.stable. The set is keyed by full loader id (e.g.
    // "1.20.1-47.4.10") for direct lookup at LoaderVersion construction time.
    // A promotions fetch failure must abort the cycle rather than fall back to
    // an empty set: merge_loader_versions overwrites existing entries wholesale,
    // so publishing with an empty recommended set would republish every Forge
    // build as unstable and wipe the "recommended" markers until the next
    // successful cycle. Aborting lets carry-forward keep the last-good manifest.
    let recommended_loaders: Arc<HashSet<String>> =
        Arc::new(fetch_forge_promotions(semaphore.clone()).await.map_err(|e| {
            crate::infrastructure::error::invalid_input(format!(
                "forge: failed to fetch promotions_slim.json ({e}); aborting this cycle \
                 so carry-forward keeps the last-good stable flags instead of \
                 republishing every build as unstable"
            ))
        })?);
    info!(
        recommended_count = recommended_loaders.len(),
        "Loaded Forge promotions"
    );

    // Previous publish's forge versions, resolved through the previous root
    // manifest — loader manifests live at timestamped keys that only the root
    // records, so this is the only path that can actually find them.
    let old_versions: Vec<daedalus::modded::Version> =
        match crate::services::cas::fetch_previous_loader_versions(
            s3_client, "forge",
        )
        .await
        {
            crate::services::cas::PreviousVersions::Loaded(v) => v,
            crate::services::cas::PreviousVersions::Absent => Vec::new(),
            crate::services::cas::PreviousVersions::Unreadable => {
                return Err(crate::infrastructure::error::invalid_input(
                    "forge: previous manifest baseline is unreadable (transient S3 \
                     error or parse failure); aborting this cycle so carry-forward \
                     keeps the last-good manifest instead of rebuilding from an empty base",
                ));
            }
        };
    let old_versions = Arc::new(Mutex::new(old_versions));

    let mc_library_cache_mutex =
        Arc::new(Mutex::new(MinecraftVersionLibraryCache::new()));

    // Processed version-JSON URL per MC id, from this run's minecraft
    // manifest. The V1 vanilla-library filter sources its library sets from
    // these CAS objects — processed version JSONs exist nowhere else.
    let mc_version_urls: Arc<HashMap<String, String>> = Arc::new(
        minecraft_versions
            .versions
            .iter()
            .map(|v| (v.id.clone(), v.url.clone()))
            .collect(),
    );

    let versions = Arc::new(Mutex::new(Vec::new()));

    let visited_assets = Arc::new(DashSet::new());
    // Cache CAS hash per artifact so dedup can produce a real CAS URL.
    // Shared by both the V1 and V2 library paths.
    let visited_lib_hashes: Arc<DashMap<GradleSpecifier, String>> =
        Arc::new(DashMap::new());

    let mut version_futures = Vec::new();

    for (minecraft_version, loader_versions) in maven_metadata.clone() {
        let mut loaders = Vec::new();

        for loader_version_full in loader_versions {
            // Don't filter by minecraft_version snapshot pattern — Forge does ship
            // installers for some pre-releases (e.g. 1.13-pre7) and `1.7.10_pre4`
            // uses an underscore that the rename below depends on. Use FORGE_SKIP_LIST
            // for known-broken specific versions instead.

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

                // Don't `?` out of the whole MC-version loop on a single
                // malformed Forge version; just skip it. Previously a single
                // bad version (e.g. Forge ships `1.20.1-47.1.0.HOTFIX`) would
                // drop ALL loaders for that MC version silently — the error
                // surfaced as "failed to process Minecraft version".
                let version = match Version::parse(&loader_version) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            forge_id = %loader_version_full,
                            parsed = %loader_version,
                            error = %e,
                            "Forge - skipping unparseable loader version"
                        );
                        continue;
                    }
                };

                if FORGE_MANIFEST_V1_QUERY.matches(&version)
                    || FORGE_MANIFEST_V2_QUERY.matches(&version)
                    || FORGE_MANIFEST_V3_QUERY.matches(&version)
                {
                    loaders.push((loader_version_full, version))
                } else {
                    // Version parses but falls into none of our supported
                    // installer-format ranges. Surface so we notice when
                    // Forge ships a new family that needs a new query
                    // range — previously this dropped silently.
                    warn!(
                        forge_id = %loader_version_full,
                        "Forge - version matches no installer-format query range; skipping"
                    );
                }
            }
        }

        if !loaders.is_empty() {
            version_futures.push(async {
                let mut loaders_versions = Vec::new();

                {
                    let loaders_futures = loaders.into_iter().map(|(loader_version_full, version)| async {
                        let mc_library_cache_mutex = Arc::clone(&mc_library_cache_mutex);
                        let mc_version_urls = Arc::clone(&mc_version_urls);
                        let versions_mutex = Arc::clone(&old_versions);
                        let visited_assets = Arc::clone(&visited_assets);
                        let visited_lib_hashes = Arc::clone(&visited_lib_hashes);
                        let recommended_loaders = Arc::clone(&recommended_loaders);
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

                            // Promotions are keyed "{mc}-{forge}"; maven ids may carry a
                            // branch suffix on top ("1.7.10-10.13.4.1614-1.7.10"), so the
                            // stable lookup compares on the first two dash segments. The MC
                            // part itself never contains a dash in forge maven ids
                            // (pre-release MCs use underscores, e.g. 1.7.10_pre4).
                            let promotion_key = {
                                let mut parts = loader_version_full.splitn(3, '-');
                                match (parts.next(), parts.next()) {
                                    (Some(mc), Some(forge)) => format!("{}-{}", mc, forge),
                                    _ => loader_version_full.clone(),
                                }
                            };


                            info!("Forge - Installer Start {}", loader_version_full.clone());
                            let bytes = download_file(&format!("https://maven.minecraftforge.net/net/minecraftforge/forge/{0}/forge-{0}-installer.jar", loader_version_full), None, semaphore.clone()).await?;

                            let reader = std::io::Cursor::new(bytes);

                            let archive = match zip::ZipArchive::new(reader) {
                                Ok(a) => Some(a),
                                Err(e) => {
                                    warn!(
                                        forge_id = %loader_version_full,
                                        error = %e,
                                        "Forge - installer JAR is not a valid zip (corrupt download or upstream error page); skipping"
                                    );
                                    None
                                }
                            };

                            if let Some(archive) = archive {
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
                                        let Some(mc_version_url) = mc_version_urls.get(&profile.install.minecraft) else {
                                            // The MC version this installer targets isn't in the
                                            // published manifest this cycle — the vanilla-library
                                            // filter has nothing to compare against.
                                            return Err(crate::infrastructure::error::invalid_input(format!(
                                                "Forge {} targets MC version {} which is not in this cycle's manifest",
                                                loader_version_full, profile.install.minecraft
                                            )));
                                        };
                                        let mut mc_library_cache = mc_library_cache_mutex.lock().await;
                                        mc_library_cache.load_minecraft_version_libs(&profile.install.minecraft, mc_version_url).await?.clone()
                                    };
                                    let libs = futures::future::try_join_all(profile.version_info.libraries.into_iter().map(|mut lib| {
                                        let semaphore = semaphore.clone();
                                        let visited_assets = visited_assets.clone();
                                        let visited_lib_hashes = visited_lib_hashes.clone();
                                        let forge_universal_bytes = forge_universal_bytes.clone();
                                        let forge_universal_path = forge_universal_path.clone();
                                        let minecraft_libs_filter = minecraft_libs_filter.clone();

                                        async move {
                                        if lib.name.is_lwjgl() || lib.name.is_log4j() || should_ignore_artifact(&minecraft_libs_filter, &lib.name) {
                                            return Ok::<Option<Library>, crate::infrastructure::error::Error>(None);
                                        }

                                        if let Some(url) = lib.url {
                                            // Reuse the CAS URL when another task already uploaded this artifact.
                                            if let Some(hash) = crate::common::cas::claim_or_reuse(&visited_assets, &visited_lib_hashes, &lib.name) {
                                                lib.url = Some(crate::common::cas::build_cas_url(&hash)?);
                                                return Ok::<Option<Library>, crate::infrastructure::error::Error>(Some(lib));
                                            }

                                            let artifact_path = lib.name.path();
                                            let mirrors = vec![url.as_str(), "https://maven.creeperhost.net/", "https://libraries.minecraft.net/"];
                                            // V1 metadata carries the served jar's SHA1 in
                                            // checksums[0]; verifying it keeps a mirror's
                                            // wrong-bytes 200 (soft-404 page, truncation)
                                            // from being immortalised as the CAS object
                                            // every other version dedups onto.
                                            let checksum = lib
                                                .checksums
                                                .as_ref()
                                                .and_then(|c| c.first())
                                                .cloned();
                                            let artifact = if lib.name.to_string() == forge_universal_path {
                                                forge_universal_bytes.clone()
                                            } else {
                                                download_file_mirrors(
                                                    &artifact_path,
                                                    &mirrors,
                                                    checksum.as_deref(),
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

                                            // Cache hash for future dedup hits.
                                            visited_lib_hashes.insert(lib.name.clone(), hash.clone());

                                            // Store full CAS URL
                                            lib.url = Some(crate::common::cas::build_cas_url(&hash)?);
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
                                    // The CAS content hash: comparable against the hash inside the
                                    // previous manifest's object URL, and reusable as the object key
                                    // when the version is unchanged.
                                    let new_hash = BatchUploader::compute_hash(&version_bytes);

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

                                    let cas_url = crate::common::cas::build_cas_url(&version_hash)?;

                                    return Ok(Some(LoaderVersion {
                                        stable: recommended_loaders.contains(&promotion_key),
                                        id: loader_version_full,
                                        url: cas_url,
                                    }));
                                } else if FORGE_MANIFEST_V2_QUERY.matches(&version) || FORGE_MANIFEST_V3_QUERY.matches(&version) {
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
                                                sha1: x.sha1,
                                                size: x.size,
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

                                    let version = profile.version.clone();

                                    for entry in profile.data.values_mut() {
                                        if entry.client.starts_with('/') || entry.server.starts_with('/') {
                                            macro_rules! read_data {
                                                ($value:expr) => {
                                                    let mut archive_clone = archive.clone();
                                                    let value_clone = $value.clone();
                                                    // Validate path has content after the leading slash
                                                    if value_clone.len() <= 1 {
                                                        return Err(crate::infrastructure::error::invalid_input(format!(
                                                            "Invalid data path in Forge installer: '{}'",
                                                            value_clone
                                                        )));
                                                    }
                                                    let lib_bytes = tokio::task::spawn_blocking(move || {
                                                        let mut lib_file = archive_clone.by_name(&value_clone[1..])?;
                                                        let mut lib_bytes =  Vec::new();
                                                        lib_file.read_to_end(&mut lib_bytes)?;

                                                        Ok::<bytes::Bytes, crate::infrastructure::error::Error>(bytes::Bytes::from(lib_bytes))
                                                    }).await??;

                                                    let split = $value.split('/').last();

                                                    if let Some(last) = split {
                                                        // rsplit_once handles multi-dot names such as
                                                        // `foo.tar.gz` (file_name = "foo.tar", ext = "gz");
                                                        // the previous split('.') + two next() calls dropped
                                                        // everything after the first dot. Matches the
                                                        // neoforge extraction path.
                                                        if let Some((file_name, ext)) = last.rsplit_once('.') {
                                                                // Use consistent namespace (synced with Modrinth daedalus approach).
                                                                // The map key must be the GradleSpecifier's canonical Display form —
                                                                // that is what the consumption lookup uses, and Display omits a
                                                                // plain '@jar' extension, so the raw formatted string would never
                                                                // match for .jar data files.
                                                                let name: GradleSpecifier = format!("gg.gdl.daedalus:forge-installer-extracts:{}:{}@{}", version, file_name, ext).as_str().try_into()?;
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
                                        let visited_lib_hashes = visited_lib_hashes.clone();
                                        let local_libs = local_libs.clone();

                                        async move {
                                        // Reuse the CAS URL when another version this run already
                                        // uploaded this exact artifact.
                                        if let Some(hash) = crate::common::cas::claim_or_reuse(&visited_assets, &visited_lib_hashes, &lib.name) {
                                            crate::common::cas::set_library_url(&mut lib, crate::common::cas::build_cas_url(&hash)?);
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

                                                if res.is_none() {
                                                    artifact.url = None;
                                                }

                                                res
                                            } else { None }
                                        } else if let Some(ref mut url) = lib.url {
                                            let res = if url.is_empty() {
                                                local_libs.get(&lib.name.to_string()).cloned().flatten()
                                            } else {
                                                let lib_url = format!("{}/{}", url, lib.name.path());
                                                // url-style metadata carries the served SHA1
                                                // in checksums[0] when present — verify it so
                                                // wrong bytes can't become the shared CAS object.
                                                let checksum = lib
                                                    .checksums
                                                    .as_ref()
                                                    .and_then(|c| c.first())
                                                    .cloned();
                                                Some(download_file(
                                                    &lib_url,
                                                    checksum.as_deref(),
                                                    semaphore.clone(),
                                                ).await?)
                                            };

                                            if res.is_none() {
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

                                            // Cache the hash so other versions referencing this same artifact
                                            // this run dedup to the CAS URL above.
                                            visited_lib_hashes.insert(lib.name.clone(), hash.clone());

                                            // Store full CAS URL
                                            crate::common::cas::set_library_url(&mut lib, crate::common::cas::build_cas_url(&hash)?);
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
                                    // The CAS content hash — see the V1 branch note above.
                                    let new_hash = BatchUploader::compute_hash(&version_bytes);

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

                                    let cas_url = crate::common::cas::build_cas_url(&version_hash)?;

                                    return Ok(Some(LoaderVersion {
                                        stable: recommended_loaders.contains(&promotion_key),
                                        id: loader_version_full,
                                        url: cas_url,
                                    }));
                                }
                            }

                            Ok(None)
                        }.await
                    });

                    {
                        let len = loaders_futures.len();
                        let mut successful = 0;
                        let mut failed = 0;

                        // The downloads inside each future already gate on `semaphore`; running
                        // these futures concurrently lets the semaphore actually do its job.
                        for (idx, result) in futures::future::join_all(loaders_futures).await.into_iter().enumerate() {
                            match result {
                                Ok(Some(loader_version)) => {
                                    loaders_versions.push(loader_version);
                                    successful += 1;
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    warn!("⚠️  Forge - Failed to process version {}/{len}: {}", idx + 1, e);
                                    failed += 1;
                                }
                            }
                        }

                        info!("📊 Forge - Loader processing complete: {} successful, {} failed", successful, failed);
                    }
                }

                if loaders_versions.is_empty() {
                    // Every loader build for this MC version failed to process
                    // this cycle (e.g. a maven outage while the version first
                    // appeared). Don't add an MC-version entry with no installable
                    // builds — it would show launchers an empty version picker.
                    // merge_loader_versions preserves any previously-published
                    // entry for this id, and a later cycle adds it once its builds
                    // process.
                    warn!(
                        minecraft_version = %minecraft_version,
                        "Forge - no loader builds processed for this MC version this cycle; not adding an empty entry"
                    );
                } else {
                    versions.lock().await.push(daedalus::modded::Version {
                        id: minecraft_version,
                        stable: true,
                        loaders: loaders_versions,
                    });
                }

                Ok::<(), crate::infrastructure::error::Error>(())
            });
        }
    }

    {
        let len = version_futures.len();
        let mut successful = 0;
        let mut failed = 0;

        for (idx, result) in futures::future::join_all(version_futures)
            .await
            .into_iter()
            .enumerate()
        {
            match result {
                Ok(_) => successful += 1,
                Err(e) => {
                    warn!(
                        "⚠️  Forge - Failed to process Minecraft version {}/{len}: {}",
                        idx + 1,
                        e
                    );
                    failed += 1;
                }
            }
        }

        info!(
            "📊 Forge - Minecraft version processing complete: {} successful, {} failed",
            successful, failed
        );
    }

    // Extract versions by locking the mutex instead of try_unwrap
    // This avoids silent failures when Arc still has strong references from async closures
    let old_manifest_versions = {
        let mut guard = old_versions.lock().await;
        std::mem::take(&mut *guard)
    };

    let new_versions = {
        let mut guard = versions.lock().await;
        std::mem::take(&mut *guard)
    };

    // Merge new versions with old ones to preserve existing data
    let mut final_versions =
        merge_loader_versions(old_manifest_versions, new_versions, "Forge");

    // Sort versions by Minecraft version order (handles 1.7.10_pre4 rename + usize::MAX fallback)
    sort_by_minecraft_order(&mut final_versions, minecraft_versions);

    // Sort loaders within each version using metadata order
    for version in &mut final_versions {
        if let Some(loader_versions) = maven_metadata.get(&version.id) {
            sort_loaders_by_metadata(version, loader_versions);
        }
    }

    // Set the full Forge versions JSON in manifest_builder with nested structure
    // This preserves game version -> loader version mappings
    let versions_json = serde_json::to_value(&final_versions)?;
    manifest_builder.set_loader_versions("forge", versions_json);
    info!(
        version_count = final_versions.len(),
        "Set Forge versions with nested structure in CAS manifest builder"
    );

    Ok(())
}

const DEFAULT_MAVEN_METADATA_URL: &str = "https://files.minecraftforge.net/net/minecraftforge/forge/maven-metadata.json";

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

const PROMOTIONS_SLIM_URL: &str = "https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json";

#[derive(serde::Deserialize)]
struct PromotionsSlim {
    promos: HashMap<String, String>,
}

/// Fetches Forge's promotions_slim.json and returns the set of
/// "{mc}-{forge}" keys that the upstream marks as `recommended`.
///
/// The JSON keys are `<mc>-<latest|recommended>[-<branch>]` and the values are
/// short Forge versions. We mirror Prism's logic: only `-recommended` entries
/// without a branch suffix promote the build. Lookups must compare against
/// the same "{mc}-{forge}" shape — maven ids can additionally carry a branch
/// suffix that this set never contains.
pub async fn fetch_forge_promotions(
    semaphore: Arc<Semaphore>,
) -> Result<HashSet<String>, crate::infrastructure::error::Error> {
    let bytes = download_file(PROMOTIONS_SLIM_URL, None, semaphore).await?;
    let parsed: PromotionsSlim = serde_json::from_slice(&bytes)?;

    let mut recommended = HashSet::new();
    for (key, short_forge_version) in parsed.promos {
        // Key shape: <mc>-<promotion>[-<branch>]. We want exactly two segments
        // ending in "recommended" (skipping branch-specific promotions like
        // "1.20.1-recommended-lts").
        let Some((mc, suffix)) = key.rsplit_once('-') else {
            continue;
        };
        if suffix != "recommended" {
            continue;
        }
        recommended.insert(format!("{}-{}", mc, short_forge_version));
    }
    Ok(recommended)
}
