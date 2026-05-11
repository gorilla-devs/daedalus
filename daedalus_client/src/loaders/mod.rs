pub mod fabric;
pub mod quilt;

use crate::{download_file, format_url};
use crate::common::cas::build_cas_url;
use crate::common::change_detection::detect_version_change;
use crate::services::upload::BatchUploader;
use dashmap::DashMap;
use daedalus::minecraft::{Library, VersionManifest};
use daedalus::modded::{LoaderVersion, PartialVersionInfo, Version};
use daedalus::{get_hash, BRANDING};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{info, warn};

/// Determines if a library is an intermediary/hashed mapping library
///
/// Intermediary libraries are the ONLY libraries that are truly game-version-specific
/// in Fabric/Quilt loaders. All other libraries (asm, mixin, loader itself) are
/// version-agnostic and should be downloaded once.
///
/// Examples:
/// - `net.fabricmc:intermediary:1.21` → true
/// - `org.quiltmc:hashed:1.20.4` → true
/// - `org.ow2.asm:asm:9.7.1` → false
/// - `net.fabricmc:fabric-loader:0.16.10` → false
fn is_intermediary_library(library_name: &str) -> bool {
    library_name.contains("intermediary") || library_name.contains("hashed")
}

/// Strategy trait for loader-specific behavior
pub trait LoaderStrategy: Send + Sync {
    fn name(&self) -> &str;
    fn meta_url(&self) -> &str;
    fn maven_fallback(&self) -> &str;
    fn manifest_path_prefix(&self) -> &str;
    fn is_stable(&self, loader: &dyn LoaderVersionInfo) -> bool;
}

pub trait LoaderVersionInfo: Send + Sync {
    fn version(&self) -> &str;
    fn stable(&self) -> Option<bool>;
}

pub trait GameVersionInfo: Send + Sync + Clone {
    fn version(&self) -> &str;
    fn stable(&self) -> bool;
}

pub trait LoaderVersionsList: Send + Sync {
    type Loader: LoaderVersionInfo;
    type Game: GameVersionInfo;

    fn loader(&self) -> &[Self::Loader];
    fn game(&self) -> &[Self::Game];
}

/// Generic processor for loaders using the strategy pattern
pub struct LoaderProcessor<S: LoaderStrategy> {
    strategy: S,
}

/// Caches shared across all loader versions of a single retrieve_data run.
///
/// - `regular_cas_urls`: maven coord (post-placeholder) → CAS URL of the unique artifact.
///   Lets duplicate non-intermediary libs across loader versions reuse the same CAS URL
///   without redownloading.
/// - `intermediary_hashes`: intermediary coord (with placeholder) → mc_version → CAS hash.
///   Same intermediary jar referenced by N loader versions only downloads once per MC.
struct LoaderCaches {
    regular_cas_urls: DashMap<String, String>,
    intermediary_hashes: DashMap<String, BTreeMap<String, String>>,
}

impl LoaderCaches {
    fn new() -> Self {
        Self {
            regular_cas_urls: DashMap::new(),
            intermediary_hashes: DashMap::new(),
        }
    }
}

impl<S: LoaderStrategy> LoaderProcessor<S> {
    pub fn new(strategy: S) -> Self {
        Self { strategy }
    }

    pub async fn retrieve_data<V>(
        &self,
        minecraft_versions: &VersionManifest,
        uploader: &BatchUploader,
        manifest_builder: &crate::services::cas::ManifestBuilder,
        s3_client: &s3::Bucket,
        semaphore: Arc<Semaphore>,
    ) -> Result<(), crate::infrastructure::error::Error>
    where
        V: LoaderVersionsList + for<'de> Deserialize<'de>,
    {
        info!("Retrieving {} data ...", self.strategy.name());

        // Wrap in Arc so per-loader-version futures can cheaply share a reference
        // without requiring V: Clone.
        let list: Arc<V> = Arc::new(self.fetch_versions_list(None, semaphore.clone()).await?);

        let old_manifest = daedalus::modded::fetch_manifest(&format_url(&format!(
            "{}/v{}/manifest.json",
            self.strategy.manifest_path_prefix(),
            crate::services::cas::CAS_VERSION,
        )))
        .await
        .ok();

        let mut versions = old_manifest
            .map(|m| m.game_versions)
            .unwrap_or_default();

        let dummy_replace_string = BRANDING
            .get()
            .expect("Branding must be set via Branding::set_branding before retrieve_data")
            .dummy_replace_string
            .clone();

        // Build the set of loader versions to process. For each loader API entry, look up
        // the previously-published LoaderVersion (if any). When found we can skip the
        // fetch/process round-trip entirely and just re-emit the existing entry.
        let mut to_skip: Vec<LoaderVersion> = Vec::new();
        let mut to_fetch: Vec<(bool, String)> = Vec::new();

        let dummy_entry = versions.iter().find(|x| x.id == dummy_replace_string);

        for loader in list.loader() {
            let stable = self.strategy.is_stable(loader as &dyn LoaderVersionInfo);
            let version_id = loader.version().to_string();

            let cached = dummy_entry
                .and_then(|x| x.loaders.iter().find(|l| l.id == version_id))
                .cloned();

            if let Some(mut existing) = cached {
                // Loader entries are immutable artifacts on the loader API side, so a known
                // loader version's processed JSON is still valid. Re-emit it without
                // refetching or re-uploading anything.
                existing.stable = stable;
                to_skip.push(existing);
            } else {
                to_fetch.push((stable, version_id));
            }
        }

        info!(
            "📊 {} - {} loader versions ({} cached, {} to fetch)",
            self.strategy.name(),
            to_skip.len() + to_fetch.len(),
            to_skip.len(),
            to_fetch.len(),
        );

        // Fetch new loader profiles in parallel (semaphore controls real concurrency).
        let fetch_futures = to_fetch.into_iter().map(|(stable, loader_version)| {
            let semaphore = semaphore.clone();
            async move {
                let result = self
                    .fetch_loader_version(DUMMY_GAME_VERSION, &loader_version, semaphore)
                    .await;
                (stable, loader_version, result)
            }
        });

        let mut fetched: Vec<(bool, String, PartialVersionInfo)> = Vec::new();
        let mut fetch_failed = 0;
        for (stable, loader, result) in futures::future::join_all(fetch_futures).await {
            match result {
                Ok(profile) => fetched.push((stable, loader, profile)),
                Err(e) => {
                    warn!(
                        "⚠️  {} - Failed to fetch loader version {}: {}",
                        self.strategy.name(),
                        loader,
                        e
                    );
                    fetch_failed += 1;
                }
            }
        }

        info!(
            "📊 {} - Fetched {} loader profiles ({} failed)",
            self.strategy.name(),
            fetched.len(),
            fetch_failed,
        );

        // Process fetched profiles in parallel.
        let caches = Arc::new(LoaderCaches::new());
        let process_futures = fetched.into_iter().map(|(stable, loader, profile)| {
            let semaphore = semaphore.clone();
            let caches = Arc::clone(&caches);
            let list = Arc::clone(&list);
            let dummy_replace_string = dummy_replace_string.clone();
            async move {
                let result = self
                    .process_loader_version(
                        stable,
                        loader.clone(),
                        profile,
                        list.as_ref(),
                        uploader,
                        s3_client,
                        &caches,
                        &dummy_replace_string,
                        semaphore,
                    )
                    .await;
                (loader, result)
            }
        });

        let mut processed: Vec<LoaderVersion> = to_skip;
        let mut process_failed = 0;
        for (loader, result) in futures::future::join_all(process_futures).await {
            match result {
                Ok(loader_version) => processed.push(loader_version),
                Err(e) => {
                    warn!(
                        "⚠️  {} - Failed to process loader {}: {}",
                        self.strategy.name(),
                        loader,
                        e
                    );
                    process_failed += 1;
                }
            }
        }

        info!(
            "📊 {} - Processing complete: {} successful, {} failed",
            self.strategy.name(),
            processed.len(),
            process_failed
        );

        // Add processed loaders to versions list under the dummy game version entry.
        if !processed.is_empty() {
            if let Some(version) = versions.iter_mut().find(|x| x.id == dummy_replace_string) {
                // Replace by id so cached entries are refreshed cleanly.
                let mut existing_by_id: BTreeMap<String, LoaderVersion> = std::mem::take(&mut version.loaders)
                    .into_iter()
                    .map(|l| (l.id.clone(), l))
                    .collect();
                for entry in processed {
                    existing_by_id.insert(entry.id.clone(), entry);
                }
                version.loaders = existing_by_id.into_values().collect();
            } else {
                versions.push(Version {
                    id: dummy_replace_string.clone(),
                    stable: true,
                    loaders: processed,
                });
            }
        }

        // Add game versions that don't have loaders yet
        for version in list.game() {
            if !versions.iter().any(|x| x.id == version.version()) {
                versions.push(Version {
                    id: version.version().to_string(),
                    stable: version.stable(),
                    loaders: vec![],
                });
            }
        }

        // Sort versions by Minecraft version order — unknown ids sort to the end.
        versions.sort_by(|x, y| {
            minecraft_versions
                .versions
                .iter()
                .position(|z| x.id == z.id)
                .unwrap_or(usize::MAX)
                .cmp(
                    &minecraft_versions
                        .versions
                        .iter()
                        .position(|z| y.id == z.id)
                        .unwrap_or(usize::MAX),
                )
        });

        // Sort loaders within each version by their position in the upstream API.
        for version in &mut versions {
            version.loaders.sort_by(|x, y| {
                let x_pos = list
                    .loader()
                    .iter()
                    .position(|z| x.id == *z.version())
                    .unwrap_or(usize::MAX);
                let y_pos = list
                    .loader()
                    .iter()
                    .position(|z| y.id == z.version())
                    .unwrap_or(usize::MAX);

                x_pos.cmp(&y_pos)
            })
        }

        let manifest = daedalus::modded::Manifest {
            game_versions: versions,
        };

        let versions_json = serde_json::to_value(&manifest.game_versions)?;
        manifest_builder.set_loader_versions(self.strategy.manifest_path_prefix(), versions_json);

        info!(
            "✅ {} - Processed {} game versions",
            self.strategy.name(),
            manifest.game_versions.len()
        );

        Ok(())
    }

    async fn fetch_versions_list<V>(
        &self,
        url: Option<&str>,
        semaphore: Arc<Semaphore>,
    ) -> Result<V, crate::infrastructure::error::Error>
    where
        V: for<'de> Deserialize<'de>,
    {
        Ok(serde_json::from_slice(
            &download_file(
                url.unwrap_or(&format!("{}/versions", self.strategy.meta_url())),
                None,
                semaphore,
            )
            .await?,
        )?)
    }

    async fn fetch_loader_version(
        &self,
        minecraft_version: &str,
        loader_version: &str,
        semaphore: Arc<Semaphore>,
    ) -> Result<PartialVersionInfo, crate::infrastructure::error::Error> {
        Ok(serde_json::from_slice(
            &download_file(
                &format!(
                    "{}/versions/loader/{}/{}/profile/json",
                    self.strategy.meta_url(),
                    minecraft_version,
                    loader_version
                ),
                None,
                semaphore,
            )
            .await?,
        )?)
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_loader_version<V>(
        &self,
        stable: bool,
        loader: String,
        version: PartialVersionInfo,
        list: &V,
        uploader: &BatchUploader,
        s3_client: &s3::Bucket,
        caches: &LoaderCaches,
        dummy_replace_string: &str,
        semaphore: Arc<Semaphore>,
    ) -> Result<LoaderVersion, crate::infrastructure::error::Error>
    where
        V: LoaderVersionsList,
    {
        // Process all libraries
        let libs = futures::future::try_join_all(version.libraries.into_iter().map(|mut lib| {
            let semaphore = semaphore.clone();
            let list_game: Vec<_> = list.game().to_vec();
            let maven_fallback = self.strategy.maven_fallback().to_string();

            async move {
                let original_name = lib.name.to_string();
                let has_placeholder = original_name.contains(DUMMY_GAME_VERSION);
                let coord_with_placeholder = original_name.replace(
                    DUMMY_GAME_VERSION,
                    dummy_replace_string,
                );

                if has_placeholder && is_intermediary_library(&coord_with_placeholder) {
                    // Intermediary path — variable artifact per MC version.
                    if let Some(cached) = caches.intermediary_hashes.get(&coord_with_placeholder) {
                        lib.name = coord_with_placeholder.parse()?;
                        lib.version_hashes = Some(cached.clone());
                        lib.url = None;
                        return Ok(lib);
                    }

                    let lib_url = lib.url.clone();
                    let version_hash_results = futures::future::try_join_all(list_game.iter().map(|game_version| {
                        let semaphore = semaphore.clone();
                        let lib_url = lib_url.clone();
                        let coord_with_placeholder = coord_with_placeholder.clone();
                        let maven_fallback = maven_fallback.clone();
                        let game_version_str = game_version.version().to_string();

                        async move {
                            let artifact_path = daedalus::get_path_from_artifact(
                                &coord_with_placeholder.replace(
                                    dummy_replace_string,
                                    &game_version_str,
                                ),
                            )?;

                            let artifact = download_file(
                                &format!(
                                    "{}{}",
                                    lib_url.as_deref().unwrap_or(&maven_fallback),
                                    artifact_path
                                ),
                                None,
                                semaphore.clone(),
                            )
                            .await?;

                            let hash = uploader.upload_cas(
                                artifact.to_vec(),
                                Some("application/java-archive".to_string()),
                                s3_client,
                                semaphore.clone(),
                            ).await?;

                            Ok::<(String, String), crate::infrastructure::error::Error>((game_version_str, hash))
                        }
                    }))
                    .await?;

                    let version_hashes: BTreeMap<String, String> = version_hash_results.into_iter().collect();
                    caches.intermediary_hashes.insert(coord_with_placeholder.clone(), version_hashes.clone());
                    lib.name = coord_with_placeholder.parse()?;
                    lib.version_hashes = Some(version_hashes);
                    lib.url = None;
                    return Ok(lib);
                }

                // Regular library path (with or without placeholder). The artifact is
                // version-agnostic, so the same CAS URL is reused across loader versions.
                if let Some(cached_url) = caches.regular_cas_urls.get(&coord_with_placeholder) {
                    lib.name = coord_with_placeholder.parse()?;
                    lib.url = Some(cached_url.clone());
                    return Ok(lib);
                }

                lib.name = coord_with_placeholder.parse()?;
                let artifact_path = lib.name.path();

                let artifact = download_file(
                    &format!(
                        "{}{}",
                        lib.url.as_deref().unwrap_or(&maven_fallback),
                        artifact_path
                    ),
                    None,
                    semaphore.clone(),
                )
                .await?;

                let hash = uploader.upload_cas(
                    artifact.to_vec(),
                    Some("application/java-archive".to_string()),
                    s3_client,
                    semaphore.clone(),
                ).await?;

                let cas_url = build_cas_url(&hash)?;
                caches.regular_cas_urls.insert(coord_with_placeholder, cas_url.clone());
                lib.url = Some(cas_url);

                Ok::<Library, crate::infrastructure::error::Error>(lib)
            }
        }))
        .await?;

        let version_info = PartialVersionInfo {
            arguments: version.arguments,
            id: version.id.replace(DUMMY_GAME_VERSION, dummy_replace_string),
            main_class: version.main_class,
            release_time: version.release_time,
            time: version.time,
            type_: version.type_,
            logging: None,
            inherits_from: version.inherits_from.replace(DUMMY_GAME_VERSION, dummy_replace_string),
            libraries: libs,
            minecraft_arguments: version.minecraft_arguments,
            processors: None,
            data: None,
        };

        let version_bytes = serde_json::to_vec(&version_info)?;
        let new_hash = get_hash(bytes::Bytes::from(version_bytes.clone())).await?;

        // Note: should_upload comparison against the OLD url is meaningless here
        // because the cached path (T2.5) skips all of this entirely. We always upload
        // newly fetched profiles.
        let _ = detect_version_change(self.strategy.name(), &loader, None, &new_hash);

        let version_hash = uploader.upload_cas(
            version_bytes,
            Some("application/json".to_string()),
            s3_client,
            semaphore.clone(),
        ).await?;

        let cas_url = build_cas_url(&version_hash)?;

        Ok(LoaderVersion {
            id: loader,
            url: cas_url,
            stable,
        })
    }
}

const DUMMY_GAME_VERSION: &str = "1.19.4-rc2";
