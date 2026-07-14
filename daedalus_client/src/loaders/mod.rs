pub mod fabric;
pub mod quilt;

use crate::common::cas::build_cas_url;
use crate::download_file;
use crate::services::upload::BatchUploader;
use daedalus::BRANDING;
use daedalus::minecraft::{Library, VersionManifest};
use daedalus::modded::{LoaderVersion, PartialVersionInfo, Version};
use dashmap::DashMap;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
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
    /// Whether to skip a specific loader version entirely (known-broken upstream artifact).
    /// Default: never skip.
    fn should_skip(&self, _loader_version: &str) -> bool {
        false
    }
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
    /// Game versions that have a published mapping artifact (fabric
    /// `intermediary`, quilt `hashed`). Only these are installable — the
    /// loader profile's mapping library resolves per game version, and a
    /// game version without a mapping has nothing to resolve to. The game
    /// list can run ahead of this one (Quilt's has for years).
    fn mapping_versions(&self) -> Vec<&str>;
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
/// - `intermediary_hashes`: intermediary coord (with placeholder) → async cell holding
///   the mc_version → CAS hash table. The cell guarantees the per-game-version mapping
///   sweep runs EXACTLY once per coordinate per cycle — every loader version referencing
///   the coordinate awaits the same expansion instead of each running its own (which
///   multiplied to loader_count × game_count downloads on cold cycles). A failed
///   expansion leaves the cell empty, so the next loader version retries it.
struct LoaderCaches {
    regular_cas_urls: DashMap<String, String>,
    intermediary_hashes:
        DashMap<String, Arc<tokio::sync::OnceCell<BTreeMap<String, String>>>>,
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
        let list: Arc<V> =
            Arc::new(self.fetch_versions_list(None, semaphore.clone()).await?);

        // Only game versions with a published mapping artifact are
        // installable. Intersecting with game[] keeps stray mapping entries
        // (mappings for ids the game list dropped) out of the expansion.
        let game_ids: HashSet<&str> =
            list.game().iter().map(|g| g.version()).collect();
        let mapped_game_versions: Arc<Vec<String>> = Arc::new(
            list.mapping_versions()
                .into_iter()
                .filter(|v| game_ids.contains(v))
                .map(str::to_string)
                .collect(),
        );
        info!(
            "📊 {} - {} game versions, {} with mappings (installable)",
            self.strategy.name(),
            list.game().len(),
            mapped_game_versions.len()
        );

        // Previous publish's game-version entries, resolved through the
        // previous root manifest — loader manifests live at timestamped keys
        // that only the root records.
        let old_versions: Option<Vec<Version>> =
            match crate::services::cas::fetch_previous_loader_versions(
                s3_client,
                self.strategy.manifest_path_prefix(),
            )
            .await
            {
                crate::services::cas::PreviousVersions::Loaded(v) => Some(v),
                crate::services::cas::PreviousVersions::Absent => None,
                crate::services::cas::PreviousVersions::Unreadable => {
                    return Err(crate::infrastructure::error::invalid_input(
                        format!(
                            "{}: previous manifest baseline is unreadable (transient \
                             S3 error or parse failure); aborting this cycle so \
                             carry-forward keeps the last-good manifest instead of \
                             rebuilding from an empty base",
                            self.strategy.name()
                        ),
                    ));
                }
            };

        // `old_manifest_was_present` is the cold-start signal for Discord
        // notifications: on a brand-new deploy (Absent) we suppress the
        // per-MC-version notifications that would otherwise fire once per
        // historical Minecraft version. An unreadable baseline is handled above
        // (the loader is aborted for the cycle), so this now only distinguishes
        // a genuine cold start from a successfully loaded baseline.
        let old_manifest_was_present = old_versions.is_some();
        let mut versions = old_versions.unwrap_or_default();

        let dummy_replace_string = BRANDING
            .get()
            .expect("Branding must be set via Branding::set_branding before retrieve_data")
            .dummy_replace_string
            .clone();

        // Cached loader entries embed the mapping table that existed when
        // they were first processed: re-emitting them after a NEW mapped game
        // version appeared would publish loader JSONs that can never resolve
        // the new Minecraft version. When the mapped set grew, bypass the
        // cache for one cycle so every loader version republishes with the
        // full table — the expansion is shared, so the refresh costs one
        // mapping sweep plus the profile fetches, not a per-version explosion.
        let known_ids: HashSet<&str> =
            versions.iter().map(|v| v.id.as_str()).collect();
        let has_new_mapped_version = mapped_game_versions
            .iter()
            .any(|v| !known_ids.contains(v.as_str()));
        drop(known_ids);
        if has_new_mapped_version && old_manifest_was_present {
            info!(
                "🔁 {} - New mapped game version(s) since the previous publish; refreshing all loader versions",
                self.strategy.name()
            );
        }

        // Build the set of loader versions to process. For each loader API entry, look up
        // the previously-published LoaderVersion (if any). When found we can skip the
        // fetch/process round-trip entirely and just re-emit the existing entry.
        let mut to_skip: Vec<LoaderVersion> = Vec::new();
        let mut to_fetch: Vec<(bool, String)> = Vec::new();

        let dummy_entry =
            versions.iter().find(|x| x.id == dummy_replace_string);

        let mut skipped = 0usize;
        for loader in list.loader() {
            let version_id = loader.version().to_string();

            if self.strategy.should_skip(&version_id) {
                info!(
                    "⏭️  {} - Skipping excluded loader version: {}",
                    self.strategy.name(),
                    version_id
                );
                skipped += 1;
                continue;
            }

            let stable =
                self.strategy.is_stable(loader as &dyn LoaderVersionInfo);

            let cached = if has_new_mapped_version {
                None
            } else {
                dummy_entry
                    .and_then(|x| x.loaders.iter().find(|l| l.id == version_id))
                    .cloned()
            };

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
        if skipped > 0 {
            info!(
                "⏭️  {} - Skipped {} known-broken loader version(s)",
                self.strategy.name(),
                skipped
            );
        }

        info!(
            "📊 {} - {} loader versions ({} cached, {} to fetch)",
            self.strategy.name(),
            to_skip.len() + to_fetch.len(),
            to_skip.len(),
            to_fetch.len(),
        );

        // Fetch new loader profiles in parallel (semaphore controls real concurrency).
        let fetch_futures =
            to_fetch.into_iter().map(|(stable, loader_version)| {
                let semaphore = semaphore.clone();
                async move {
                    let result = self
                        .fetch_loader_version(
                            DUMMY_GAME_VERSION,
                            &loader_version,
                            semaphore,
                        )
                        .await;
                    (stable, loader_version, result)
                }
            });

        let mut fetched: Vec<(bool, String, PartialVersionInfo)> = Vec::new();
        let mut fetch_failed = 0;
        for (stable, loader, result) in
            futures::future::join_all(fetch_futures).await
        {
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
        let process_futures =
            fetched.into_iter().map(|(stable, loader, profile)| {
                let semaphore = semaphore.clone();
                let caches = Arc::clone(&caches);
                let mapped_game_versions = Arc::clone(&mapped_game_versions);
                let dummy_replace_string = dummy_replace_string.clone();
                async move {
                    let result = self
                        .process_loader_version(
                            stable,
                            loader.clone(),
                            profile,
                            &mapped_game_versions,
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
        for (loader, result) in futures::future::join_all(process_futures).await
        {
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
            if let Some(version) =
                versions.iter_mut().find(|x| x.id == dummy_replace_string)
            {
                // Replace by id so cached entries are refreshed cleanly.
                let mut existing_by_id: BTreeMap<String, LoaderVersion> =
                    std::mem::take(&mut version.loaders)
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

        // Add game versions that don't have loaders yet, and emit a Discord
        // notification per new (loader, mc_version) pair — Fabric/Quilt use
        // a placeholder game version with `version_hashes` resolution at the
        // launcher, so the meaningful event is the MC id appearing in the API.
        // Only MAPPED game versions are listed: a version without a mapping
        // artifact cannot be installed, and publishing it would advertise
        // loader support that resolves to nothing.
        let mapped_set: HashSet<&str> =
            mapped_game_versions.iter().map(String::as_str).collect();

        // Game versions whose mapping artifact actually resolved this cycle. The
        // shared intermediary expansion above downloads one mapping jar per
        // mapped game version; a version whose jar the maven doesn't serve yet
        // (upstream lag, or a wrong-body 200) is omitted from the hash table.
        // Advertising such a version as installable would publish a loader whose
        // mapping library resolves to nothing, and the cache would then re-emit
        // it every cycle. So a NEW game version is only added below once its
        // mapping resolved; one left out is re-seen as "new" next cycle and
        // picked up automatically once its jar appears. This set is only
        // consulted for versions not already in the manifest, and new additions
        // only happen when a new mapped version appeared (which forces the full
        // expansion to run), so an empty set on a fully-cached cycle can never
        // drop an already-published version.
        let installable_game_versions: HashSet<String> = caches
            .intermediary_hashes
            .iter()
            .filter_map(|entry| entry.value().get().cloned())
            .flat_map(|map| map.into_keys())
            .collect();

        let notifier = crate::services::discord::notifier();
        for version in list.game() {
            if !mapped_set.contains(version.version()) {
                continue;
            }
            if !versions.iter().any(|x| x.id == version.version()) {
                // Only advertise a NEW game version once its mapping artifact
                // resolved this cycle (see installable_game_versions above).
                if !installable_game_versions.contains(version.version()) {
                    warn!(
                        loader = %self.strategy.name(),
                        game_version = %version.version(),
                        "New mapped game version has no resolved mapping artifact yet; not advertising it as installable this cycle"
                    );
                    continue;
                }
                if old_manifest_was_present {
                    if let Some(n) = notifier.as_ref() {
                        n.report_new_loader_support(
                            self.strategy.name(),
                            version.version(),
                            DUMMY_GAME_VERSION,
                        );
                    }
                }
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
        manifest_builder.set_loader_versions(
            self.strategy.manifest_path_prefix(),
            versions_json,
        );

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
                url.unwrap_or(&format!(
                    "{}/versions",
                    self.strategy.meta_url()
                )),
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
    async fn process_loader_version(
        &self,
        stable: bool,
        loader: String,
        version: PartialVersionInfo,
        mapped_game_versions: &Arc<Vec<String>>,
        uploader: &BatchUploader,
        s3_client: &s3::Bucket,
        caches: &LoaderCaches,
        dummy_replace_string: &str,
        semaphore: Arc<Semaphore>,
    ) -> Result<LoaderVersion, crate::infrastructure::error::Error> {
        // Process all libraries
        let libs = futures::future::try_join_all(
            version.libraries.into_iter().map(|mut lib| {
                let semaphore = semaphore.clone();
                let mapped_game_versions = Arc::clone(mapped_game_versions);
                let maven_fallback = self.strategy.maven_fallback().to_string();

                async move {
                    let original_name = lib.name.to_string();
                    let has_placeholder =
                        original_name.contains(DUMMY_GAME_VERSION);
                    let coord_with_placeholder = original_name
                        .replace(DUMMY_GAME_VERSION, dummy_replace_string);

                    if has_placeholder
                        && is_intermediary_library(&coord_with_placeholder)
                    {
                        // Intermediary path — one artifact per mapped MC
                        // version, identical for every loader version that
                        // references this coordinate. The cell runs the
                        // expansion exactly once per coordinate per cycle;
                        // concurrent loader versions await the same result.
                        let cell = caches
                            .intermediary_hashes
                            .entry(coord_with_placeholder.clone())
                            .or_default()
                            .clone();

                        let lib_url = lib.url.clone();
                        let version_hashes = cell
                            .get_or_try_init(|| async {
                                let results = futures::future::join_all(
                                    mapped_game_versions.iter().map(|game_version| {
                                        let semaphore = semaphore.clone();
                                        let lib_url = lib_url.clone();
                                        let coord_with_placeholder =
                                            coord_with_placeholder.clone();
                                        let maven_fallback = maven_fallback.clone();

                                        async move {
                                            let artifact_path =
                                                daedalus::get_path_from_artifact(
                                                    &coord_with_placeholder.replace(
                                                        dummy_replace_string,
                                                        game_version,
                                                    ),
                                                )?;

                                            let artifact = match download_file(
                                                &format!(
                                                    "{}{}",
                                                    lib_url
                                                        .as_deref()
                                                        .unwrap_or(&maven_fallback),
                                                    artifact_path
                                                ),
                                                None,
                                                semaphore.clone(),
                                            )
                                            .await
                                            {
                                                Ok(bytes) => bytes,
                                                // The meta lists a mapping the
                                                // maven doesn't serve: that game
                                                // version simply isn't
                                                // installable. Omit its hash
                                                // instead of failing every
                                                // loader version over it.
                                                Err(e) if e.is_not_found() => {
                                                    warn!(
                                                        coordinate = %coord_with_placeholder,
                                                        game_version = %game_version,
                                                        "Mapping artifact missing on the maven; omitting this game version"
                                                    );
                                                    return Ok(None);
                                                }
                                                Err(e) => return Err(e),
                                            };

                                            // The meta lists the mapping version but
                                            // not its jar hash, so a full checksum
                                            // isn't possible here. Reject an obvious
                                            // wrong-body 200 (soft-404 HTML page,
                                            // truncated proxy error) by requiring the
                                            // ZIP local-file magic — otherwise the bad
                                            // bytes become the CAS object baked into
                                            // version_hashes for every cached re-emit.
                                            if !artifact.starts_with(b"PK") {
                                                warn!(
                                                    coordinate = %coord_with_placeholder,
                                                    game_version = %game_version,
                                                    "Mapping artifact is not a ZIP (wrong-body 200?); omitting this game version"
                                                );
                                                return Ok(None);
                                            }

                                            let hash = uploader
                                                .upload_cas(
                                                    artifact.to_vec(),
                                                    Some(
                                                        "application/java-archive"
                                                            .to_string(),
                                                    ),
                                                    s3_client,
                                                    semaphore.clone(),
                                                )
                                                .await?;

                                            Ok::<
                                                Option<(String, String)>,
                                                crate::infrastructure::error::Error,
                                            >(Some((
                                                game_version.clone(),
                                                hash,
                                            )))
                                        }
                                    }),
                                )
                                .await;

                                // A transient failure anywhere fails the whole
                                // expansion (the cell stays empty and the next
                                // loader version retries it) — publishing a
                                // partial mapping table would permanently break
                                // the omitted game versions for every cached
                                // re-emit of these loader JSONs.
                                let mut map = BTreeMap::new();
                                for result in results {
                                    if let Some((game_version, hash)) = result? {
                                        map.insert(game_version, hash);
                                    }
                                }
                                Ok::<
                                    BTreeMap<String, String>,
                                    crate::infrastructure::error::Error,
                                >(map)
                            })
                            .await?
                            .clone();

                        lib.name = coord_with_placeholder.parse()?;
                        lib.version_hashes = Some(version_hashes);
                        lib.url = None;
                        // The meta's sha1/size describe the DUMMY game
                        // version's mapping jar; the resolved artifact differs
                        // per game version, so publishing them would fail
                        // checksum validation everywhere.
                        lib.sha1 = None;
                        lib.size = None;
                        return Ok(lib);
                    }

                    // Regular library path (with or without placeholder). The artifact is
                    // version-agnostic, so the same CAS URL is reused across loader versions.
                    if let Some(cached_url) =
                        caches.regular_cas_urls.get(&coord_with_placeholder)
                    {
                        lib.name = coord_with_placeholder.parse()?;
                        lib.url = Some(cached_url.clone());
                        return Ok(lib);
                    }

                    lib.name = coord_with_placeholder.parse()?;
                    let artifact_path = lib.name.path();

                    // Hardcode: net.minecraft:launchwrapper:1.12 ships on Mojang's maven,
                    // not Fabric's. Older Fabric loaders (1.13/1.14-era) reference it with
                    // a null url field; without this override we'd 404 on the Fabric maven
                    // fallback. Matches Modrinth daedalus's fabric.rs.
                    let coord = lib.name.to_string();
                    let mojang_libs_override =
                        if coord == "net.minecraft:launchwrapper:1.12" {
                            Some("https://libraries.minecraft.net/")
                        } else {
                            None
                        };

                    // Loader metas publish the artifact's sha1 alongside its
                    // url; verifying it keeps a maven's 200-with-wrong-body
                    // from being immortalised as the CAS object every loader
                    // version reuses.
                    let expected_sha1 = lib.sha1.clone();
                    let artifact = download_file(
                        &format!(
                            "{}{}",
                            mojang_libs_override
                                .or(lib.url.as_deref())
                                .unwrap_or(&maven_fallback),
                            artifact_path
                        ),
                        expected_sha1.as_deref(),
                        semaphore.clone(),
                    )
                    .await?;

                    let hash = uploader
                        .upload_cas(
                            artifact.to_vec(),
                            Some("application/java-archive".to_string()),
                            s3_client,
                            semaphore.clone(),
                        )
                        .await?;

                    let cas_url = build_cas_url(&hash)?;
                    caches
                        .regular_cas_urls
                        .insert(coord_with_placeholder, cas_url.clone());
                    lib.url = Some(cas_url);

                    Ok::<Library, crate::infrastructure::error::Error>(lib)
                }
            }),
        )
        .await?;

        let version_info = PartialVersionInfo {
            arguments: version.arguments,
            id: version.id.replace(DUMMY_GAME_VERSION, dummy_replace_string),
            main_class: version.main_class,
            release_time: version.release_time,
            time: version.time,
            type_: version.type_,
            logging: None,
            inherits_from: version
                .inherits_from
                .replace(DUMMY_GAME_VERSION, dummy_replace_string),
            libraries: libs,
            minecraft_arguments: version.minecraft_arguments,
            processors: None,
            data: None,
        };

        // Newly fetched profiles are always uploaded — the cached fast path
        // in retrieve_data already skips known loader versions entirely, so
        // by the time control reaches here the version is new (or being
        // refreshed on purpose) and upload_cas dedups identical bytes anyway.
        let version_bytes = serde_json::to_vec(&version_info)?;
        let version_hash = uploader
            .upload_cas(
                version_bytes,
                Some("application/json".to_string()),
                s3_client,
                semaphore.clone(),
            )
            .await?;

        let cas_url = build_cas_url(&version_hash)?;

        Ok(LoaderVersion {
            id: loader,
            url: cas_url,
            stable,
            // Fabric/Quilt loader profiles have no installer jar to hash.
            original_sha1: None,
        })
    }
}

const DUMMY_GAME_VERSION: &str = "1.19.4-rc2";
