pub mod fabric;
pub mod quilt;

use crate::{download_file, format_url};
use crate::services::upload::BatchUploader;
use dashmap::DashSet;
use daedalus::minecraft::{Library, VersionManifest};
use daedalus::modded::{LoaderVersion, PartialVersionInfo, Version};
use daedalus::{get_hash, Branding, BRANDING};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{info, warn};

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
///
/// This trait abstracts the differences between loaders like Fabric and Quilt,
/// which have nearly identical processing logic but differ in URLs, API details,
/// and stability determination.
pub trait LoaderStrategy: Send + Sync {
    /// Loader name for logging (e.g., "Fabric", "Quilt")
    fn name(&self) -> &str;

    /// Base URL for loader metadata API
    fn meta_url(&self) -> &str;

    /// Maven repository fallback URL
    fn maven_fallback(&self) -> &str;

    /// Path prefix for storage (e.g., "fabric", "quilt")
    fn manifest_path_prefix(&self) -> &str;

    /// Determine if a loader version is stable
    ///
    /// Different loaders have different ways of determining stability:
    /// - Fabric includes a `stable` field in the API response
    /// - Quilt does not, so we default to false
    fn is_stable(&self, loader: &dyn LoaderVersionInfo) -> bool;
}

/// Common interface for loader version information
///
/// Both Fabric and Quilt have similar structures but with different field availability.
/// This trait allows the generic processor to work with both.
pub trait LoaderVersionInfo: Send + Sync {
    fn version(&self) -> &str;
    fn stable(&self) -> Option<bool>;
}

/// Common interface for game version information
pub trait GameVersionInfo: Send + Sync + Clone {
    fn version(&self) -> &str;
    fn stable(&self) -> bool;
}

/// Common interface for loader versions list
pub trait LoaderVersionsList: Send + Sync {
    type Loader: LoaderVersionInfo;
    type Game: GameVersionInfo;

    fn loader(&self) -> &[Self::Loader];
    fn game(&self) -> &[Self::Game];
}

/// Generic processor for loaders using the strategy pattern
///
/// This processor handles the common logic for fetching, processing, and uploading
/// loader data. Loader-specific behavior is delegated to the LoaderStrategy trait.
pub struct LoaderProcessor<S: LoaderStrategy> {
    strategy: S,
}

impl<S: LoaderStrategy> LoaderProcessor<S> {
    pub fn new(strategy: S) -> Self {
        Self { strategy }
    }

    /// Main entry point for retrieving and processing loader data
    ///
    /// This is the generic implementation of what was previously duplicated
    /// in fabric.rs and quilt.rs.
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

        // Fetch list of available versions from the loader API
        let list: V = self.fetch_versions_list(None, semaphore.clone()).await?;

        // Try to load existing manifest to do incremental updates
        let old_manifest = daedalus::modded::fetch_manifest(&format_url(&format!(
            "{}/v{}/manifest.json",
            self.strategy.manifest_path_prefix(),
            crate::services::cas::CAS_VERSION,
        )))
        .await
        .ok();

        let mut versions = if let Some(old_manifest) = old_manifest {
            old_manifest.game_versions
        } else {
            Vec::new()
        };

        // Prepare list of loaders to process
        // Format: (stable, version, old_version_opt)
        let loaders_mutex = RwLock::new(Vec::new());

        {
            let mut loaders = loaders_mutex.write().await;
            for loader in list.loader() {
                // Find old version if it exists in the dummy version
                let old_loader_version = versions
                    .iter()
                    .find(|x| {
                        x.id == BRANDING
                            .get_or_init(Branding::default)
                            .dummy_replace_string
                    })
                    .and_then(|x| x.loaders.iter().find(|l| l.id == loader.version()))
                    .cloned();

                loaders.push((
                    Box::new(self.strategy.is_stable(loader as &dyn LoaderVersionInfo)),
                    loader.version().to_string(),
                    old_loader_version,
                ))
            }
        }

        const DUMMY_GAME_VERSION: &str = "1.19.4-rc2";

        let loader_version_mutex = Mutex::new(Vec::new());

        // Fetch loader versions with individual error handling
        let mut loader_versions = Vec::new();
        let mut fetch_successful = 0;
        let mut fetch_failed = 0;

        for (stable, loader, old_loader_version) in loaders_mutex.read().await.clone() {
            match self
                .fetch_loader_version(DUMMY_GAME_VERSION, &loader, semaphore.clone())
                .await
            {
                Ok(version) => {
                    loader_versions.push((stable, loader, version, old_loader_version));
                    fetch_successful += 1;
                }
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
            "📊 {} - Fetched {} loader versions ({} successful, {} failed)",
            self.strategy.name(),
            fetch_successful + fetch_failed,
            fetch_successful,
            fetch_failed
        );

        let visited_artifacts = Arc::new(DashSet::new());

        // Process loader versions with individual error handling
        let mut process_successful = 0;
        let mut process_failed = 0;

        for (stable, loader, version, old_loader_version) in loader_versions {
            let loader_clone = loader.clone();
            let process_result = self
                .process_loader_version(
                    stable,
                    loader,
                    version,
                    old_loader_version,
                    &list,
                    &loader_version_mutex,
                    uploader,
                    manifest_builder,
                    s3_client,
                    &visited_artifacts,
                    semaphore.clone(),
                )
                .await;

            match process_result {
                Ok(_) => {
                    process_successful += 1;
                }
                Err(e) => {
                    warn!(
                        "⚠️  {} - Failed to process loader {}: {}",
                        self.strategy.name(),
                        loader_clone,
                        e
                    );
                    process_failed += 1;
                }
            }
        }

        info!(
            "📊 {} - Processing complete: {} successful, {} failed",
            self.strategy.name(),
            process_successful,
            process_failed
        );

        // Add processed loaders to versions list
        let mut loader_version_mutex = loader_version_mutex.into_inner();
        if !loader_version_mutex.is_empty() {
            if let Some(version) = versions.iter_mut().find(|x| {
                x.id == BRANDING.get_or_init(Branding::default).dummy_replace_string
            }) {
                version.loaders.append(&mut loader_version_mutex);
            } else {
                versions.push(Version {
                    id: BRANDING
                        .get_or_init(Branding::default)
                        .dummy_replace_string
                        .clone(),
                    stable: true,
                    loaders: loader_version_mutex,
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

        // Sort versions by Minecraft version order
        versions.sort_by(|x, y| {
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
        for version in &mut versions {
            version.loaders.sort_by(|x, y| {
                let x_pos = list
                    .loader()
                    .iter()
                    .position(|z| x.id == *z.version())
                    .unwrap_or_default();
                let y_pos = list
                    .loader()
                    .iter()
                    .position(|z| y.id == z.version())
                    .unwrap_or_default();

                x_pos.cmp(&y_pos)
            })
        }

        // Build the complete manifest and store it in ManifestBuilder
        // Fabric/Quilt use daedalus::modded::Manifest format (game_versions array)
        // which doesn't include release_time unlike LoaderManifestEntry
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

    /// Fetch the list of available versions from the loader API
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

    /// Fetch a specific loader version profile
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

    /// Process a single loader version
    #[allow(clippy::too_many_arguments)]
    async fn process_loader_version<V>(
        &self,
        stable: Box<bool>,
        loader: String,
        version: PartialVersionInfo,
        old_loader_version: Option<LoaderVersion>,
        list: &V,
        loader_version_mutex: &Mutex<Vec<LoaderVersion>>,
        uploader: &BatchUploader,
        manifest_builder: &crate::services::cas::ManifestBuilder,
        s3_client: &s3::Bucket,
        visited_artifacts: &Arc<DashSet<String>>,
        semaphore: Arc<Semaphore>,
    ) -> Result<(), crate::infrastructure::error::Error>
    where
        V: LoaderVersionsList,
    {
        const DUMMY_GAME_VERSION: &str = "1.19.4-rc2";

        // Process all libraries
        let libs = futures::future::try_join_all(version.libraries.into_iter().map(|mut lib| {
            let semaphore = semaphore.clone();
            let visited_artifacts = visited_artifacts.clone();
            let list_game = list.game().to_vec();
            let maven_fallback = self.strategy.maven_fallback().to_string();

            async move {
                // Check if we've already processed this artifact (lock-free)
                if !visited_artifacts.insert(lib.name.to_string()) {
                    // Already processed, skip download but still update name
                    lib.name = lib
                        .name
                        .to_string()
                        .replace(
                            DUMMY_GAME_VERSION,
                            &BRANDING.get_or_init(Branding::default).dummy_replace_string,
                        )
                        .parse()?;

                    // Note: url and version_hashes remain as-is from the original library entry
                    // This path should only be hit if the library is referenced multiple times,
                    // which means url/version_hashes were already set correctly the first time

                    return Ok(lib);
                }

                let name = lib.name.to_string();
                if name.contains(DUMMY_GAME_VERSION) {
                    // Replace dummy game version with placeholder
                    lib.name = name
                        .replace(
                            DUMMY_GAME_VERSION,
                            &BRANDING.get_or_init(Branding::default).dummy_replace_string,
                        )
                        .parse()?;

                    // Check if this is an intermediary library
                    // Only intermediary libraries are truly game-version-specific and need version_hashes
                    if is_intermediary_library(&lib.name.to_string()) {
                        // Intermediary library: Download for all game versions and create version_hashes map
                        let version_hash_results = futures::future::try_join_all(list_game.iter().map(|game_version| {
                            let semaphore = semaphore.clone();
                            let lib_name = lib.name.to_string();
                            let lib_url = lib.url.clone();
                            let maven_fallback = maven_fallback.clone();
                            let game_version_str = game_version.version().to_string();

                            async move {
                                let artifact_path = daedalus::get_path_from_artifact(
                                    &lib_name.replace(
                                        &BRANDING.get_or_init(Branding::default).dummy_replace_string,
                                        &game_version_str,
                                    ),
                                )?;

                                let artifact = download_file(
                                    &format!(
                                        "{}{}",
                                        lib_url.as_deref()
                                            .unwrap_or(&maven_fallback),
                                        artifact_path
                                    ),
                                    None,
                                    semaphore.clone(),
                                )
                                .await?;

                                // Upload to CAS and get hash
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

                        // Build version_hashes map from results
                        let version_hashes: HashMap<String, String> = version_hash_results.into_iter().collect();
                        lib.version_hashes = Some(version_hashes);
                        lib.url = None;
                    } else {
                        // Regular library with placeholder: Download ONCE and use single URL
                        // The dummy game version was only used to fetch the manifest, but this library
                        // itself is version-agnostic (e.g., org.ow2.asm:asm, fabric-loader, etc.)
                        let artifact_path = lib.name.path();

                        let artifact = download_file(
                            &format!(
                                "{}{}",
                                lib.url.as_deref()
                                    .unwrap_or(&maven_fallback),
                                artifact_path
                            ),
                            None,
                            semaphore.clone(),
                        )
                        .await?;

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
                    }

                    return Ok(lib);
                }

                // Regular library, download once
                let artifact_path = lib.name.path();

                let artifact = download_file(
                    &format!(
                        "{}{}",
                        lib.url.as_deref()
                            .unwrap_or(&maven_fallback),
                        artifact_path
                    ),
                    None,
                    semaphore.clone(),
                )
                .await?;

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

                Ok::<Library, crate::infrastructure::error::Error>(lib)
            }
        }))
        .await?;

        // Prepare version info with replaced dummy game version
        let version_info = PartialVersionInfo {
            arguments: version.arguments,
            id: version.id.replace(
                DUMMY_GAME_VERSION,
                &BRANDING.get_or_init(Branding::default).dummy_replace_string,
            ),
            main_class: version.main_class,
            release_time: version.release_time,
            time: version.time,
            type_: version.type_,
            logging: None,
            inherits_from: version.inherits_from.replace(
                DUMMY_GAME_VERSION,
                &BRANDING.get_or_init(Branding::default).dummy_replace_string,
            ),
            libraries: libs,
            minecraft_arguments: version.minecraft_arguments,
            processors: None,
            data: None,
        };

        let version_bytes = serde_json::to_vec(&version_info)?;
        let new_hash = get_hash(bytes::Bytes::from(version_bytes.clone())).await?;

        let should_upload = if let Some(old_version) = &old_loader_version {
            if let Some(old_hash) = extract_hash_from_cas_url(&old_version.url) {
                if old_hash == new_hash {
                    info!("✓ {} {} unchanged (hash: {})", self.strategy.name(), loader, &new_hash[..8]);
                    false
                } else {
                    info!("↻ {} {} changed (old: {}, new: {})", self.strategy.name(), loader, &old_hash[..8], &new_hash[..8]);
                    true
                }
            } else {
                true
            }
        } else {
            info!("+ {} {} is new", self.strategy.name(), loader);
            true
        };

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

        // Store the CAS URL for this loader version
        // Note: We don't call manifest_builder.add_version() here because Fabric/Quilt
        // use a custom manifest format (daedalus::modded::Manifest) that doesn't include
        // release_time. The manifest will be built at the end of retrieve_data() using
        // manifest_builder.set_loader_versions().
        let base_url = dotenvy::var("BASE_URL").unwrap();
        let cas_url = format!(
            "{}/v{}/objects/{}/{}",
            base_url,
            crate::services::cas::CAS_VERSION,
            &version_hash[..2],
            &version_hash[2..]
        );

        let mut loader_version_map = loader_version_mutex.lock().await;
        loader_version_map.push(LoaderVersion {
            id: loader,
            url: cas_url,
            stable: *stable,
        });

        Ok(())
    }
}
