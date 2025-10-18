//! Type definitions for Forge loader processing

use crate::services::upload::BatchUploader;
use chrono::{DateTime, Utc};
use dashmap::DashSet;
use daedalus::minecraft::{Library, VersionType};
use daedalus::modded::{Processor, SidedDataEntry};
use daedalus::GradleSpecifier;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

/// Forge installer profile (v1 format) - install section
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ForgeInstallerProfileInstallDataV1 {
    pub mirror_list: String,
    pub target: String,
    /// Path to the Forge universal library
    pub file_path: String,
    pub logo: String,
    pub welcome: String,
    pub version: String,
    /// Maven coordinates of the Forge universal library
    pub path: String,
    pub profile_name: String,
    pub minecraft: String,
}

/// Forge installer profile (v1 format) - version info section
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ForgeInstallerProfileManifestV1 {
    pub id: String,
    pub libraries: Vec<Library>,
    pub main_class: Option<String>,
    pub minecraft_arguments: Option<String>,
    pub release_time: DateTime<Utc>,
    pub time: DateTime<Utc>,
    pub type_: VersionType,
    pub assets: Option<String>,
    pub inherits_from: Option<String>,
    pub jar: Option<String>,
}

/// Forge installer profile (v1 format)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ForgeInstallerProfileV1 {
    pub install: ForgeInstallerProfileInstallDataV1,
    pub version_info: ForgeInstallerProfileManifestV1,
}

/// Forge installer profile (v2+ format)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ForgeInstallerProfileV2 {
    pub profile: String,
    pub version: String,
    pub json: String,
    pub path: Option<String>,
    pub minecraft: String,
    pub data: HashMap<String, SidedDataEntry>,
    pub libraries: Vec<Library>,
    pub processors: Vec<Processor>,
}

/// Cache entry for Minecraft version libraries
#[derive(Clone)]
pub struct MinecraftVersionCacheEntry {
    pub id: String,
    pub libraries: HashSet<GradleSpecifier>,
}

/// LRU cache for Minecraft version library sets
#[derive(Clone)]
pub struct MinecraftVersionLibraryCache {
    pub versions: Vec<MinecraftVersionCacheEntry>,
    pub max_size: usize,
}

impl MinecraftVersionLibraryCache {
    pub fn new() -> Self {
        MinecraftVersionLibraryCache {
            versions: Vec::new(),
            max_size: 20,
        }
    }

    pub async fn load_minecraft_version_libs(
        &mut self,
        version_id: &str,
    ) -> Result<&HashSet<GradleSpecifier>, crate::infrastructure::error::Error> {
        let index = self.versions.iter().position(|ver| ver.id == version_id);

        if let Some(index) = index {
            // move found entry to the front of the stack
            let entry = self.versions.remove(index);
            self.versions.insert(0, entry);
        } else {
            let generated_version =
                super::fetch_generated_version_info(version_id).await?;

            let libraries: HashSet<GradleSpecifier> = generated_version
                .libraries
                .into_iter()
                .map(|lib| lib.name)
                .collect();
            self.versions.insert(
                0,
                MinecraftVersionCacheEntry {
                    id: version_id.to_string(),
                    libraries,
                },
            );
            // truncate to drop oldest entry
            self.versions.truncate(self.max_size);
        }

        let entry = self
            .versions
            .first()
            .expect("Valid first index as we just inserted it");
        Ok(&entry.libraries)
    }
}

/// Context shared across Forge processing operations
pub struct ForgeProcessingContext<'a> {
    pub uploader: &'a BatchUploader,
    pub s3_client: &'a s3::Bucket,
    pub semaphore: Arc<Semaphore>,
    pub visited_assets: Arc<DashSet<GradleSpecifier>>,
    pub mc_library_cache: Arc<Mutex<MinecraftVersionLibraryCache>>,
    pub old_versions: Arc<Mutex<Vec<daedalus::modded::Version>>>,
}
