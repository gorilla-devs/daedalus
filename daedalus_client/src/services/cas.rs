use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Current CAS (Content-Addressable Storage) version
///
/// This is the single version entrypoint for all metadata (minecraft, forge, fabric, quilt, neoforge).
/// Old versions had individual versioning per loader, but v3+ uses a unified version.
pub const CAS_VERSION: u32 = 3;

/// Content-Addressable Storage (CAS) system
///
/// This module implements a content-addressable storage architecture where:
/// - Files are stored by their SHA256 hash (immutable, deduplicated)
/// - Loader manifests are timestamped for version history
/// - A root manifest atomically points to the current versions
///
/// # Architecture
///
/// ```text
/// Root Manifest (root.json)
///   ├─> minecraft manifest (minecraft/<timestamp>.json)
///   ├─> forge manifest (forge/<timestamp>.json)
///   ├─> fabric manifest (fabric/<timestamp>.json)
///   ├─> quilt manifest (quilt/<timestamp>.json)
///   └─> neoforge manifest (neoforge/<timestamp>.json)
///
/// Each loader manifest contains:
///   ├─> version entries with content hashes
///   └─> references to objects/<hash>
/// ```
///
/// # Benefits
///
/// - **Atomic updates**: Single root manifest update makes all changes visible
/// - **Rollback**: Keep historical manifests, update root to point to previous version
/// - **Deduplication**: Same content = same hash = stored once
/// - **Immutability**: Content never changes, only manifest pointers
/// - **Version history**: Timestamped manifests enable auditing and rollback
///
/// Reference to a loader manifest with its location
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoaderReference {
    /// Timestamp of the loader manifest (ISO 8601 format)
    pub timestamp: String,
    /// Full path to the loader manifest
    pub url: String,
}

impl LoaderReference {
    /// Create a new loader reference
    pub fn new(loader: &str, timestamp: String) -> Self {
        let url = format!("v{}/manifests/{}/{}.json", CAS_VERSION, loader, timestamp);
        Self { timestamp, url }
    }
}

/// Root manifest that points to the current version of each loader manifest
///
/// This is the single source of truth for the current state of the metadata.
/// Updating this file atomically switches between versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootManifest {
    /// Schema version for future compatibility
    pub schema_version: u32,
    /// Timestamp when this root manifest was created
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    /// Map of loader name to its manifest reference
    /// Example: "minecraft" -> { timestamp: "2024-01-15T10-30-00Z", url: "v{CAS_VERSION}/manifests/minecraft/2024-01-15T10-30-00Z.json" }
    pub loaders: HashMap<String, LoaderReference>,
}

impl RootManifest {
    /// Create a new root manifest
    pub fn new(loaders: HashMap<String, LoaderReference>) -> Self {
        Self {
            schema_version: 1,
            created_at: Utc::now(),
            loaders,
        }
    }

    /// Create an empty root manifest
    #[cfg(test)]
    pub fn empty() -> Self {
        Self::new(HashMap::new())
    }

    /// Add or update a loader reference
    #[cfg(test)]
    pub fn add_loader(&mut self, loader: String, timestamp: String) {
        self.loaders.insert(
            loader.clone(),
            LoaderReference::new(&loader, timestamp),
        );
    }
}

/// Entry in a loader manifest that references content by hash
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoaderManifestEntry {
    /// The version ID (e.g., "1.20.4", "23w10a")
    pub id: String,
    /// SHA256 hash of the content (references objects/<hash>)
    pub hash: String,
    /// Size of the content in bytes
    pub size: u64,
    /// When this entry was last updated
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

/// Loader manifest containing all versions for a specific loader
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoaderManifest {
    /// Schema version for future compatibility
    pub schema_version: u32,
    /// Loader name (e.g., "minecraft", "forge")
    pub loader: String,
    /// Timestamp when this manifest was created (ISO 8601)
    pub timestamp: String,
    /// All version entries
    pub versions: Vec<LoaderManifestEntry>,
}

impl LoaderManifest {
    /// Create a new loader manifest
    pub fn new(loader: String, versions: Vec<LoaderManifestEntry>) -> Self {
        let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
        Self {
            schema_version: 1,
            loader,
            timestamp,
            versions,
        }
    }
}

/// Builder for tracking version entries and constructing loader manifests
///
/// This is used during metadata processing to collect version→hash mappings
/// for each loader. Once all versions are added, it can build LoaderManifest
/// structures for upload.
///
/// # Thread Safety
///
/// Uses DashMap for lock-free concurrent access, allowing multiple threads
/// to add versions simultaneously.
///
/// # Example
///
/// ```no_run
/// # use daedalus_client::services::cas::ManifestBuilder;
/// let builder = ManifestBuilder::new();
///
/// // Multiple threads can add versions concurrently
/// builder.add_version("minecraft", "1.20.4".to_string(), "abc123...".to_string(), 1024);
/// builder.add_version("forge", "49.0.3".to_string(), "def456...".to_string(), 2048);
///
/// // Build loader manifests
/// let minecraft_manifest = builder.build_loader_manifest("minecraft");
/// let forge_manifest = builder.build_loader_manifest("forge");
/// ```
pub struct ManifestBuilder {
    /// Map of loader name → (version_id → (hash, size))
    /// Using nested DashMap for concurrent access at both levels
    versions: DashMap<String, DashMap<String, (String, u64)>>,
}

impl ManifestBuilder {
    /// Create a new empty manifest builder
    pub fn new() -> Self {
        Self {
            versions: DashMap::new(),
        }
    }

    /// Add a version entry for a specific loader
    ///
    /// If the version already exists for this loader, it will be overwritten.
    /// This is idempotent and thread-safe.
    ///
    /// # Arguments
    ///
    /// * `loader` - Loader name (e.g., "minecraft", "forge")
    /// * `version_id` - Version identifier (e.g., "1.20.4", "49.0.3")
    /// * `hash` - SHA256 hash of the version's content
    /// * `size` - Size of the content in bytes
    #[instrument(skip(self))]
    pub fn add_version(&self, loader: &str, version_id: String, hash: String, size: u64) {
        // Get or create the version map for this loader
        let loader_map = self
            .versions
            .entry(loader.to_string())
            .or_default();

        // Add the version entry
        loader_map.insert(version_id, (hash, size));

        info!(loader = %loader, "Added version to manifest builder");
    }

    /// Build a loader manifest from the tracked versions
    ///
    /// Creates a LoaderManifest with all versions that were added for this loader.
    /// Returns None if no versions exist for this loader.
    ///
    /// # Arguments
    ///
    /// * `loader` - Loader name to build manifest for
    #[instrument(skip(self))]
    pub fn build_loader_manifest(&self, loader: &str) -> Option<LoaderManifest> {
        let loader_map = self.versions.get(loader)?;

        // Collect all version entries
        let mut entries: Vec<LoaderManifestEntry> = loader_map
            .iter()
            .map(|entry| {
                let (version_id, (hash, size)) = entry.pair();
                LoaderManifestEntry {
                    id: version_id.clone(),
                    hash: hash.clone(),
                    size: *size,
                    updated_at: Utc::now(),
                }
            })
            .collect();

        // Sort by version ID for deterministic ordering
        entries.sort_by(|a, b| a.id.cmp(&b.id));

        info!(
            loader = %loader,
            version_count = entries.len(),
            "Built loader manifest"
        );

        Some(LoaderManifest::new(loader.to_string(), entries))
    }

    /// Get list of all loaders that have versions
    ///
    /// Returns a sorted vector of loader names.
    pub fn get_loaders(&self) -> Vec<String> {
        let mut loaders: Vec<String> = self.versions.iter().map(|e| e.key().clone()).collect();
        loaders.sort();
        loaders
    }

    /// Get the number of versions for a specific loader
    ///
    /// Returns 0 if the loader doesn't exist.
    #[cfg(test)]
    pub fn version_count(&self, loader: &str) -> usize {
        self.versions
            .get(loader)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Get the total number of loaders
    #[cfg(test)]
    pub fn loader_count(&self) -> usize {
        self.versions.len()
    }
}

impl Default for ManifestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_manifest_creation() {
        let mut loaders = HashMap::new();
        loaders.insert(
            "minecraft".to_string(),
            LoaderReference::new("minecraft", "2024-01-15T10-30-00Z".to_string()),
        );
        loaders.insert(
            "forge".to_string(),
            LoaderReference::new("forge", "2024-01-15T10-31-00Z".to_string()),
        );

        let root = RootManifest::new(loaders.clone());

        assert_eq!(root.schema_version, 1);
        assert_eq!(root.loaders, loaders);
    }

    #[test]
    fn test_loader_reference_creation() {
        let reference = LoaderReference::new("minecraft", "2024-01-15T10-30-00Z".to_string());

        assert_eq!(reference.timestamp, "2024-01-15T10-30-00Z");
        assert_eq!(reference.url, format!("v{}/manifests/minecraft/2024-01-15T10-30-00Z.json", CAS_VERSION));
    }

    #[test]
    fn test_root_manifest_add_loader() {
        let mut root = RootManifest::empty();

        root.add_loader("minecraft".to_string(), "2024-01-15T10-30-00Z".to_string());

        assert_eq!(root.loaders.len(), 1);
        assert!(root.loaders.contains_key("minecraft"));

        let reference = &root.loaders["minecraft"];
        assert_eq!(reference.timestamp, "2024-01-15T10-30-00Z");
        assert_eq!(reference.url, format!("v{}/manifests/minecraft/2024-01-15T10-30-00Z.json", CAS_VERSION));
    }

    #[test]
    fn test_root_manifest_serialization() {
        let root = RootManifest::empty();
        let json = serde_json::to_string(&root).unwrap();
        let deserialized: RootManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(root.schema_version, deserialized.schema_version);
        assert_eq!(root.loaders, deserialized.loaders);
    }

    #[test]
    fn test_loader_manifest_entry() {
        let entry = LoaderManifestEntry {
            id: "1.20.4".to_string(),
            hash: "abc123".to_string(),
            size: 1024,
            updated_at: Utc::now(),
        };

        assert_eq!(entry.id, "1.20.4");
        assert_eq!(entry.hash, "abc123");
        assert_eq!(entry.size, 1024);
    }

    #[test]
    fn test_loader_manifest_creation() {
        let entries = vec![
            LoaderManifestEntry {
                id: "1.20.4".to_string(),
                hash: "abc123".to_string(),
                size: 1024,
                updated_at: Utc::now(),
            },
            LoaderManifestEntry {
                id: "1.20.3".to_string(),
                hash: "def456".to_string(),
                size: 2048,
                updated_at: Utc::now(),
            },
        ];

        let manifest = LoaderManifest::new("minecraft".to_string(), entries.clone());

        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.loader, "minecraft");
        assert_eq!(manifest.versions.len(), 2);
        assert_eq!(manifest.versions[0].id, "1.20.4");
    }

    #[test]
    fn test_loader_manifest_serialization() {
        let manifest = LoaderManifest::new("forge".to_string(), vec![]);
        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: LoaderManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(manifest.schema_version, deserialized.schema_version);
        assert_eq!(manifest.loader, deserialized.loader);
        assert_eq!(manifest.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_manifest_builder_creation() {
        let builder = ManifestBuilder::new();
        assert_eq!(builder.loader_count(), 0);
    }

    #[test]
    fn test_manifest_builder_add_version() {
        let builder = ManifestBuilder::new();

        builder.add_version("minecraft", "1.20.4".to_string(), "abc123".to_string(), 1024);

        assert_eq!(builder.loader_count(), 1);
        assert_eq!(builder.version_count("minecraft"), 1);
    }

    #[test]
    fn test_manifest_builder_multiple_loaders() {
        let builder = ManifestBuilder::new();

        builder.add_version("minecraft", "1.20.4".to_string(), "abc123".to_string(), 1024);
        builder.add_version("forge", "49.0.3".to_string(), "def456".to_string(), 2048);
        builder.add_version("fabric", "0.15.0".to_string(), "ghi789".to_string(), 512);

        assert_eq!(builder.loader_count(), 3);
        assert_eq!(builder.version_count("minecraft"), 1);
        assert_eq!(builder.version_count("forge"), 1);
        assert_eq!(builder.version_count("fabric"), 1);

        let loaders = builder.get_loaders();
        assert_eq!(loaders, vec!["fabric", "forge", "minecraft"]); // Sorted
    }

    #[test]
    fn test_manifest_builder_multiple_versions() {
        let builder = ManifestBuilder::new();

        builder.add_version("minecraft", "1.20.4".to_string(), "abc123".to_string(), 1024);
        builder.add_version("minecraft", "1.20.3".to_string(), "def456".to_string(), 2048);
        builder.add_version("minecraft", "1.20.2".to_string(), "ghi789".to_string(), 512);

        assert_eq!(builder.loader_count(), 1);
        assert_eq!(builder.version_count("minecraft"), 3);
    }

    #[test]
    fn test_manifest_builder_build_manifest() {
        let builder = ManifestBuilder::new();

        builder.add_version("minecraft", "1.20.4".to_string(), "abc123".to_string(), 1024);
        builder.add_version("minecraft", "1.20.3".to_string(), "def456".to_string(), 2048);

        let manifest = builder.build_loader_manifest("minecraft").unwrap();

        assert_eq!(manifest.loader, "minecraft");
        assert_eq!(manifest.versions.len(), 2);

        // Check versions are sorted by ID
        assert_eq!(manifest.versions[0].id, "1.20.3");
        assert_eq!(manifest.versions[1].id, "1.20.4");
    }

    #[test]
    fn test_manifest_builder_nonexistent_loader() {
        let builder = ManifestBuilder::new();

        builder.add_version("minecraft", "1.20.4".to_string(), "abc123".to_string(), 1024);

        assert!(builder.build_loader_manifest("forge").is_none());
        assert_eq!(builder.version_count("forge"), 0);
    }

    #[test]
    fn test_manifest_builder_overwrite_version() {
        let builder = ManifestBuilder::new();

        // Add same version twice with different hashes
        builder.add_version("minecraft", "1.20.4".to_string(), "abc123".to_string(), 1024);
        builder.add_version("minecraft", "1.20.4".to_string(), "def456".to_string(), 2048);

        assert_eq!(builder.version_count("minecraft"), 1); // Still 1, overwritten

        let manifest = builder.build_loader_manifest("minecraft").unwrap();
        assert_eq!(manifest.versions.len(), 1);
        assert_eq!(manifest.versions[0].hash, "def456"); // Latest hash
        assert_eq!(manifest.versions[0].size, 2048); // Latest size
    }
}
