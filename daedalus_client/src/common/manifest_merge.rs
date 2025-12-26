//! Manifest version merging utilities
//!
//! This module provides common logic for merging old and new loader versions,
//! updating existing loaders, and sorting versions.

use daedalus::minecraft::VersionManifest;
use daedalus::modded::Version;
use tracing::info;

/// Merge old and new loader versions
///
/// This function:
/// 1. Starts with the old versions as a base
/// 2. For each new version:
///    - If the Minecraft version exists in old versions, merge loaders
///    - If the Minecraft version is new, add it
/// 3. When merging loaders:
///    - Update existing loaders if found
///    - Add new loaders if not found
///
/// # Arguments
///
/// * `old_versions` - Versions from the previous manifest
/// * `new_versions` - Newly generated versions
/// * `loader_name` - Name of the loader for logging (e.g., "Forge", "NeoForge")
///
/// # Returns
///
/// Merged versions with old and new combined
pub fn merge_loader_versions(
    mut old_versions: Vec<Version>,
    new_versions: Vec<Version>,
    loader_name: &str,
) -> Vec<Version> {
    for new_version in new_versions {
        // Find if this Minecraft version already exists
        if let Some(existing) = old_versions
            .iter_mut()
            .find(|v| v.id == new_version.id)
        {
            // Merge loaders: keep old loaders + add/update new ones
            for new_loader in new_version.loaders {
                if let Some(existing_loader) = existing
                    .loaders
                    .iter_mut()
                    .find(|l| l.id == new_loader.id)
                {
                    // Update existing loader
                    let loader_id = new_loader.id.clone();
                    *existing_loader = new_loader;
                    info!(
                        "✅ {} - Updated loader: {}/{}",
                        loader_name, existing.id, loader_id
                    );
                } else {
                    // Add new loader
                    info!(
                        "✅ {} - Added new loader: {}/{}",
                        loader_name, existing.id, new_loader.id
                    );
                    existing.loaders.push(new_loader);
                }
            }
        } else {
            // Add new Minecraft version
            info!(
                "✅ {} - Added new Minecraft version: {}",
                loader_name, new_version.id
            );
            old_versions.push(new_version);
        }
    }

    old_versions
}

/// Sort versions by Minecraft version order
///
/// Sorts the versions based on their position in the Minecraft version manifest.
/// Versions not found in the manifest are placed at the end.
///
/// # Arguments
///
/// * `versions` - Versions to sort (modified in place)
/// * `minecraft_manifest` - Minecraft version manifest for ordering reference
pub fn sort_by_minecraft_order(
    versions: &mut [Version],
    minecraft_manifest: &VersionManifest,
) {
    versions.sort_by(|x, y| {
        let x_pos = minecraft_manifest
            .versions
            .iter()
            .position(|z| {
                // Handle special case for 1.7.10_pre4 -> 1.7.10-pre4 transformation
                x.id.replace("1.7.10_pre4", "1.7.10-pre4") == z.id
            })
            .unwrap_or(usize::MAX);

        let y_pos = minecraft_manifest
            .versions
            .iter()
            .position(|z| {
                // Handle special case for 1.7.10_pre4 -> 1.7.10-pre4 transformation
                y.id.replace("1.7.10_pre4", "1.7.10-pre4") == z.id
            })
            .unwrap_or(usize::MAX);

        x_pos.cmp(&y_pos)
    });
}

/// Sort loaders within a version by their position in metadata
///
/// This is used to maintain a consistent order of loaders based on the original
/// maven metadata or other source ordering.
///
/// # Arguments
///
/// * `version` - Version containing loaders to sort (modified in place)
/// * `loader_order` - Ordered list of loader IDs from metadata
pub fn sort_loaders_by_metadata(version: &mut Version, loader_order: &[String]) {
    version.loaders.sort_by(|x, y| {
        let x_pos = loader_order
            .iter()
            .position(|z| &x.id == z)
            .unwrap_or(usize::MAX);

        let y_pos = loader_order
            .iter()
            .position(|z| &y.id == z)
            .unwrap_or(usize::MAX);

        x_pos.cmp(&y_pos)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use daedalus::modded::LoaderVersion;

    #[test]
    fn test_merge_adds_new_minecraft_version() {
        let old_versions = vec![];
        let new_versions = vec![Version {
            id: "1.20.1".to_string(),
            stable: true,
            loaders: vec![LoaderVersion {
                id: "forge-47.1.0".to_string(),
                url: "test_url".to_string(),
                stable: true,
            }],
        }];

        let merged = merge_loader_versions(old_versions, new_versions, "TestLoader");

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].id, "1.20.1");
        assert_eq!(merged[0].loaders.len(), 1);
    }

    #[test]
    fn test_merge_updates_existing_loader() {
        let old_versions = vec![Version {
            id: "1.20.1".to_string(),
            stable: true,
            loaders: vec![LoaderVersion {
                id: "forge-47.1.0".to_string(),
                url: "old_url".to_string(),
                stable: true,
            }],
        }];

        let new_versions = vec![Version {
            id: "1.20.1".to_string(),
            stable: true,
            loaders: vec![LoaderVersion {
                id: "forge-47.1.0".to_string(),
                url: "new_url".to_string(),
                stable: true,
            }],
        }];

        let merged = merge_loader_versions(old_versions, new_versions, "TestLoader");

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].loaders[0].url, "new_url");
    }

    #[test]
    fn test_merge_adds_new_loader_to_existing_version() {
        let old_versions = vec![Version {
            id: "1.20.1".to_string(),
            stable: true,
            loaders: vec![LoaderVersion {
                id: "forge-47.1.0".to_string(),
                url: "url1".to_string(),
                stable: true,
            }],
        }];

        let new_versions = vec![Version {
            id: "1.20.1".to_string(),
            stable: true,
            loaders: vec![LoaderVersion {
                id: "forge-47.2.0".to_string(),
                url: "url2".to_string(),
                stable: true,
            }],
        }];

        let merged = merge_loader_versions(old_versions, new_versions, "TestLoader");

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].loaders.len(), 2);
    }
}
