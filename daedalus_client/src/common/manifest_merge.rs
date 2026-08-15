//! Manifest version merging utilities
//!
//! This module provides common logic for merging old and new loader versions,
//! updating existing loaders, and sorting versions.

use crate::services::discord;
use daedalus::minecraft::VersionManifest;
use daedalus::modded::Version;
use std::collections::HashSet;
use tracing::{info, warn};

/// Published loader builds that upstream no longer lists.
///
/// Nothing prunes them: the merge is deliberately additive so a truncated or
/// failed upstream response can never unpublish content, and instances pinned
/// to a build keep resolving it. The cost of that safety is that a build
/// withdrawn upstream is served forever with no signal, so report it and let a
/// human decide rather than letting it accumulate silently.
///
/// Reports one aggregated line per loader rather than one per build — the same
/// set is absent on every subsequent cycle, and a per-build line would bury the
/// signal it exists to provide.
///
/// An empty `upstream_ids` is treated as "unknown", not "everything was
/// delisted": a fetch that returned nothing must not look like mass withdrawal.
pub fn report_absent_upstream(
    published: &[Version],
    upstream_ids: &HashSet<String>,
    loader_name: &str,
) -> Vec<String> {
    if upstream_ids.is_empty() {
        return Vec::new();
    }

    let mut absent: Vec<String> = published
        .iter()
        .flat_map(|version| version.loaders.iter())
        .map(|loader| loader.id.clone())
        .filter(|id| !upstream_ids.contains(id))
        .collect();
    absent.sort();
    absent.dedup();

    if !absent.is_empty() {
        let sample = absent
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            loader = %loader_name,
            count = absent.len(),
            sample = %sample,
            "Published builds are no longer listed upstream; they stay published \
             because the merge is additive, so remove them deliberately if they \
             should go"
        );
    }

    absent
}

/// Merge newly generated loader versions onto the previous manifest.
///
/// The previous versions are the base. Each new version is merged in by its
/// Minecraft version: a loader already present for that version is updated and
/// one that isn't is added, and a Minecraft version not in the base is added
/// wholesale.
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
    let old_is_empty = old_versions.is_empty();
    let notifier = discord::notifier();

    for new_version in new_versions {
        // Find if this Minecraft version already exists
        if let Some(existing) =
            old_versions.iter_mut().find(|v| v.id == new_version.id)
        {
            // Merge loaders: keep old loaders + add/update new ones
            let mc_version_id = existing.id.clone();
            // "First-time support" only makes sense if this MC version had at
            // least one loader before; otherwise it's effectively a new-MC-version
            // event, which we handle in the other branch.
            let had_any_loader_before = !existing.loaders.is_empty();
            for new_loader in new_version.loaders {
                if let Some(existing_loader) =
                    existing.loaders.iter_mut().find(|l| l.id == new_loader.id)
                {
                    // Update existing loader
                    let loader_id = new_loader.id.clone();
                    *existing_loader = new_loader;
                    info!(
                        "{} - Updated loader: {}/{}",
                        loader_name, existing.id, loader_id
                    );
                } else {
                    // Add new loader
                    info!(
                        "{} - Added new loader: {}/{}",
                        loader_name, existing.id, new_loader.id
                    );
                    // Notify Discord about the first build for an existing
                    // MC version. Skip on a cold start (old_versions empty)
                    // because every entry would fire a notification.
                    if !old_is_empty && !had_any_loader_before {
                        if let Some(n) = notifier.as_ref() {
                            n.report_new_loader_support(
                                loader_name,
                                &mc_version_id,
                                &new_loader.id,
                            );
                        }
                    }
                    existing.loaders.push(new_loader);
                }
            }
        } else {
            // Add new Minecraft version
            info!(
                "{} - Added new Minecraft version: {}",
                loader_name, new_version.id
            );
            // First time we're seeing this MC version for this loader. Skip
            // on cold start so we don't fire a flood of notifications for
            // every historical version on first deploy.
            if !old_is_empty {
                if let (Some(n), Some(first_loader)) =
                    (notifier.as_ref(), new_version.loaders.first())
                {
                    n.report_new_loader_support(
                        loader_name,
                        &new_version.id,
                        &first_loader.id,
                    );
                }
            }
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
pub fn sort_loaders_by_metadata(
    version: &mut Version,
    loader_order: &[String],
) {
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

    fn published(builds: &[&str]) -> Vec<Version> {
        vec![Version {
            id: "1.21".to_string(),
            stable: true,
            loaders: builds
                .iter()
                .map(|id| LoaderVersion {
                    id: id.to_string(),
                    url: format!("https://example.com/{id}.json"),
                    stable: true,
                    original_sha1: None,
                })
                .collect(),
        }]
    }

    fn upstream(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_build_upstream_dropped_is_reported() {
        let absent = report_absent_upstream(
            &published(&["0.17.5-beta.4", "0.17.5-beta.6"]),
            &upstream(&["0.17.5-beta.6", "0.17.6"]),
            "quilt",
        );

        assert_eq!(absent, vec!["0.17.5-beta.4".to_string()]);
    }

    #[test]
    fn an_empty_upstream_list_reports_nothing() {
        // A fetch that came back empty means "unknown", not "everything was
        // withdrawn". Reporting here would flag the entire manifest every time
        // upstream had a bad minute.
        let absent = report_absent_upstream(
            &published(&["0.17.5-beta.4", "0.17.5-beta.6"]),
            &upstream(&[]),
            "quilt",
        );

        assert!(absent.is_empty());
    }

    #[test]
    fn nothing_is_reported_when_upstream_still_lists_everything() {
        let absent = report_absent_upstream(
            &published(&["0.17.6"]),
            &upstream(&["0.17.6", "0.17.7"]),
            "quilt",
        );

        assert!(absent.is_empty());
    }

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
                original_sha1: None,
            }],
        }];

        let merged =
            merge_loader_versions(old_versions, new_versions, "TestLoader");

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
                original_sha1: None,
            }],
        }];

        let new_versions = vec![Version {
            id: "1.20.1".to_string(),
            stable: true,
            loaders: vec![LoaderVersion {
                id: "forge-47.1.0".to_string(),
                url: "new_url".to_string(),
                stable: true,
                original_sha1: None,
            }],
        }];

        let merged =
            merge_loader_versions(old_versions, new_versions, "TestLoader");

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
                original_sha1: None,
            }],
        }];

        let new_versions = vec![Version {
            id: "1.20.1".to_string(),
            stable: true,
            loaders: vec![LoaderVersion {
                id: "forge-47.2.0".to_string(),
                url: "url2".to_string(),
                stable: true,
                original_sha1: None,
            }],
        }];

        let merged =
            merge_loader_versions(old_versions, new_versions, "TestLoader");

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].loaders.len(), 2);
    }
}
