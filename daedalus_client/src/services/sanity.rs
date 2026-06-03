//! Sanity gates: minimum-content checks before any loader manifest upload.
//!
//! All functions in this module are pure (no I/O), making them trivially unit-testable.
//! The caller is responsible for fetching and passing the manifests.

use crate::services::cas::LoaderManifest;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Describes which invariant was violated.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SanityViolation {
    /// Version count dropped below 90% of the previous count.
    VersionCountDrop {
        loader: String,
        previous: usize,
        current: usize,
        minimum: usize,
    },
    /// For MC-pinned loaders: less than 90% of the same Minecraft IDs are covered.
    MinecraftCoverageDrop {
        loader: String,
        previous_mc_ids: usize,
        covered: usize,
        minimum: usize,
    },
    /// The latest release in the new Minecraft manifest is older than in the previous one.
    MinecraftLatestReleaseRegressed {
        previous_latest: String,
        new_latest: String,
    },
}

impl std::fmt::Display for SanityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SanityViolation::VersionCountDrop {
                loader,
                previous,
                current,
                minimum,
            } => write!(
                f,
                "sanity gate: {loader} version count dropped from {previous} to {current} \
                 (minimum {minimum}, i.e. 90% of previous)"
            ),
            SanityViolation::MinecraftCoverageDrop {
                loader,
                previous_mc_ids,
                covered,
                minimum,
            } => write!(
                f,
                "sanity gate: {loader} covers {covered}/{previous_mc_ids} previous Minecraft IDs \
                 (minimum {minimum}, i.e. 90%)"
            ),
            SanityViolation::MinecraftLatestReleaseRegressed {
                previous_latest,
                new_latest,
            } => write!(
                f,
                "sanity gate: minecraft latest release regressed from {previous_latest} to \
                 {new_latest}"
            ),
        }
    }
}

/// Check the health of a loader manifest against its predecessor.
///
/// Invariants enforced:
/// 1. `new.versions.len() >= floor(previous.versions.len() * 0.9)`.
/// 2. For loaders that embed Minecraft version IDs (Forge / Fabric / Quilt / NeoForge):
///    the new manifest must cover ≥ 90% of the MC IDs the previous manifest covered.
/// 3. For `loader == "minecraft"`: the latest release in the new manifest must be
///    ≥ (i.e. not older than) the latest release in the previous manifest.
///
/// Returns `Ok(())` if all invariants pass.
/// Returns `Err(SanityViolation)` on the first failed invariant.
///
/// If `previous` is `None` (first deploy) all checks are skipped.
pub fn check_loader_health(
    loader: &str,
    new: &LoaderManifest,
    previous: Option<&LoaderManifest>,
) -> Result<(), SanityViolation> {
    let Some(prev) = previous else {
        return Ok(());
    };

    let new_count = version_count(&new.versions);
    let prev_count = version_count(&prev.versions);

    // Invariant 1: version count ≥ 90% of previous.
    if prev_count > 0 {
        // `.max(1)` closes the low-end hole: floor(0.9 * 1) == 0, which would
        // otherwise let a 1-version loader silently collapse to zero versions.
        let minimum = floor_90_percent(prev_count).max(1);
        if new_count < minimum {
            return Err(SanityViolation::VersionCountDrop {
                loader: loader.to_string(),
                previous: prev_count,
                current: new_count,
                minimum,
            });
        }
    }

    // Invariant 2: Minecraft ID coverage for non-minecraft loaders.
    if loader != "minecraft" {
        let prev_mc_ids = extract_mc_ids(&prev.versions);
        let new_mc_ids = extract_mc_ids(&new.versions);

        if !prev_mc_ids.is_empty() {
            let covered = prev_mc_ids
                .iter()
                .filter(|id| new_mc_ids.contains(*id))
                .count();
            let minimum = floor_90_percent(prev_mc_ids.len());
            if covered < minimum {
                return Err(SanityViolation::MinecraftCoverageDrop {
                    loader: loader.to_string(),
                    previous_mc_ids: prev_mc_ids.len(),
                    covered,
                    minimum,
                });
            }
        }
    }

    // Invariant 3: Minecraft latest release must not regress.
    if loader == "minecraft" {
        if let (Some(prev_latest), Some(new_latest)) = (
            latest_release_time(&prev.versions),
            latest_release_time(&new.versions),
        ) {
            if new_latest < prev_latest {
                return Err(SanityViolation::MinecraftLatestReleaseRegressed {
                    previous_latest: prev_latest.to_rfc3339(),
                    new_latest: new_latest.to_rfc3339(),
                });
            }
        }
    }

    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Count versions in a LoaderManifest's `versions` Value.
/// Works for both the simple `[{id,...}]` array and minecraft's richer objects.
fn version_count(versions: &Value) -> usize {
    match versions {
        Value::Array(arr) => arr.len(),
        _ => 0,
    }
}

/// floor(n * 0.9)
fn floor_90_percent(n: usize) -> usize {
    (n as f64 * 0.9).floor() as usize
}

/// Extract the set of Minecraft version IDs from a non-minecraft loader manifest.
///
/// These loaders embed the MC version either as:
/// - Fabric/Quilt: objects with a `"gameVersions"` array of strings, OR
///   objects with a `"gameVersion"` string field.
/// - Forge/NeoForge: simple entries with an `"id"` like `"1.20.1-47.3.0"` —
///   we extract the prefix before the first `-`.
/// - Any top-level array where each element has a `"gameVersion"` string field.
///
/// We try all known patterns and union the results. If we find nothing that
/// looks like MC IDs (e.g. a simple `[{id, hash, size}]` array), we return an
/// empty set so the caller skips the MC-coverage check rather than raising a
/// false positive.
fn extract_mc_ids(versions: &Value) -> Vec<String> {
    let Value::Array(arr) = versions else {
        return vec![];
    };

    let mut ids: Vec<String> = Vec::new();

    for item in arr {
        let Some(obj) = item.as_object() else {
            continue;
        };

        // Pattern A: `gameVersions: ["1.20.1", ...]`
        if let Some(Value::Array(gvs)) = obj.get("gameVersions") {
            for gv in gvs {
                if let Some(s) = gv.as_str() {
                    ids.push(s.to_string());
                }
            }
            continue;
        }

        // Pattern B: `gameVersion: "1.20.1"`
        if let Some(Value::String(gv)) = obj.get("gameVersion") {
            ids.push(gv.clone());
            continue;
        }

        // Pattern C: Forge/NeoForge simple entries — `id: "1.20.1-47.3.0"`
        // extract the part before the first `-`.
        if let Some(Value::String(id)) = obj.get("id") {
            // Only treat it as a MC ID if it looks like a version string
            // (contains dots and doesn't look like a plain loader version
            // like "0.15.3").
            let candidate = id.split('-').next().unwrap_or(id.as_str());
            if candidate.contains('.') && candidate != id.as_str() {
                // The full id had a `-` separator, so the prefix is the MC part.
                ids.push(candidate.to_string());
            }
            // If there's no `-`, this is a plain loader version — no MC ID to extract.
        }
    }

    ids.sort();
    ids.dedup();
    ids
}

/// Find the latest `releaseTime` among versions of type `"release"` in a
/// Minecraft manifest.  Returns `None` if none are found.
fn latest_release_time(versions: &Value) -> Option<DateTime<Utc>> {
    let Value::Array(arr) = versions else {
        return None;
    };

    arr.iter()
        .filter_map(|item| {
            let obj = item.as_object()?;
            // Only consider official releases.
            let ty = obj.get("type")?.as_str()?;
            if ty != "release" {
                return None;
            }
            // `releaseTime` field (ISO 8601).
            let rt_str = obj
                .get("releaseTime")
                .or_else(|| obj.get("release_time"))?
                .as_str()?;
            rt_str.parse::<DateTime<Utc>>().ok()
        })
        .max()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::cas::LoaderManifest;
    use serde_json::json;

    fn make_manifest(
        loader: &str,
        versions: serde_json::Value,
    ) -> LoaderManifest {
        LoaderManifest {
            schema_version: 1,
            loader: loader.to_string(),
            timestamp: "2026-01-01T00-00-00Z".to_string(),
            versions,
        }
    }

    // ── invariant 1: version count drop ──────────────────────────────────────

    #[test]
    fn test_version_count_ok() {
        let prev = make_manifest(
            "fabric",
            json!([{"id":"a"},{"id":"b"},{"id":"c"},{"id":"d"},{"id":"e"},{"id":"f"},{"id":"g"},{"id":"h"},{"id":"i"},{"id":"j"}]),
        );
        // 10 previous → minimum 9; new has 9 → ok
        let new_versions: Vec<serde_json::Value> =
            (0..9).map(|i| json!({"id": format!("{i}")})).collect();
        let new = make_manifest("fabric", json!(new_versions));
        assert_eq!(check_loader_health("fabric", &new, Some(&prev)), Ok(()));
    }

    #[test]
    fn test_version_count_drop_fails() {
        let prev_versions: Vec<serde_json::Value> =
            (0..100).map(|i| json!({"id": format!("{i}")})).collect();
        let prev = make_manifest("fabric", json!(prev_versions));
        // 100 previous → minimum 90; new has 50 → fail
        let new_versions: Vec<serde_json::Value> =
            (0..50).map(|i| json!({"id": format!("{i}")})).collect();
        let new = make_manifest("fabric", json!(new_versions));
        assert!(matches!(
            check_loader_health("fabric", &new, Some(&prev)),
            Err(SanityViolation::VersionCountDrop {
                current: 50,
                minimum: 90,
                ..
            })
        ));
    }

    #[test]
    fn test_empty_previous_no_check() {
        let prev = make_manifest("fabric", json!([]));
        let new = make_manifest("fabric", json!([]));
        assert_eq!(check_loader_health("fabric", &new, Some(&prev)), Ok(()));
    }

    #[test]
    fn test_single_version_cannot_drop_to_zero() {
        // prev has 1 version; floor(0.9 * 1) == 0, but `.max(1)` must still
        // block a collapse to zero versions.
        let prev = make_manifest("forge", json!([{"id": "1.20.1"}]));
        let new = make_manifest("forge", json!([]));
        assert!(matches!(
            check_loader_health("forge", &new, Some(&prev)),
            Err(SanityViolation::VersionCountDrop { current: 0, .. })
        ));
    }

    // ── no previous → always ok ───────────────────────────────────────────────

    #[test]
    fn test_no_previous_always_ok() {
        let new = make_manifest("minecraft", json!([]));
        assert_eq!(check_loader_health("minecraft", &new, None), Ok(()));
    }

    // ── invariant 2: minecraft coverage ──────────────────────────────────────

    #[test]
    fn test_mc_coverage_ok() {
        // Fabric-style: previous covers mc 1.20.1; new still covers it.
        let prev = make_manifest(
            "fabric",
            json!([{"gameVersion": "1.20.1"}, {"gameVersion": "1.19.4"}]),
        );
        let new = make_manifest(
            "fabric",
            json!([{"gameVersion": "1.20.1"}, {"gameVersion": "1.19.4"}, {"gameVersion": "1.21.0"}]),
        );
        assert_eq!(check_loader_health("fabric", &new, Some(&prev)), Ok(()));
    }

    #[test]
    fn test_mc_coverage_drop_fails() {
        // Previous covers 10 distinct MC versions across 20 entries (2 loader
        // versions per MC version).  New has 20 entries too (passes the version-count
        // check) but only covers 4 of the 10 MC versions → coverage drop fires.
        let prev_versions: Vec<serde_json::Value> = (0..10)
            .flat_map(|i| {
                vec![
                    json!({"gameVersion": format!("1.{i}.0")}),
                    json!({"gameVersion": format!("1.{i}.0")}),
                ]
            })
            .collect();
        let prev = make_manifest("forge", json!(prev_versions));

        // New also has 20 entries (≥ 18 = 90% of 20) but maps only 4 MC IDs.
        let new_versions: Vec<serde_json::Value> = (0..4)
            .flat_map(|i| {
                (0..5).map(move |_| json!({"gameVersion": format!("1.{i}.0")}))
            })
            .collect();
        let new = make_manifest("forge", json!(new_versions));

        let result = check_loader_health("forge", &new, Some(&prev));
        assert!(
            matches!(
                result,
                Err(SanityViolation::MinecraftCoverageDrop {
                    covered: 4,
                    previous_mc_ids: 10,
                    ..
                })
            ),
            "Expected MinecraftCoverageDrop(covered=4, prev=10), got {result:?}"
        );
    }

    #[test]
    fn test_forge_id_pattern_extraction() {
        // Forge entries use `id: "1.20.1-47.3.0"` — we must extract "1.20.1".
        let prev_versions: Vec<serde_json::Value> = (1..11)
            .map(|i| json!({"id": format!("1.{i}.0-47.0.{i}"), "hash": "aaa", "size": 1}))
            .collect();
        let prev = make_manifest("forge", json!(prev_versions));

        // new covers 9 of the same 10 MC IDs → ok (90%)
        let new_versions: Vec<serde_json::Value> = (1..10)
            .map(|i| json!({"id": format!("1.{i}.0-47.0.{i}"), "hash": "aaa", "size": 1}))
            .collect();
        let new = make_manifest("forge", json!(new_versions));
        assert_eq!(check_loader_health("forge", &new, Some(&prev)), Ok(()));
    }

    // ── invariant 3: minecraft latest release ─────────────────────────────────

    #[test]
    fn test_minecraft_release_ok() {
        let prev = make_manifest(
            "minecraft",
            json!([
                {"id": "1.20.1", "type": "release", "releaseTime": "2023-06-12T09:00:00Z"},
            ]),
        );
        let new = make_manifest(
            "minecraft",
            json!([
                {"id": "1.20.1", "type": "release", "releaseTime": "2023-06-12T09:00:00Z"},
                {"id": "1.21.0", "type": "release", "releaseTime": "2024-06-01T00:00:00Z"},
            ]),
        );
        assert_eq!(check_loader_health("minecraft", &new, Some(&prev)), Ok(()));
    }

    #[test]
    fn test_minecraft_release_regression_fails() {
        let prev = make_manifest(
            "minecraft",
            json!([
                {"id": "1.21.0", "type": "release", "releaseTime": "2024-06-01T00:00:00Z"},
            ]),
        );
        // new only has 1.20.1 — latest release regressed
        let new = make_manifest(
            "minecraft",
            json!([
                {"id": "1.20.1", "type": "release", "releaseTime": "2023-06-12T09:00:00Z"},
            ]),
        );
        assert!(matches!(
            check_loader_health("minecraft", &new, Some(&prev)),
            Err(SanityViolation::MinecraftLatestReleaseRegressed { .. })
        ));
    }

    #[test]
    fn test_minecraft_no_releases_skips_check() {
        // If neither manifest has any release entries, the check is skipped.
        let prev = make_manifest(
            "minecraft",
            json!([{"id": "23w10a", "type": "snapshot", "releaseTime": "2023-03-08T12:00:00Z"}]),
        );
        let new = make_manifest(
            "minecraft",
            json!([{"id": "23w10a", "type": "snapshot", "releaseTime": "2023-03-08T12:00:00Z"}]),
        );
        assert_eq!(check_loader_health("minecraft", &new, Some(&prev)), Ok(()));
    }

    // ── display ───────────────────────────────────────────────────────────────

    #[test]
    fn test_violation_display() {
        let v = SanityViolation::VersionCountDrop {
            loader: "forge".to_string(),
            previous: 100,
            current: 50,
            minimum: 90,
        };
        let s = v.to_string();
        assert!(s.contains("forge"));
        assert!(s.contains("50"));
        assert!(s.contains("100"));
    }
}
