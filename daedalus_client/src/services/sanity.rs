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
        // Fabric and Quilt nest every loader build under a single placeholder
        // entry and emit each real Minecraft version as its own empty-`loaders`
        // entry, so for them an empty-loaders entry still counts as covering its
        // MC id. Forge and NeoForge carry per-MC builds, so there an
        // empty-loaders entry means that MC version lost all its builds and must
        // not count as covered.
        let include_empty_loaders = matches!(loader, "fabric" | "quilt");
        let prev_mc_ids = extract_mc_ids(&prev.versions, include_empty_loaders);
        let new_mc_ids = extract_mc_ids(&new.versions, include_empty_loaders);

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

/// Extract the set of Minecraft version IDs a non-minecraft loader manifest
/// covers.
///
/// Forge, NeoForge, Fabric and Quilt all serialise `Vec<daedalus::modded::Version>`,
/// where every top-level entry is `{ "id": "<mc version>", "stable": …,
/// "loaders": [ … ] }` — the `id` IS the Minecraft version.
///
/// The two loader families differ in where the builds live, so
/// `include_empty_loaders` selects the right coverage rule:
///
/// * Forge / NeoForge nest a per-Minecraft-version build list under `loaders`,
///   so a version only *covers* its id when it carries at least one build
///   (`include_empty_loaders == false`). That lets the gate catch a run that
///   keeps the MC-version skeleton but loses the builds inside it.
/// * Fabric / Quilt nest every build under a single placeholder entry and emit
///   each real Minecraft version as its own entry with an EMPTY `loaders` array
///   (builds are resolved via `version_hashes` at the launcher). For those an
///   empty-loaders entry still declares MC coverage, so they pass
///   `include_empty_loaders == true`; otherwise the gate would only ever see
///   the single placeholder id and be a permanent no-op.
///
/// Any element that doesn't match this shape is skipped, and a manifest that
/// yields nothing returns an empty set so the caller skips the coverage check
/// rather than raising a false positive.
fn extract_mc_ids(versions: &Value, include_empty_loaders: bool) -> Vec<String> {
    let Value::Array(arr) = versions else {
        return vec![];
    };

    let mut ids: Vec<String> = Vec::new();

    for item in arr {
        let Some(obj) = item.as_object() else {
            continue;
        };

        // Modded loader entry: { id: "<mc>", loaders: [ … ] }. Count the
        // Minecraft id only when it actually carries a loader build.
        if let (Some(Value::String(id)), Some(Value::Array(loaders))) =
            (obj.get("id"), obj.get("loaders"))
        {
            if include_empty_loaders || !loaders.is_empty() {
                ids.push(id.clone());
            }
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

    /// Build one entry of the real modded-loader manifest shape
    /// (`daedalus::modded::Version`): a top-level MC `id` with its loader builds
    /// nested under `loaders`. An empty `builds` slice models an MC version that
    /// kept its slot but lost every loader build.
    fn modded_version(mc: &str, builds: &[&str]) -> serde_json::Value {
        json!({
            "id": mc,
            "stable": true,
            "loaders": builds
                .iter()
                .map(|id| json!({ "id": id, "url": "https://example/x.json", "stable": true }))
                .collect::<Vec<_>>(),
        })
    }

    #[test]
    fn test_mc_coverage_ok() {
        // Previous covers mc 1.20.1 / 1.19.4; new still covers both (and adds one).
        let prev = make_manifest(
            "fabric",
            json!([
                modded_version("1.20.1", &["0.15.0"]),
                modded_version("1.19.4", &["0.15.0"]),
            ]),
        );
        let new = make_manifest(
            "fabric",
            json!([
                modded_version("1.20.1", &["0.15.1"]),
                modded_version("1.19.4", &["0.15.1"]),
                modded_version("1.21.0", &["0.16.0"]),
            ]),
        );
        assert_eq!(check_loader_health("fabric", &new, Some(&prev)), Ok(()));
    }

    #[test]
    fn test_mc_coverage_drop_fails() {
        // Previous covers 10 MC versions, each with a build. New keeps all 10
        // top-level entries (so the version-count gate passes) but 6 of them
        // have an empty `loaders` array, so only 4 MC versions are actually
        // covered → coverage drop fires.
        let prev = make_manifest(
            "forge",
            json!((0..10)
                .map(|i| modded_version(&format!("1.{i}.0"), &["1.0.0"]))
                .collect::<Vec<_>>()),
        );

        let new = make_manifest(
            "forge",
            json!((0..10)
                .map(|i| {
                    let builds: &[&str] = if i < 4 { &["1.0.0"] } else { &[] };
                    modded_version(&format!("1.{i}.0"), builds)
                })
                .collect::<Vec<_>>()),
        );

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
    fn test_nested_modded_shape_is_understood() {
        // Regression guard for the dead-gate bug: the real shape nests the loader
        // id (e.g. "1.20.1-47.0.3") under a top-level MC `id` ("1.20.1"). The
        // coverage gate must key off the top-level MC id, not the nested loader
        // id. prev covers 10 MC ids; new covers 9 of them → 90% → ok.
        let prev = make_manifest(
            "forge",
            json!((1..11)
                .map(|i| modded_version(&format!("1.{i}.0"), &["47.0.1"]))
                .collect::<Vec<_>>()),
        );
        let new = make_manifest(
            "forge",
            json!((1..10)
                .map(|i| modded_version(&format!("1.{i}.0"), &["47.0.1"]))
                .collect::<Vec<_>>()),
        );
        assert_eq!(check_loader_health("forge", &new, Some(&prev)), Ok(()));
    }

    #[test]
    fn test_fabric_quilt_placeholder_shape_coverage_is_checked() {
        // Fabric/Quilt store every loader build under ONE placeholder entry
        // (non-empty `loaders`) and emit each real Minecraft version as its own
        // entry with an EMPTY `loaders` array. The coverage gate must count
        // those empty-loaders MC entries for fabric/quilt — otherwise it only
        // ever sees the single placeholder id and is a permanent no-op. Here the
        // entry COUNT is preserved (so invariant 1 passes) but the specific MC
        // ids change, which only the coverage gate can catch.
        let placeholder = json!({
            "id": "${gameVersion}", "stable": true,
            "loaders": [{"id": "0.16.0", "url": "https://example/x.json", "stable": true}],
        });
        let mc = |v: &str| json!({ "id": v, "stable": true, "loaders": [] });

        let prev = make_manifest(
            "fabric",
            json!([
                placeholder.clone(),
                mc("1.0.0"), mc("1.1.0"), mc("1.2.0"), mc("1.3.0"), mc("1.4.0"),
                mc("1.5.0"), mc("1.6.0"), mc("1.7.0"), mc("1.8.0"), mc("1.9.0"),
            ]),
        );
        // Same entry count (11), but 6 of the MC ids are replaced, so only 5 of
        // the 11 previous ids (placeholder + 1.0.0..1.3.0) survive → coverage
        // 5/11 < floor(0.9 * 11) = 9 → drop fires.
        let new = make_manifest(
            "fabric",
            json!([
                placeholder,
                mc("1.0.0"), mc("1.1.0"), mc("1.2.0"), mc("1.3.0"),
                mc("9.0.0"), mc("9.1.0"), mc("9.2.0"), mc("9.3.0"), mc("9.4.0"), mc("9.5.0"),
            ]),
        );

        let result = check_loader_health("fabric", &new, Some(&prev));
        assert!(
            matches!(
                result,
                Err(SanityViolation::MinecraftCoverageDrop {
                    covered: 5,
                    previous_mc_ids: 11,
                    ..
                })
            ),
            "Expected MinecraftCoverageDrop(covered=5, prev=11) for the fabric \
             placeholder shape, got {result:?}"
        );
    }

    #[test]
    fn test_fabric_quilt_placeholder_shape_ok_when_ids_retained() {
        // Same placeholder shape, but the new manifest keeps every previous MC
        // id (and adds one) → coverage holds and the gate passes.
        let placeholder = json!({
            "id": "${gameVersion}", "stable": true,
            "loaders": [{"id": "0.16.0", "url": "https://example/x.json", "stable": true}],
        });
        let mc = |v: &str| json!({ "id": v, "stable": true, "loaders": [] });

        let prev = make_manifest(
            "quilt",
            json!([placeholder.clone(), mc("1.20.1"), mc("1.19.4")]),
        );
        let new = make_manifest(
            "quilt",
            json!([placeholder, mc("1.20.1"), mc("1.19.4"), mc("1.21.0")]),
        );
        assert_eq!(check_loader_health("quilt", &new, Some(&prev)), Ok(()));
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
