//! Minecraft version comparison utilities
//!
//! This module provides custom version comparison logic that handles all
//! Minecraft version formats correctly, including:
//! - Snapshots (YYwWWx format like 23w9a, 23w10a)
//! - Pre-releases (X.Y.Z-preN, X.Y.Z-rcN)
//! - Old format (X.Y.Z_preN)
//! - Forge/NeoForge versions (X.Y.Z-A.B.C.D)
//! - Regular releases (X.Y.Z)
//!
//! The standard `lenient_semver` crate fails on snapshot versions because
//! it uses lexicographic comparison which incorrectly orders "23w9a" > "23w10a"
//! (since '9' > '1' in ASCII).

use std::cmp::Ordering;

/// Parsed Minecraft version format
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinecraftVersion {
    /// Snapshot version (YYwWWx format)
    /// Example: 23w10a = year 23, week 10, revision a
    Snapshot {
        year: u32,
        week: u32,
        revision: String,
    },
    /// Regular release version
    /// Example: 1.20.4
    Release {
        major: u32,
        minor: u32,
        patch: u32,
        prerelease: Option<Prerelease>,
        build: Option<Vec<u32>>,
    },
}

/// Pre-release format
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerelease {
    /// Pre-release (e.g., "pre1", "pre2")
    Pre(u32),
    /// Release candidate (e.g., "rc1", "rc2")
    Rc(u32),
    /// Other pre-release format (e.g., "alpha", "beta")
    Other(String),
}

impl MinecraftVersion {
    /// Parse a Minecraft version string
    pub fn parse(version: &str) -> Result<Self, String> {
        // Try snapshot format first (YYwWWx)
        if let Some(snapshot) = Self::try_parse_snapshot(version) {
            return Ok(snapshot);
        }

        // Try release/pre-release format
        Self::parse_release(version)
    }

    /// Try to parse as snapshot (YYwWWx format)
    fn try_parse_snapshot(version: &str) -> Option<Self> {
        // Check for 'w' character which is unique to snapshots
        if !version.contains('w') {
            return None;
        }

        // Split on 'w'
        let parts: Vec<&str> = version.split('w').collect();
        if parts.len() != 2 {
            return None;
        }

        // Parse year (before 'w')
        let year = parts[0].parse::<u32>().ok()?;

        // Parse week and revision (after 'w')
        // Week can be 1-2 digits, revision is everything after
        let week_and_rev = parts[1];

        // Find where the numeric week ends
        let week_end = week_and_rev
            .chars()
            .position(|c| !c.is_ascii_digit())
            .unwrap_or(week_and_rev.len());

        let week = week_and_rev[..week_end].parse::<u32>().ok()?;
        let revision = week_and_rev[week_end..].to_string();

        Some(MinecraftVersion::Snapshot {
            year,
            week,
            revision,
        })
    }

    /// Parse as release version
    fn parse_release(version: &str) -> Result<Self, String> {
        // Normalize: replace underscore with hyphen for old format compatibility
        let normalized = version.replace('_', "-");

        // Split on '-' to separate version from prerelease/build
        let parts: Vec<&str> = normalized.split('-').collect();

        // Parse base version (X.Y.Z or X.Y)
        let version_parts: Vec<&str> = parts[0].split('.').collect();

        let major = version_parts
            .first()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| format!("Invalid major version in '{}'", version))?;

        let minor = version_parts
            .get(1)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let patch = version_parts
            .get(2)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        // Parse pre-release if present (e.g., "pre1", "rc2")
        let mut prerelease = None;
        let mut build = None;

        if parts.len() > 1 {
            // Check if it's a pre-release
            let pre_str = parts[1];
            prerelease = Self::parse_prerelease(pre_str);

            // If not a prerelease, try parsing as build metadata (Forge format)
            if prerelease.is_none() {
                // Try parsing as numeric build (e.g., "14.23.5.2859" in Forge)
                let build_parts: Vec<u32> = parts[1..]
                    .iter()
                    .flat_map(|s| s.split('.'))
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect();

                if !build_parts.is_empty() {
                    build = Some(build_parts);
                }
            }
        }

        Ok(MinecraftVersion::Release {
            major,
            minor,
            patch,
            prerelease,
            build,
        })
    }

    /// Parse pre-release identifier
    fn parse_prerelease(s: &str) -> Option<Prerelease> {
        if let Some(stripped) = s.strip_prefix("pre") {
            return stripped.parse::<u32>().ok().map(Prerelease::Pre);
        }

        if let Some(stripped) = s.strip_prefix("rc") {
            return stripped.parse::<u32>().ok().map(Prerelease::Rc);
        }

        // Other pre-release formats (alpha, beta, etc.)
        if !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Some(Prerelease::Other(s.to_string()));
        }

        None
    }
}

impl PartialOrd for MinecraftVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MinecraftVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            // Snapshot vs Snapshot
            (
                MinecraftVersion::Snapshot { year: y1, week: w1, revision: r1 },
                MinecraftVersion::Snapshot { year: y2, week: w2, revision: r2 },
            ) => {
                // Compare year first
                match y1.cmp(y2) {
                    Ordering::Equal => {
                        // Then week
                        match w1.cmp(w2) {
                            Ordering::Equal => {
                                // Finally revision (lexicographic)
                                r1.cmp(r2)
                            }
                            other => other,
                        }
                    }
                    other => other,
                }
            }

            // Release vs Release
            (
                MinecraftVersion::Release { major: maj1, minor: min1, patch: p1, prerelease: pre1, build: b1 },
                MinecraftVersion::Release { major: maj2, minor: min2, patch: p2, prerelease: pre2, build: b2 },
            ) => {
                // Compare major.minor.patch
                match maj1.cmp(maj2) {
                    Ordering::Equal => match min1.cmp(min2) {
                        Ordering::Equal => match p1.cmp(p2) {
                            Ordering::Equal => {
                                // Compare pre-release
                                match (pre1, pre2) {
                                    (None, None) => {
                                        // Compare build metadata if both are releases
                                        compare_builds(b1, b2)
                                    }
                                    (Some(_), None) => Ordering::Less, // Pre-release < release
                                    (None, Some(_)) => Ordering::Greater, // Release > pre-release
                                    (Some(p1), Some(p2)) => compare_prereleases(p1, p2),
                                }
                            }
                            other => other,
                        },
                        other => other,
                    },
                    other => other,
                }
            }

            // Snapshot vs Release: snapshots are generally "development" versions
            // We treat them as lexicographically greater for now
            // (This is a heuristic and may need refinement based on usage)
            (MinecraftVersion::Snapshot { .. }, MinecraftVersion::Release { .. }) => {
                Ordering::Greater
            }
            (MinecraftVersion::Release { .. }, MinecraftVersion::Snapshot { .. }) => {
                Ordering::Less
            }
        }
    }
}

/// Compare build metadata (Forge versions)
fn compare_builds(b1: &Option<Vec<u32>>, b2: &Option<Vec<u32>>) -> Ordering {
    match (b1, b2) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (Some(v1), Some(v2)) => {
            // Compare element by element
            for (x, y) in v1.iter().zip(v2.iter()) {
                match x.cmp(y) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
            // If all equal so far, longer version is greater
            v1.len().cmp(&v2.len())
        }
    }
}

/// Compare pre-release identifiers
fn compare_prereleases(p1: &Prerelease, p2: &Prerelease) -> Ordering {
    match (p1, p2) {
        (Prerelease::Pre(n1), Prerelease::Pre(n2)) => n1.cmp(n2),
        (Prerelease::Rc(n1), Prerelease::Rc(n2)) => n1.cmp(n2),
        (Prerelease::Pre(_), Prerelease::Rc(_)) => Ordering::Less, // pre < rc
        (Prerelease::Rc(_), Prerelease::Pre(_)) => Ordering::Greater, // rc > pre
        (Prerelease::Other(s1), Prerelease::Other(s2)) => s1.cmp(s2),
        (Prerelease::Other(_), _) => Ordering::Less, // other < specific
        (_, Prerelease::Other(_)) => Ordering::Greater, // specific > other
    }
}

/// Convenience function for comparing two version strings
pub fn compare_versions(v1: &str, v2: &str) -> Result<Ordering, String> {
    let ver1 = MinecraftVersion::parse(v1)?;
    let ver2 = MinecraftVersion::parse(v2)?;
    Ok(ver1.cmp(&ver2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_snapshot() {
        let v = MinecraftVersion::parse("23w10a").unwrap();
        assert!(matches!(v, MinecraftVersion::Snapshot { year: 23, week: 10, .. }));

        let v = MinecraftVersion::parse("20w14infinite").unwrap();
        assert!(matches!(v, MinecraftVersion::Snapshot { year: 20, week: 14, .. }));
    }

    #[test]
    fn test_parse_release() {
        let v = MinecraftVersion::parse("1.20.4").unwrap();
        assert!(matches!(v, MinecraftVersion::Release { major: 1, minor: 20, patch: 4, .. }));
    }

    #[test]
    fn test_parse_prerelease() {
        let v = MinecraftVersion::parse("1.20.4-pre1").unwrap();
        if let MinecraftVersion::Release { ref prerelease, .. } = v {
            assert!(matches!(prerelease, Some(Prerelease::Pre(1))));
        } else {
            panic!("Expected Release variant");
        }
    }

    #[test]
    fn test_snapshot_ordering() {
        let v1 = MinecraftVersion::parse("23w9a").unwrap();
        let v2 = MinecraftVersion::parse("23w10a").unwrap();
        assert!(v1 < v2, "23w9a should be less than 23w10a");
    }

    #[test]
    fn test_release_ordering() {
        let v1 = MinecraftVersion::parse("1.19.4").unwrap();
        let v2 = MinecraftVersion::parse("1.20.0").unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_prerelease_ordering() {
        let release = MinecraftVersion::parse("1.20.4").unwrap();
        let pre = MinecraftVersion::parse("1.20.4-pre1").unwrap();
        assert!(pre < release, "pre-release should be less than release");
    }

    #[test]
    fn test_old_format() {
        let v = MinecraftVersion::parse("1.7.10_pre4").unwrap();
        if let MinecraftVersion::Release { ref prerelease, .. } = v {
            assert!(matches!(prerelease, Some(Prerelease::Pre(4))));
        } else {
            panic!("Expected Release variant");
        }

        let release = MinecraftVersion::parse("1.7.10").unwrap();
        assert!(v < release, "1.7.10_pre4 should be less than 1.7.10");
    }

    #[test]
    fn test_forge_versions() {
        let v1 = MinecraftVersion::parse("1.12.2-14.23.5.2851").unwrap();
        let v2 = MinecraftVersion::parse("1.12.2-14.23.5.2859").unwrap();
        assert!(v1 < v2, "Build 2851 should be less than 2859");
    }
}
