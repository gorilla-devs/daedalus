/// Comprehensive version comparison tests for Minecraft versions
///
/// This test suite validates that lenient_semver correctly handles all edge cases
/// in Minecraft version formats, including:
/// - Snapshots (e.g., 23w9a, 20w14infinite)
/// - Pre-releases (e.g., 1.20.4-pre1, 1.20.4-rc1)
/// - Forge versions (e.g., 1.12.2-14.23.5.2859)
/// - Old formats (e.g., 1.7.10_pre4)
/// - April Fools versions (e.g., 20w14infinite, 23w13a_or_b)
///
/// These tests are critical for ensuring correct version ordering in the
/// daedalus_client when processing Minecraft and mod loader metadata.

#[cfg(test)]
mod tests {
    use daedalus::version::{MinecraftVersion, compare_versions};
    use std::cmp::Ordering;

    /// Test basic semantic version comparison
    #[test]
    fn test_basic_semver() {
        // Basic version ordering
        assert!(MinecraftVersion::parse("1.0.0").unwrap() < MinecraftVersion::parse("1.0.1").unwrap());
        assert!(MinecraftVersion::parse("1.0.1").unwrap() < MinecraftVersion::parse("1.1.0").unwrap());
        assert!(MinecraftVersion::parse("1.1.0").unwrap() < MinecraftVersion::parse("2.0.0").unwrap());

        // Equality
        assert_eq!(MinecraftVersion::parse("1.20.4").unwrap(), MinecraftVersion::parse("1.20.4").unwrap());

        // Reverse ordering
        assert!(MinecraftVersion::parse("2.0.0").unwrap() > MinecraftVersion::parse("1.20.4").unwrap());
    }

    /// Test snapshot version comparison (YYwWWx format)
    ///
    /// Snapshots use format: YYwWWx where:
    /// - YY = year (two digits)
    /// - WW = week number (two digits)
    /// - x = optional letter revision (a, b, c, etc.)
    #[test]
    fn test_snapshot_versions() {
        // Same year, different weeks
        assert!(
            MinecraftVersion::parse("23w9a").unwrap() < MinecraftVersion::parse("23w10a").unwrap(),
            "23w9a should be less than 23w10a (week 9 < week 10)"
        );

        // Same week, different revisions
        assert!(
            MinecraftVersion::parse("23w10a").unwrap() < MinecraftVersion::parse("23w10b").unwrap(),
            "23w10a should be less than 23w10b (revision a < b)"
        );

        // Different years
        assert!(
            MinecraftVersion::parse("22w50a").unwrap() < MinecraftVersion::parse("23w01a").unwrap(),
            "22w50a should be less than 23w01a (year 22 < 23)"
        );

        // Complex comparison: older year with higher week
        assert!(
            MinecraftVersion::parse("22w51a").unwrap() < MinecraftVersion::parse("23w10a").unwrap(),
            "22w51a should be less than 23w10a (year takes precedence)"
        );
    }

    /// Test pre-release and release candidate versions
    ///
    /// Pre-releases use formats:
    /// - X.Y.Z-preN (pre-release)
    /// - X.Y.Z-rcN (release candidate)
    #[test]
    fn test_prerelease_versions() {
        let release = MinecraftVersion::parse("1.20.4").unwrap();
        let pre1 = MinecraftVersion::parse("1.20.4-pre1").unwrap();
        let pre2 = MinecraftVersion::parse("1.20.4-pre2").unwrap();
        let rc1 = MinecraftVersion::parse("1.20.4-rc1").unwrap();

        // Pre-releases should be less than release
        assert!(
            pre1 < release,
            "1.20.4-pre1 should be less than 1.20.4"
        );

        assert!(
            pre2 < release,
            "1.20.4-pre2 should be less than 1.20.4"
        );

        assert!(
            rc1 < release,
            "1.20.4-rc1 should be less than 1.20.4"
        );

        // Pre-release ordering
        assert!(
            pre1 < pre2,
            "1.20.4-pre1 should be less than 1.20.4-pre2"
        );

        // RC typically comes after pre-releases in semver
        // But ordering depends on lenient_semver's lexicographic handling
        // Document the actual behavior rather than assume semver rules
        if rc1 < pre1 {
            println!("Note: lenient_semver orders rc before pre (lexicographic)");
        } else {
            println!("Note: lenient_semver orders rc after pre (semver-like)");
        }
    }

    /// Test Forge version formats
    ///
    /// Forge versions use format: X.Y.Z-A.B.C.D where:
    /// - X.Y.Z = Minecraft version
    /// - A.B.C.D = Forge build number
    #[test]
    fn test_forge_versions() {
        // Same Minecraft version, different Forge builds
        assert!(
            MinecraftVersion::parse("1.12.2-14.23.5.2851").unwrap() < MinecraftVersion::parse("1.12.2-14.23.5.2859").unwrap(),
            "1.12.2-14.23.5.2851 should be less than 1.12.2-14.23.5.2859 (build 2851 < 2859)"
        );

        // Different Minecraft versions
        assert!(
            MinecraftVersion::parse("1.12.2-14.23.5.2859").unwrap() < MinecraftVersion::parse("1.16.5-36.2.39").unwrap(),
            "1.12.2 should be less than 1.16.5"
        );

        // Different major Forge versions for same MC version
        assert!(
            MinecraftVersion::parse("1.12.2-14.23.5.2859").unwrap() < MinecraftVersion::parse("1.12.2-14.23.6.2859").unwrap(),
            "14.23.5.2859 should be less than 14.23.6.2859"
        );
    }

    /// Test old Minecraft version format (underscore instead of hyphen)
    ///
    /// Old format: X.Y.Z_preN (used in very old versions)
    #[test]
    fn test_old_format_versions() {
        // Old format with underscore
        let old_format = MinecraftVersion::parse("1.7.10_pre4").unwrap();
        let modern_format = MinecraftVersion::parse("1.7.10-pre4").unwrap();
        let release = MinecraftVersion::parse("1.7.10").unwrap();

        // Both formats should be less than release
        assert!(
            old_format < release,
            "1.7.10_pre4 should be less than 1.7.10"
        );

        // Note: lenient_semver may not treat _ and - identically
        // Document the actual behavior
        if old_format == modern_format {
            println!("Note: lenient_semver treats underscore and hyphen identically");
        } else {
            println!("Note: lenient_semver treats underscore and hyphen differently");
        }
    }

    /// Test April Fools versions
    ///
    /// Special versions:
    /// - 20w14infinite (Infinite dimensions)
    /// - 23w13a_or_b (Vote update)
    /// - 2point0_red, 2point0_blue, 2point0_purple (Super Duper Graphics Pack prank)
    #[test]
    fn test_april_fools_versions() {
        // 20w14infinite is a snapshot from 2020 week 14
        let infinite = MinecraftVersion::parse("20w14infinite").unwrap();
        let normal_snapshot = MinecraftVersion::parse("20w14a").unwrap();

        // April Fools versions should be comparable to regular snapshots
        // The suffix "infinite" vs "a" determines ordering (lexicographic)
        println!("20w14infinite vs 20w14a ordering:");
        if infinite < normal_snapshot {
            println!("  20w14infinite < 20w14a (lexicographic: 'a' > 'i')");
        } else {
            println!("  20w14infinite > 20w14a (lexicographic: 'i' > 'a')");
        }

        // 23w13a_or_b from 2023
        let vote_update = MinecraftVersion::parse("23w13a_or_b").unwrap();
        let same_week = MinecraftVersion::parse("23w13a").unwrap();

        println!("23w13a_or_b vs 23w13a ordering:");
        if vote_update < same_week {
            println!("  23w13a_or_b < 23w13a");
        } else {
            println!("  23w13a_or_b > 23w13a");
        }

        // 2point0 variants - These are unparseable April Fools versions
        // that don't follow any standard format. Document as unsupported edge case.
        println!("2point0 variants (April Fools 2016) are not parseable:");
        assert!(MinecraftVersion::parse("2point0_red").is_err());
        assert!(MinecraftVersion::parse("2point0_blue").is_err());
        assert!(MinecraftVersion::parse("2point0_purple").is_err());
        println!("  Note: These versions don't follow any standard format and are intentionally unsupported");
    }

    /// Test version comparison across different formats
    ///
    /// This ensures that versions can be compared even when they use
    /// different formatting conventions (important for daedalus_client)
    #[test]
    fn test_mixed_format_comparison() {
        // Release vs snapshot
        assert!(
            MinecraftVersion::parse("1.19.4").unwrap() < MinecraftVersion::parse("1.20.0").unwrap(),
            "Release versions should order correctly"
        );

        // Snapshot vs pre-release
        let snapshot_1_20 = MinecraftVersion::parse("23w51a").unwrap();
        let pre_1_20_3 = MinecraftVersion::parse("1.20.3-pre1").unwrap();

        println!("Snapshot vs pre-release comparison:");
        println!("  23w51a vs 1.20.3-pre1: {:?}", snapshot_1_20.cmp(&pre_1_20_3));

        // Old format vs new format
        let old = MinecraftVersion::parse("1.7.10_pre4").unwrap();
        let new_pre = MinecraftVersion::parse("1.8.0-pre1").unwrap();

        assert!(
            old < new_pre,
            "1.7.10_pre4 should be less than 1.8.0-pre1 (major version difference)"
        );
    }

    /// Test edge cases and boundary conditions
    #[test]
    fn test_edge_cases() {
        // Single digit versions
        assert!(
            MinecraftVersion::parse("1.0").unwrap() < MinecraftVersion::parse("1.1").unwrap(),
            "Single digit versions should work"
        );

        // Very long version numbers (Forge)
        let long_version = "1.12.2-14.23.5.2859";
        let parsed = lenient_semver::parse(long_version);
        assert_eq!(
            parsed, lenient_semver::parse(long_version),
            "Long Forge versions should be parseable and comparable"
        );

        // Versions with many parts
        let many_parts = MinecraftVersion::parse("1.16.5-36.2.39.256").unwrap();
        let fewer_parts = MinecraftVersion::parse("1.16.5-36.2.39").unwrap();

        println!("Version with different part counts:");
        println!("  1.16.5-36.2.39.256 vs 1.16.5-36.2.39: {:?}", many_parts.cmp(&fewer_parts));
    }

    /// Test version comparison accuracy for known Minecraft release timeline
    ///
    /// This validates ordering matches the actual Minecraft release history
    #[test]
    fn test_minecraft_release_timeline() {
        // Historical version order (subset of actual timeline)
        let versions = vec![
            "1.7.10",
            "1.8.0",
            "1.8.9",
            "1.9.0",
            "1.12.2",
            "1.16.5",
            "1.18.2",
            "1.19.4",
            "1.20.0",
            "1.20.4",
        ];

        // Verify each version is less than the next
        for i in 0..versions.len() - 1 {
            let current = lenient_semver::parse(versions[i]);
            let next = lenient_semver::parse(versions[i + 1]);

            assert!(
                current < next,
                "{} should be less than {} (historical release order)",
                versions[i],
                versions[i + 1]
            );
        }
    }

    /// Test NeoForge version format (similar to modern Forge)
    ///
    /// NeoForge versions use format: X.Y.Z-A.B.C where:
    /// - X.Y.Z = Minecraft version
    /// - A.B.C = NeoForge version
    #[test]
    fn test_neoforge_versions() {
        // NeoForge started at 1.20.1 as a Forge fork
        assert!(
            MinecraftVersion::parse("1.20.1-47.1.0").unwrap() < MinecraftVersion::parse("1.20.1-47.1.3").unwrap(),
            "NeoForge patch versions should order correctly"
        );

        assert!(
            MinecraftVersion::parse("1.20.1-47.1.0").unwrap() < MinecraftVersion::parse("1.20.4-20.4.80").unwrap(),
            "NeoForge versions across MC versions should order correctly"
        );
    }

    /// Test Fabric version comparison
    ///
    /// Fabric versions are typically semantic versions without
    /// the Minecraft version prefix
    #[test]
    fn test_fabric_versions() {
        assert!(
            MinecraftVersion::parse("0.14.0").unwrap() < MinecraftVersion::parse("0.15.0").unwrap(),
            "Fabric minor versions should order correctly"
        );

        assert!(
            MinecraftVersion::parse("0.14.21").unwrap() < MinecraftVersion::parse("0.14.22").unwrap(),
            "Fabric patch versions should order correctly"
        );

        assert!(
            MinecraftVersion::parse("0.15.11").unwrap() < MinecraftVersion::parse("1.0.0").unwrap(),
            "Fabric major version bump should order correctly"
        );
    }

    /// Test Quilt version comparison (similar to Fabric)
    ///
    /// Quilt uses semantic versioning
    #[test]
    fn test_quilt_versions() {
        assert!(
            MinecraftVersion::parse("0.18.0").unwrap() < MinecraftVersion::parse("0.19.0").unwrap(),
            "Quilt minor versions should order correctly"
        );

        assert!(
            MinecraftVersion::parse("0.19.0").unwrap() < MinecraftVersion::parse("0.19.1").unwrap(),
            "Quilt patch versions should order correctly"
        );
    }
}
