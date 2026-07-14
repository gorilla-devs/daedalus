//! Version-related utilities for Forge processing

use daedalus::GradleSpecifier;
use std::collections::HashSet;

// Re-export CAS utilities from common module
pub use crate::common::cas::extract_hash_from_cas_url;

/// Fetch a processed Minecraft version JSON, given the CAS object URL
/// recorded in this run's freshly built minecraft manifest. The URL must come
/// from that manifest — processed version JSONs exist only as CAS objects,
/// not at any per-version path.
pub async fn fetch_generated_version_info(
    url: &str,
) -> Result<daedalus::minecraft::VersionInfo, crate::infrastructure::error::Error>
{
    Ok(serde_json::from_slice(
        &daedalus::download_file(url, None).await?,
    )?)
}

/// Check if an artifact should be ignored based on version comparison
/// Returns true if:
/// - The artifact already exists with the same or higher version in libs
/// - This prevents downgrading libraries
pub fn should_ignore_artifact(
    libs: &HashSet<GradleSpecifier>,
    name: &GradleSpecifier,
) -> bool {
    let Some(ver) = libs.iter().find(|ver| {
        ver.package == name.package
            && ver.artifact == name.artifact
            && ver.identifier == name.identifier
    }) else {
        // No matching artifact in the set.
        return false;
    };

    // Same version already present — ignore (dedup).
    if ver.version == name.version {
        return true;
    }

    // Different version: ignore only when we can prove the existing one is
    // strictly newer. `lenient_semver::parse` returns a Result, and comparing
    // two Results directly relies on `Err` sorting after `Ok`, which scrambled
    // the decision whenever either version string failed to parse. Parse both
    // explicitly; if either is unparseable we cannot prove the existing is
    // newer, so we do NOT ignore (process the artifact) rather than risk
    // dropping a library that should be included.
    match (
        lenient_semver::parse(&ver.version),
        lenient_semver::parse(&name.version),
    ) {
        (Ok(existing), Ok(candidate)) => existing > candidate,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_should_ignore_artifact() {
        // Create test artifacts
        let create_spec =
            |package: &str, artifact: &str, version: &str| -> GradleSpecifier {
                GradleSpecifier::from_str(&format!(
                    "{}:{}:{}",
                    package, artifact, version
                ))
                .expect("Valid GradleSpecifier")
            };

        // Test case 1: Identical version (should ignore - already have it)
        {
            let mut libs = HashSet::new();
            libs.insert(create_spec("org.example", "library", "1.0.0"));

            let new_artifact = create_spec("org.example", "library", "1.0.0");
            assert!(
                should_ignore_artifact(&libs, &new_artifact),
                "Should ignore identical version"
            );
        }

        // Test case 2: Lower version in new data (should ignore - keep existing higher version)
        {
            let mut libs = HashSet::new();
            libs.insert(create_spec("org.example", "library", "2.0.0"));

            let new_artifact = create_spec("org.example", "library", "1.0.0");
            assert!(
                should_ignore_artifact(&libs, &new_artifact),
                "Should ignore lower version"
            );
        }

        // Test case 3: Higher version in new data (should NOT ignore - upgrade needed)
        {
            let mut libs = HashSet::new();
            libs.insert(create_spec("org.example", "library", "1.0.0"));

            let new_artifact = create_spec("org.example", "library", "2.0.0");
            assert!(
                !should_ignore_artifact(&libs, &new_artifact),
                "Should NOT ignore higher version (upgrade needed)"
            );
        }

        // Test case 4: No match in set (should NOT ignore - new artifact)
        {
            let mut libs = HashSet::new();
            libs.insert(create_spec("org.example", "other-library", "1.0.0"));

            let new_artifact = create_spec("org.example", "library", "1.0.0");
            assert!(
                !should_ignore_artifact(&libs, &new_artifact),
                "Should NOT ignore new artifact"
            );
        }

        // Test case 5: Different package (should NOT ignore)
        {
            let mut libs = HashSet::new();
            libs.insert(create_spec("org.example", "library", "1.0.0"));

            let new_artifact = create_spec("com.other", "library", "1.0.0");
            assert!(
                !should_ignore_artifact(&libs, &new_artifact),
                "Should NOT ignore different package"
            );
        }

        // Test case 6: Empty libs set (should NOT ignore)
        {
            let libs = HashSet::new();
            let new_artifact = create_spec("org.example", "library", "1.0.0");
            assert!(
                !should_ignore_artifact(&libs, &new_artifact),
                "Should NOT ignore when libs is empty"
            );
        }
    }

    #[test]
    fn test_unparseable_version_is_not_treated_as_newer() {
        let spec = |v: &str| {
            GradleSpecifier::from_str(&format!("org.example:library:{v}"))
                .expect("valid GradleSpecifier")
        };
        // The existing version is unparseable by lenient_semver (a real Forge
        // form — underscores fail to parse). We cannot prove it is newer, so a
        // different candidate must NOT be ignored (it must be processed). Guards
        // the Result-comparison regression where Err sorted after Ok and
        // scrambled the decision.
        let mut libs = HashSet::new();
        libs.insert(spec("1.7.10_pre4"));
        assert!(
            !should_ignore_artifact(&libs, &spec("1.0.0")),
            "Unparseable existing version must not be treated as newer"
        );
        // The exact-equal short-circuit still dedups without parsing.
        let mut libs2 = HashSet::new();
        libs2.insert(spec("1.7.10_pre4"));
        assert!(
            should_ignore_artifact(&libs2, &spec("1.7.10_pre4")),
            "Identical version must still dedup via string equality"
        );
    }
}
