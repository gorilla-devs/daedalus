//! Version-related utilities for Forge processing

use crate::format_url;
use daedalus::GradleSpecifier;
use std::collections::HashSet;

// Re-export CAS utilities from common module
pub use crate::common::cas::extract_hash_from_cas_url;

/// Fetch generated version info from the CAS
pub async fn fetch_generated_version_info(
    version_id: &str,
) -> Result<daedalus::minecraft::VersionInfo, crate::infrastructure::error::Error> {
    let path = format!(
        "minecraft/v{}/versions/{}.json",
        daedalus::minecraft::CURRENT_FORMAT_VERSION,
        version_id
    );

    Ok(serde_json::from_slice(
        &daedalus::download_file(&format_url(&path), None).await?,
    )?)
}

/// Check if an artifact should be ignored based on version comparison
/// Returns true if:
/// - The artifact already exists with the same or higher version in libs
/// - This prevents downgrading libraries
pub fn should_ignore_artifact(libs: &HashSet<GradleSpecifier>, name: &GradleSpecifier) -> bool {
    if let Some(ver) = libs.iter().find(|ver| {
        ver.package == name.package
            && ver.artifact == name.artifact
            && ver.identifier == name.identifier
    }) {
        if ver.version == name.version
            || lenient_semver::parse(&ver.version) > lenient_semver::parse(&name.version)
        {
            // new version is lower or equal
            true
        } else {
            // no match or new version is higher and this is an upgrade
            false
        }
    } else {
        // no match in set
        false
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
                GradleSpecifier::from_str(&format!("{}:{}:{}", package, artifact, version))
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
}
