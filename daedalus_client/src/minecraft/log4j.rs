//! Log4j security patching for CVE-2021-44228, CVE-2021-44832, CVE-2021-45046
//!
//! This module handles detection and replacement of vulnerable Log4j versions
//! with patched versions. This is SECURITY-CRITICAL code.

use crate::format_url;
use daedalus::minecraft::{Library, LibraryDownload, LibraryDownloads};
use daedalus::GradleSpecifier;
use tracing::debug;

/// Determine if a Log4j version needs patching and return the replacement version and Maven URL
///
/// Returns `Some((replacement_version, maven_url))` if patching is needed, `None` otherwise
///
/// # Security
/// - CVE-2021-44228: Log4Shell vulnerability
/// - CVE-2021-44832: Remote code execution
/// - CVE-2021-45046: Information disclosure
///
/// All versions < 2.17.1 are vulnerable and should be patched.
pub fn map_log4j_artifact(
    version: &str,
) -> Result<Option<(String, String)>, crate::infrastructure::error::Error> {
    debug!("log4j version: {}", version);
    let x = lenient_semver::parse(version);
    if x <= lenient_semver::parse("2.0") {
        debug!("log4j use beta9 patch");
        return Ok(Some(("2.0-beta9-fixed".to_string(), format_url("maven/"))));
    }
    if x < lenient_semver::parse("2.17.1") {
        debug!("bump log4j to 2.17.1");
        return Ok(Some((
            "2.17.1".to_string(),
            "https://repo1.maven.org/maven2/".to_string(),
        )));
    }
    debug!("no log4j match!");
    Ok(None)
}

/// Create a replacement Log4j library with patched version
///
/// # Security
/// The SHA1 hashes and sizes are hardcoded for security verification.
/// These values are for the patched Log4j versions that fix CVEs.
///
/// # Arguments
/// - `artifact_name`: The artifact name (e.g., "log4j-api", "log4j-core")
/// - `version_override`: The patched version to use ("2.0-beta9-fixed" or "2.17.1")
/// - `maven_override`: The Maven repository URL
/// - `include_in_classpath`: Whether to include in classpath (from original library)
///
/// # Returns
/// A `Library` struct with the replacement Log4j artifact
pub fn create_log4j_replacement_library(
    artifact_name: &str,
    version_override: &str,
    maven_override: &str,
    include_in_classpath: bool,
) -> Result<Library, crate::infrastructure::error::Error> {
    let replacement_name = GradleSpecifier {
        package: "org.apache.logging.log4j".to_string(),
        artifact: artifact_name.to_string(),
        identifier: None,
        version: version_override.to_string(),
        extension: "jar".to_string(),
    };

    // Hardcoded SHA1 hashes and sizes for security verification
    // DO NOT MODIFY unless you've verified the new hashes
    let (sha1, size) = match version_override {
        "2.0-beta9-fixed" => match artifact_name {
            "log4j-api" => ("b61eaf2e64d8b0277e188262a8b771bbfa1502b3", 107347),
            "log4j-core" => ("677991ea2d7426f76309a73739cecf609679492c", 677588),
            _ => {
                return Err(crate::infrastructure::error::invalid_input(format!(
                    "Unhandled log4j artifact {} for overridden version {}",
                    artifact_name, version_override
                )))
            }
        },
        "2.17.1" => match artifact_name {
            "log4j-api" => ("d771af8e336e372fb5399c99edabe0919aeaf5b2", 301872),
            "log4j-core" => ("779f60f3844dadc3ef597976fcb1e5127b1f343d", 1790452),
            "log4j-slf4j18-impl" => ("ca499d751f4ddd8afb016ef698c30be0da1d09f7", 21268),
            _ => {
                return Err(crate::infrastructure::error::invalid_input(format!(
                    "Unhandled log4j artifact {} for overridden version {}",
                    artifact_name, version_override
                )))
            }
        },
        _ => {
            return Err(crate::infrastructure::error::invalid_input(format!(
                "Unhandled log4j version {}",
                version_override
            )))
        }
    };

    let artifact = LibraryDownload {
        path: replacement_name.path(),
        sha1: sha1.to_string(),
        size,
        url: Some(format!("{}{}", maven_override, replacement_name.path())),
    };

    Ok(Library {
        name: replacement_name,
        downloads: Some(LibraryDownloads {
            artifact: Some(artifact),
            classifiers: None,
        }),
        extract: None,
        url: None,
        natives: None,
        rules: None,
        checksums: None,
        include_in_classpath,
        version_hashes: None,
        patched: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lenient_semver_comparison() {
        // Test basic version comparisons
        assert!(lenient_semver::parse("1.0.0") < lenient_semver::parse("2.0.0"));
        assert!(lenient_semver::parse("2.0.0") > lenient_semver::parse("1.0.0"));
        assert!(lenient_semver::parse("2.0.0") == lenient_semver::parse("2.0.0"));

        // Test beta/pre-release versions (critical for Log4j patching)
        assert!(lenient_semver::parse("2.0-beta9") <= lenient_semver::parse("2.0"));
        assert!(lenient_semver::parse("2.0-beta9") < lenient_semver::parse("2.1.0"));
        assert!(lenient_semver::parse("2.0-rc2") <= lenient_semver::parse("2.0"));

        // Test Log4j security threshold (CVE-2021-44832 fixed in 2.17.1)
        assert!(lenient_semver::parse("2.0") <= lenient_semver::parse("2.17.1"));
        assert!(lenient_semver::parse("2.15.0") <= lenient_semver::parse("2.17.1"));
        assert!(lenient_semver::parse("2.16.0") <= lenient_semver::parse("2.17.1"));
        assert!(lenient_semver::parse("2.17.0") <= lenient_semver::parse("2.17.1"));
        assert!(lenient_semver::parse("2.17.1") <= lenient_semver::parse("2.17.1"));
        assert!(lenient_semver::parse("2.18.0") > lenient_semver::parse("2.17.1"));

        // Test actual Log4j versions that have been patched
        assert!(lenient_semver::parse("2.0-beta9") <= lenient_semver::parse("2.0"));
        assert!(lenient_semver::parse("2.12.1") <= lenient_semver::parse("2.17.1"));
        assert!(lenient_semver::parse("2.14.1") <= lenient_semver::parse("2.17.1"));
    }

    #[test]
    fn test_log4j_artifact_mapping() {
        // Test versions below 2.0 (should use beta9 patch)
        let result = map_log4j_artifact("1.2.17").unwrap();
        assert!(result.is_some());
        let (version, _url) = result.unwrap();
        assert_eq!(version, "2.0-beta9-fixed");

        let result = map_log4j_artifact("2.0-beta9").unwrap();
        assert!(result.is_some());
        let (version, _url) = result.unwrap();
        assert_eq!(version, "2.0-beta9-fixed");

        // Test versions between 2.0 and 2.17.1 (should bump to 2.17.1)
        let result = map_log4j_artifact("2.12.1").unwrap();
        assert!(result.is_some());
        let (version, url) = result.unwrap();
        assert_eq!(version, "2.17.1");
        assert_eq!(url, "https://repo1.maven.org/maven2/");

        let result = map_log4j_artifact("2.15.0").unwrap();
        assert!(result.is_some());
        let (version, _url) = result.unwrap();
        assert_eq!(version, "2.17.1");

        let result = map_log4j_artifact("2.17.0").unwrap();
        assert!(result.is_some());
        let (version, _url) = result.unwrap();
        assert_eq!(version, "2.17.1");

        // Test versions at or above 2.17.1 (no patching needed)
        let result = map_log4j_artifact("2.17.1").unwrap();
        assert!(result.is_none());

        let result = map_log4j_artifact("2.18.0").unwrap();
        assert!(result.is_none());

        let result = map_log4j_artifact("2.19.0").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_create_log4j_replacement_library() {
        // Test creating a replacement for log4j-api with 2.0-beta9-fixed
        let lib = create_log4j_replacement_library(
            "log4j-api",
            "2.0-beta9-fixed",
            "https://test-maven.org/",
            true,
        )
        .unwrap();

        assert_eq!(lib.name.package, "org.apache.logging.log4j");
        assert_eq!(lib.name.artifact, "log4j-api");
        assert_eq!(lib.name.version, "2.0-beta9-fixed");
        assert!(lib.patched);
        assert_eq!(lib.include_in_classpath, true);

        let downloads = lib.downloads.unwrap();
        let artifact = downloads.artifact.unwrap();
        assert_eq!(artifact.sha1, "b61eaf2e64d8b0277e188262a8b771bbfa1502b3");
        assert_eq!(artifact.size, 107347);

        // Test creating a replacement for log4j-core with 2.17.1
        let lib2 = create_log4j_replacement_library(
            "log4j-core",
            "2.17.1",
            "https://repo1.maven.org/maven2/",
            false,
        )
        .unwrap();

        assert_eq!(lib2.name.version, "2.17.1");
        assert_eq!(lib2.include_in_classpath, false);

        let downloads2 = lib2.downloads.unwrap();
        let artifact2 = downloads2.artifact.unwrap();
        assert_eq!(artifact2.sha1, "779f60f3844dadc3ef597976fcb1e5127b1f343d");
        assert_eq!(artifact2.size, 1790452);
    }

    #[test]
    fn test_create_log4j_replacement_unknown_artifact() {
        // Test that unknown artifacts return an error
        let result = create_log4j_replacement_library(
            "log4j-unknown",
            "2.17.1",
            "https://repo1.maven.org/maven2/",
            true,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_create_log4j_replacement_unknown_version() {
        // Test that unknown versions return an error
        let result = create_log4j_replacement_library(
            "log4j-api",
            "9.9.9",
            "https://repo1.maven.org/maven2/",
            true,
        );

        assert!(result.is_err());
    }
}
