//! Version change detection utilities
//!
//! This module provides common logic for detecting whether a loader version has changed
//! by comparing content hashes, and logging appropriate messages.

use super::cas::extract_hash_from_cas_url;
use tracing::info;

/// Result of version change detection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeResult {
    /// Whether the version should be uploaded (true if changed or new)
    pub should_upload: bool,
    /// The old hash if it existed
    pub old_hash: Option<String>,
}

/// Detect if a loader version has changed by comparing hashes
///
/// This function:
/// 1. Extracts the old hash from the old version URL (if it exists)
/// 2. Compares it with the new hash
/// 3. Logs an appropriate message:
///    - "✓ {loader} {version} unchanged" if hashes match
///    - "↻ {loader} {version} changed" if hashes differ
///    - "+ {loader} {version} is new" if no old version exists
/// 4. Returns whether the version should be uploaded
///
/// # Arguments
///
/// * `loader_name` - Name of the loader (e.g., "Forge", "NeoForge")
/// * `version_id` - Version identifier (e.g., "1.20.1-47.1.0")
/// * `old_version_url` - Optional CAS URL from the previous manifest
/// * `new_hash` - Hash of the newly generated version data
///
/// # Returns
///
/// `ChangeResult` indicating whether to upload and the old hash if it existed
///
/// # Example
///
/// ```
/// let result = detect_version_change(
///     "Forge",
///     "1.20.1-47.1.0",
///     Some("https://example.com/v4/objects/ab/cdef123"),
///     "abcdef123"
/// );
/// assert_eq!(result.should_upload, false); // Unchanged
/// ```
pub fn detect_version_change(
    loader_name: &str,
    version_id: &str,
    old_version_url: Option<&str>,
    new_hash: &str,
) -> ChangeResult {
    if let Some(old_url) = old_version_url {
        if let Some(old_hash) = extract_hash_from_cas_url(old_url) {
            if old_hash == new_hash {
                info!(
                    "✓ {} {} unchanged (hash: {})",
                    loader_name,
                    version_id,
                    &new_hash[..8.min(new_hash.len())]
                );
                return ChangeResult {
                    should_upload: false,
                    old_hash: Some(old_hash),
                };
            } else {
                info!(
                    "↻ {} {} changed (old: {}, new: {})",
                    loader_name,
                    version_id,
                    &old_hash[..8.min(old_hash.len())],
                    &new_hash[..8.min(new_hash.len())]
                );
                return ChangeResult {
                    should_upload: true,
                    old_hash: Some(old_hash),
                };
            }
        }
    }

    // No old version or couldn't extract hash
    info!("+ {} {} is new", loader_name, version_id);
    ChangeResult {
        should_upload: true,
        old_hash: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unchanged_version() {
        let result = detect_version_change(
            "TestLoader",
            "1.0.0",
            Some("https://example.com/v4/objects/ab/cdef123"),
            "abcdef123",
        );
        assert_eq!(result.should_upload, false);
        assert_eq!(result.old_hash, Some("abcdef123".to_string()));
    }

    #[test]
    fn test_changed_version() {
        let result = detect_version_change(
            "TestLoader",
            "1.0.0",
            Some("https://example.com/v4/objects/ab/cdef123"),
            "xyz789abc",
        );
        assert_eq!(result.should_upload, true);
        assert_eq!(result.old_hash, Some("abcdef123".to_string()));
    }

    #[test]
    fn test_new_version() {
        let result = detect_version_change("TestLoader", "1.0.0", None, "abcdef123");
        assert_eq!(result.should_upload, true);
        assert_eq!(result.old_hash, None);
    }

    #[test]
    fn test_invalid_old_url() {
        // Old URL that doesn't match CAS format
        let result = detect_version_change(
            "TestLoader",
            "1.0.0",
            Some("invalid-url"),
            "abcdef123",
        );
        assert_eq!(result.should_upload, true);
        assert_eq!(result.old_hash, None);
    }
}
