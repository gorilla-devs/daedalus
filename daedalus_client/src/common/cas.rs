//! Content-Addressable Storage (CAS) utilities
//!
//! This module provides common functions for working with the CAS system,
//! including URL building and hash extraction.

use std::sync::LazyLock;

/// Cached BASE_URL — fetched once at first access from the environment.
///
/// Centralising this avoids the ~10 scattered `dotenvy::var("BASE_URL").unwrap()`
/// hot-path calls and surfaces a missing env var with a clear panic at startup
/// rather than at the first concurrent task that happens to format a URL.
pub static BASE_URL: LazyLock<String> = LazyLock::new(|| {
    dotenvy::var("BASE_URL")
        .expect("BASE_URL environment variable must be set (checked at startup via check_env_vars)")
});

/// Extract the content hash from a CAS URL
///
/// CAS URLs have the format: `{base}/v{version}/objects/{hash_prefix}/{hash_suffix}`
/// This function extracts and concatenates the hash components.
///
/// # Arguments
///
/// * `url` - The CAS URL to extract the hash from
///
/// # Returns
///
/// * `Some(hash)` - The full hash if the URL format is valid
/// * `None` - If the URL doesn't match the expected format
///
/// # Example
///
/// ```
/// let url = "https://example.com/v4/objects/ab/cdef123";
/// let hash = extract_hash_from_cas_url(url);
/// assert_eq!(hash, Some("abcdef123".to_string()));
/// ```
pub fn extract_hash_from_cas_url(url: &str) -> Option<String> {
    let parts: Vec<&str> = url.rsplitn(3, '/').collect();
    // Valid CAS URL must have exactly 3 parts when split from right:
    // [hash_suffix, hash_prefix, "{base}/v{version}/objects"]
    // The third part must end with "objects" to be valid
    if parts.len() == 3 && parts[2].ends_with("objects") {
        let hash_suffix = parts[0];
        let hash_prefix = parts[1];
        Some(format!("{}{}", hash_prefix, hash_suffix))
    } else {
        None
    }
}

/// Build a CAS URL from a content hash
///
/// Constructs a URL in the format: `{base}/v{version}/objects/{hash[..2]}/{hash[2..]}`
///
/// # Arguments
///
/// * `hash` - The content hash to build a URL for (must be at least 2 characters)
///
/// # Returns
///
/// The complete CAS URL, or an error if the hash is too short
///
/// # Example
///
/// ```
/// let hash = "abcdef123456";
/// let url = build_cas_url(hash)?;
/// // Returns: "{BASE_URL}/v{CAS_VERSION}/objects/ab/cdef123456"
/// ```
pub fn build_cas_url(
    hash: &str,
) -> Result<String, crate::infrastructure::error::Error> {
    if hash.len() < 2 || !hash.is_char_boundary(2) {
        return Err(crate::infrastructure::error::invalid_input(format!(
            "Hash unusable for CAS URL: '{}' (must be at least 2 single-byte characters)",
            hash
        )));
    }
    Ok(format!(
        "{}/v{}/objects/{}/{}",
        BASE_URL.as_str(),
        crate::services::cas::CAS_VERSION,
        &hash[..2],
        &hash[2..]
    ))
}

/// Claim an artifact for processing, or resolve it to the CAS hash of an
/// upload another task finished earlier this run.
///
/// Returns `Some(hash)` when these coordinates were already uploaded — the
/// caller should point the library at the existing CAS object (see
/// [`build_cas_url`]) and skip processing. Returns `None` when the caller
/// must source and upload the bytes itself: either this is the first claim,
/// or the artifact is claimed but its hash is not recorded yet because the
/// first claimer hasn't finished uploading. Uploading again in that window
/// is safe — identical bytes hash to the same CAS object — whereas emitting
/// a URL before its object exists would publish a dangling reference.
pub fn claim_or_reuse(
    visited: &dashmap::DashSet<daedalus::GradleSpecifier>,
    hashes: &dashmap::DashMap<daedalus::GradleSpecifier, String>,
    name: &daedalus::GradleSpecifier,
) -> Option<String> {
    if visited.insert(name.clone()) {
        return None;
    }
    hashes.get(name).map(|entry| entry.value().clone())
}

/// Point a library's download location at `url`: the artifact entry when the
/// library uses the `downloads` form, otherwise the maven-style `url` field
/// when one was set. A library with neither is left untouched.
pub fn set_library_url(lib: &mut daedalus::minecraft::Library, url: String) {
    if let Some(artifact) =
        lib.downloads.as_mut().and_then(|d| d.artifact.as_mut())
    {
        artifact.url = Some(url);
    } else if lib.url.is_some() {
        lib.url = Some(url);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hash_from_cas_url() {
        // Valid CAS URL
        let url = "https://example.com/v4/objects/ab/cdef123456";
        assert_eq!(
            extract_hash_from_cas_url(url),
            Some("abcdef123456".to_string())
        );

        // Different hash
        let url = "https://example.com/v4/objects/12/34567890abcd";
        assert_eq!(
            extract_hash_from_cas_url(url),
            Some("1234567890abcd".to_string())
        );

        // Invalid URL (not enough parts)
        let url = "https://example.com/objects/ab";
        assert_eq!(extract_hash_from_cas_url(url), None);

        // Invalid URL (no slashes)
        let url = "invalid-url";
        assert_eq!(extract_hash_from_cas_url(url), None);
    }

    #[test]
    fn test_claim_or_reuse_claim_then_race_then_reuse() {
        let visited = dashmap::DashSet::new();
        let hashes = dashmap::DashMap::new();
        let name: daedalus::GradleSpecifier =
            "org.example:lib:1.0".try_into().unwrap();

        // First claim: caller must process the artifact itself.
        assert_eq!(claim_or_reuse(&visited, &hashes, &name), None);
        // Claimed but no hash recorded (claimer still uploading): caller
        // must process rather than emit a URL for a missing object.
        assert_eq!(claim_or_reuse(&visited, &hashes, &name), None);
        // Hash recorded: subsequent callers reuse it.
        hashes.insert(name.clone(), "abcdef123456".to_string());
        assert_eq!(
            claim_or_reuse(&visited, &hashes, &name),
            Some("abcdef123456".to_string())
        );
    }

    #[test]
    fn test_set_library_url_prefers_artifact_over_url_field() {
        let mut with_artifact: daedalus::minecraft::Library =
            serde_json::from_value(serde_json::json!({
                "name": "org.example:lib:1.0",
                "downloads": {
                    "artifact": {
                        "path": "org/example/lib/1.0/lib-1.0.jar",
                        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "size": 1,
                        "url": "https://upstream.example/lib-1.0.jar"
                    }
                },
                "url": "https://maven.example/"
            }))
            .unwrap();
        set_library_url(&mut with_artifact, "https://cas.example/x".into());
        assert_eq!(
            with_artifact
                .downloads
                .unwrap()
                .artifact
                .unwrap()
                .url
                .as_deref(),
            Some("https://cas.example/x")
        );
        // The maven-style field is the fallback form; it stays untouched
        // when the artifact entry exists.
        assert_eq!(with_artifact.url.as_deref(), Some("https://maven.example/"));

        let mut url_only: daedalus::minecraft::Library =
            serde_json::from_value(serde_json::json!({
                "name": "org.example:lib:1.0",
                "url": "https://maven.example/"
            }))
            .unwrap();
        set_library_url(&mut url_only, "https://cas.example/y".into());
        assert_eq!(url_only.url.as_deref(), Some("https://cas.example/y"));

        let mut sourceless: daedalus::minecraft::Library =
            serde_json::from_value(serde_json::json!({
                "name": "org.example:lib:1.0"
            }))
            .unwrap();
        set_library_url(&mut sourceless, "https://cas.example/z".into());
        assert_eq!(sourceless.url, None);
        assert!(sourceless.downloads.is_none());
    }
}
