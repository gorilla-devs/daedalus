//! Content-Addressable Storage (CAS) utilities
//!
//! This module provides common functions for working with the CAS system,
//! including URL building and hash extraction.

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
/// * `hash` - The content hash to build a URL for
///
/// # Returns
///
/// The complete CAS URL
///
/// # Example
///
/// ```
/// let hash = "abcdef123456";
/// let url = build_cas_url(hash);
/// // Returns: "{BASE_URL}/v{CAS_VERSION}/objects/ab/cdef123456"
/// ```
pub fn build_cas_url(hash: &str) -> String {
    let base_url = dotenvy::var("BASE_URL").expect("BASE_URL must be set");
    format!(
        "{}/v{}/objects/{}/{}",
        base_url,
        crate::services::cas::CAS_VERSION,
        &hash[..2],
        &hash[2..]
    )
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
}
