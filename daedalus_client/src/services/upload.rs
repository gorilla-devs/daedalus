use backon::{ExponentialBuilder, Retryable};
use s3::Bucket;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{error, info, instrument};

/// Batch uploader for immediate CAS (Content-Addressable Storage) uploads
///
/// This uploader handles immediate uploads of content to S3 using content-addressable storage.
/// Files are stored by their SHA256 hash at v{CAS_VERSION}/objects/{hash[0..2]}/{hash[2..]}.
///
/// Benefits:
/// - **Immediate uploads**: No queuing, files upload as soon as requested
/// - **Deduplication**: Same content (same hash) = same storage location, uploaded once
/// - **Immutability**: Content never changes, only manifest pointers
/// - **Reproducibility**: Hash is deterministic from file content
///
/// # Example
///
/// ```no_run
/// let uploader = BatchUploader::new();
///
/// // Upload content to CAS and get its hash
/// let hash = uploader.upload_cas(
///     vec![1, 2, 3],
///     Some("application/json".to_string()),
///     &s3_client,
///     semaphore.clone()
/// ).await?;
///
/// // Hash can be used in manifests to reference the content
/// println!("Content stored at hash: {}", hash);
/// ```
pub struct BatchUploader;

impl BatchUploader {
    /// Create a new batch uploader
    pub fn new() -> Self {
        Self
    }

    /// Compute SHA256 hash of content
    ///
    /// This hash is used as the content-addressable identifier for CAS storage.
    pub fn compute_hash(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }

    /// Upload content to CAS immediately and return its hash
    ///
    /// Content is uploaded to v{CAS_VERSION}/objects/{hash[0..2]}/{hash[2..]}.
    /// The hash is computed from the content's SHA256 and returned immediately.
    ///
    /// The upload happens concurrently (limited by semaphore) and will retry on failure.
    ///
    /// # Arguments
    ///
    /// * `content` - The file content to upload
    /// * `content_type` - Optional MIME type (e.g., "application/json")
    /// * `s3_client` - S3 bucket client
    /// * `semaphore` - Semaphore for concurrent upload limiting
    ///
    /// # Returns
    ///
    /// The SHA256 hash of the content, which serves as its CAS identifier
    ///
    /// # Errors
    ///
    /// Returns error if upload fails after retries
    #[instrument(skip(self, content, s3_client, semaphore), fields(size = content.len()))]
    pub async fn upload_cas(
        &self,
        content: Vec<u8>,
        content_type: Option<String>,
        s3_client: &Bucket,
        semaphore: Arc<Semaphore>,
    ) -> Result<String, crate::infrastructure::error::Error> {
        let hash = Self::compute_hash(&content);
        let path = format!(
            "v{}/objects/{}/{}",
            crate::services::cas::CAS_VERSION,
            &hash[..2],
            &hash[2..]
        );

        info!(hash = %hash, path = %path, "Uploading to CAS");

        upload_single_file(
            &path,
            &content,
            content_type.as_deref(),
            s3_client,
            semaphore,
        )
        .await?;

        info!(hash = %hash, "CAS upload completed");
        Ok(hash)
    }
}

impl Default for BatchUploader {
    fn default() -> Self {
        Self::new()
    }
}

/// Upload a single file to S3 with retry logic
///
/// Internal helper function that handles the actual S3 upload with
/// exponential backoff retry on failure.
///
/// # Arguments
///
/// * `path` - S3 object path
/// * `bytes` - File content
/// * `content_type` - Optional MIME type
/// * `s3_client` - S3 bucket client
/// * `semaphore` - Semaphore for concurrent upload limiting
#[instrument(skip(bytes, s3_client, semaphore), fields(size = bytes.len()))]
async fn upload_single_file(
    path: &str,
    bytes: &[u8],
    content_type: Option<&str>,
    s3_client: &Bucket,
    semaphore: Arc<Semaphore>,
) -> Result<(), crate::infrastructure::error::Error> {
    let _permit = semaphore.acquire().await?;

    info!(path = %path, "Started uploading");

    (|| async {
        let result = if let Some(content_type) = content_type {
            s3_client
                .put_object_with_content_type(path.to_string(), bytes, content_type)
                .await
        } else {
            s3_client.put_object(path.to_string(), bytes).await
        }
        .map_err(|err| {
            error!(path = %path, error = %err, "Failed to upload");
            crate::infrastructure::error::s3_error(err, path.to_string())
        });

        match result {
            Ok(_) => {
                info!(path = %path, "Upload completed");
                Ok(())
            }
            Err(err) => {
                error!(path = %path, error = %err, "Upload failed");
                Err(err)
            }
        }
    })
    .retry(
        ExponentialBuilder::default()
            .with_max_times(10)
            .with_max_delay(Duration::from_secs(1800)),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_uploader_creation() {
        let uploader = BatchUploader::new();
        // Uploader is stateless, just verify it can be created
        let _ = uploader;
    }

    #[test]
    fn test_compute_hash() {
        let content = b"hello world";
        let hash = BatchUploader::compute_hash(content);

        // SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let content = vec![1, 2, 3];
        let hash1 = BatchUploader::compute_hash(&content);
        let hash2 = BatchUploader::compute_hash(&content);

        // Same content should always produce same hash (reproducibility)
        assert_eq!(hash1, hash2);
        assert_eq!(
            hash1,
            "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"
        );
    }

    #[test]
    fn test_different_content_different_hash() {
        let hash1 = BatchUploader::compute_hash(&[1]);
        let hash2 = BatchUploader::compute_hash(&[2]);
        let hash3 = BatchUploader::compute_hash(&[3]);

        // Different content should produce different hashes
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_length() {
        let hash = BatchUploader::compute_hash(b"test");
        // SHA256 produces 64 hex characters
        assert_eq!(hash.len(), 64);
    }
}
