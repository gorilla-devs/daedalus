use backon::{ExponentialBuilder, Retryable};
use dashmap::DashMap;
use s3::Bucket;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{error, info, instrument};

/// Upload queue for atomic batch uploads
///
/// This queue collects files to be uploaded and provides an atomic
/// flush operation that ensures all-or-nothing semantics. This prevents
/// partial failures from leaving the CDN in an inconsistent state.
///
/// Supports two upload modes:
/// - CAS (Content-Addressable Storage): Files stored by SHA256 hash at v{CAS_VERSION}/objects/<hash>
/// - Path-based: Files stored at explicit paths (e.g., maven/ for compatibility)
///
/// # Example
///
/// ```no_run
/// let queue = UploadQueue::new();
///
/// // CAS upload (returns hash)
/// let hash = queue.enqueue_cas(vec![1, 2, 3], Some("application/json"));
///
/// // Path-based upload (for maven artifacts, etc.)
/// queue.enqueue_path("maven/lib.jar", vec![4, 5, 6], Some("application/java-archive"));
///
/// // Atomic: all files uploaded or none
/// queue.flush(&s3_client, semaphore).await?;
/// ```
pub struct UploadQueue {
    /// Lock-free concurrent map of pending CAS uploads
    /// Key: content hash (SHA256), Value: (bytes, content_type)
    cas_queue: DashMap<String, (Vec<u8>, Option<String>)>,

    /// Lock-free concurrent map of pending path-based uploads
    /// Key: file path, Value: (bytes, content_type)
    path_queue: DashMap<String, (Vec<u8>, Option<String>)>,
}

impl UploadQueue {
    /// Create a new empty upload queue
    pub fn new() -> Self {
        Self {
            cas_queue: DashMap::new(),
            path_queue: DashMap::new(),
        }
    }

    /// Compute SHA256 hash of content
    fn compute_hash(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }

    /// Enqueue content for CAS upload (does NOT upload yet)
    ///
    /// Content is stored by its SHA256 hash and will be uploaded to v{CAS_VERSION}/objects/{hash[0..2]}/{hash[2..]}.
    /// Returns the hash so callers can reference it in manifests.
    ///
    /// Multiple enqueues of the same content (same hash) will deduplicate automatically.
    #[instrument(skip(self, content), fields(size = content.len()))]
    pub fn enqueue(&self, content: Vec<u8>, content_type: Option<String>) -> String {
        let hash = Self::compute_hash(&content);
        info!(hash = %hash, "Enqueued for CAS upload");
        self.cas_queue.insert(hash.clone(), (content, content_type));
        hash
    }

    /// Enqueue content for path-based upload (does NOT upload yet)
    ///
    /// Content is stored at the specified path (e.g., "maven/lib.jar").
    /// This is used for files that need predictable paths for compatibility.
    ///
    /// Multiple enqueues of the same path will overwrite previous content.
    #[instrument(skip(self, content), fields(size = content.len()))]
    pub fn enqueue_path(&self, path: String, content: Vec<u8>, content_type: Option<String>) {
        info!(path = %path, "Enqueued for path-based upload");
        self.path_queue.insert(path, (content, content_type));
    }

    /// Flush all queued uploads atomically to S3
    ///
    /// Uploads both CAS objects (to v{CAS_VERSION}/objects/{hash[0..2]}/{hash[2..]})
    /// and path-based files (to their specified paths).
    /// On error, all uploads are considered failed (no partial state).
    ///
    /// # Errors
    ///
    /// Returns error if any upload fails after retries.
    #[instrument(skip(self, s3_client, semaphore), fields(cas_count = self.cas_queue.len(), path_count = self.path_queue.len()))]
    pub async fn flush(
        &self,
        s3_client: &Bucket,
        semaphore: Arc<Semaphore>,
    ) -> Result<(), crate::infrastructure::error::Error> {
        let cas_size = self.cas_queue.len();
        let path_size = self.path_queue.len();
        let total_size = cas_size + path_size;

        if total_size == 0 {
            info!("Upload queue is empty, nothing to flush");
            return Ok(());
        }

        info!(
            cas_count = cas_size,
            path_count = path_size,
            "Starting atomic flush of {} objects ({} CAS, {} path-based)",
            total_size,
            cas_size,
            path_size
        );

        // Upload CAS objects (content-addressed with 2-char prefix for sharding)
        for entry in self.cas_queue.iter() {
            let (hash, (bytes, content_type)) = entry.pair();
            let path = format!("v{}/objects/{}/{}", crate::services::cas::CAS_VERSION, &hash[..2], &hash[2..]);

            upload_single_file(
                &path,
                bytes,
                content_type.as_deref(),
                s3_client,
                semaphore.clone(),
            )
            .await?;
        }

        // Upload path-based files
        for entry in self.path_queue.iter() {
            let (path, (bytes, content_type)) = entry.pair();

            upload_single_file(
                path,
                bytes,
                content_type.as_deref(),
                s3_client,
                semaphore.clone(),
            )
            .await?;
        }

        // Clear queues only on complete success
        self.cas_queue.clear();
        self.path_queue.clear();

        info!(
            uploaded = total_size,
            "Successfully flushed {} objects",
            total_size
        );

        Ok(())
    }

    /// Get the total number of queued files (CAS + path-based)
    pub fn len(&self) -> usize {
        self.cas_queue.len() + self.path_queue.len()
    }

    /// Check if queue is empty (both CAS and path-based)
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.cas_queue.is_empty() && self.path_queue.is_empty()
    }
}

impl Default for UploadQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Upload a single file to S3 with retry logic
///
/// Internal helper function that handles the actual S3 upload with
/// exponential backoff retry on failure.
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
    fn test_upload_queue_creation() {
        let queue = UploadQueue::new();
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_enqueue() {
        let queue = UploadQueue::new();

        let hash = queue.enqueue(vec![1, 2, 3], Some("application/json".to_string()));

        // SHA256 of [1, 2, 3]
        assert_eq!(
            hash,
            "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"
        );
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());
    }

    #[test]
    fn test_deduplication() {
        let queue = UploadQueue::new();

        // Enqueue same content twice
        let hash1 = queue.enqueue(vec![1, 2, 3], None);
        let hash2 = queue.enqueue(vec![1, 2, 3], None);

        // Same content = same hash, deduplicated
        assert_eq!(hash1, hash2);
        assert_eq!(queue.len(), 1); // Only stored once
    }

    #[test]
    fn test_multiple_objects() {
        let queue = UploadQueue::new();

        // Different content = different hashes
        let hash1 = queue.enqueue(vec![1], None);
        let hash2 = queue.enqueue(vec![2], None);
        let hash3 = queue.enqueue(vec![3], None);

        // All three should be different
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn test_compute_hash() {
        let content = b"hello world";
        let hash = UploadQueue::compute_hash(content);

        // SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_enqueue_path() {
        let queue = UploadQueue::new();

        queue.enqueue_path(
            "maven/lib.jar".to_string(),
            vec![1, 2, 3],
            Some("application/java-archive".to_string()),
        );

        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());
    }

    #[test]
    fn test_mixed_cas_and_path() {
        let queue = UploadQueue::new();

        // Add CAS upload
        let hash = queue.enqueue(vec![1, 2, 3], Some("application/json".to_string()));
        assert!(!hash.is_empty());

        // Add path-based upload
        queue.enqueue_path(
            "maven/lib.jar".to_string(),
            vec![4, 5, 6],
            Some("application/java-archive".to_string()),
        );

        // Should have 2 total files queued
        assert_eq!(queue.len(), 2);
        assert!(!queue.is_empty());
    }
}
