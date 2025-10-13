use crate::infrastructure::error::Error;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{info, instrument};

/// Download a file with optional SHA1 verification
///
/// This function wraps the daedalus library's download_file function,
/// adding semaphore-based concurrency control and structured logging.
///
/// # Arguments
///
/// * `url` - The URL to download from
/// * `sha1` - Optional SHA1 hash for verification
/// * `semaphore` - Semaphore for limiting concurrent downloads
///
/// # Returns
///
/// The downloaded file contents as bytes
#[instrument(skip(semaphore))]
pub async fn download_file(
    url: &str,
    sha1: Option<&str>,
    semaphore: Arc<Semaphore>,
) -> Result<bytes::Bytes, Error> {
    let _permit = semaphore.acquire().await?;
    info!(url = %url, has_sha1 = sha1.is_some(), "Started downloading");
    let val = daedalus::download_file(url, sha1).await?;
    info!(url = %url, "Download completed");
    Ok(val)
}

/// Download a file from multiple mirror URLs with automatic fallback
///
/// This function wraps the daedalus library's download_file_mirrors function,
/// adding semaphore-based concurrency control and structured logging.
/// It will try each mirror in order until one succeeds.
///
/// # Arguments
///
/// * `base` - The base path to append to each mirror URL
/// * `mirrors` - Array of mirror base URLs to try
/// * `sha1` - Optional SHA1 hash for verification
/// * `semaphore` - Semaphore for limiting concurrent downloads
///
/// # Returns
///
/// The downloaded file contents as bytes
#[instrument(skip(semaphore), fields(mirror_count = mirrors.len()))]
pub async fn download_file_mirrors(
    base: &str,
    mirrors: &[&str],
    sha1: Option<&str>,
    semaphore: Arc<Semaphore>,
) -> Result<bytes::Bytes, Error> {
    let _permit = semaphore.acquire().await?;
    info!(base = %base, has_sha1 = sha1.is_some(), "Started downloading from mirrors");
    let val = daedalus::download_file_mirrors(base, mirrors, sha1).await?;
    info!(base = %base, "Download from mirrors completed");
    Ok(val)
}
