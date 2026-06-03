use crate::infrastructure::error::Error;
use backon::{ExponentialBuilder, Retryable};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, instrument};

/// Retry tuning — matches the upload-side retry policy in main.rs / services/upload.rs.
const MAX_DOWNLOAD_RETRIES: usize = 5;
const MAX_DOWNLOAD_DELAY_SECS: u64 = 60;

/// Download a file with optional SHA1 verification.
///
/// Uses `daedalus::download_file_once` and runs the retry loop here so the
/// shared concurrency permit is acquired (and released) on each attempt.
/// Holding a permit across the full retry sequence (5 attempts × up to 60s
/// each) starves the upload pool — a stuck upstream could pin all 10
/// permits for ~5 minutes and deadlock the pipeline against itself.
///
/// # Arguments
/// * `url` - The URL to download from
/// * `sha1` - Optional SHA1 hash for verification
/// * `semaphore` - Shared concurrency limiter (released between retry attempts)
#[instrument(skip(semaphore))]
pub async fn download_file(
    url: &str,
    sha1: Option<&str>,
    semaphore: Arc<Semaphore>,
) -> Result<bytes::Bytes, Error> {
    info!(url = %url, has_sha1 = sha1.is_some(), "Started downloading");

    let val = (|| async {
        let _permit = semaphore.acquire().await?;
        daedalus::download_file_once(url, sha1)
            .await
            .map_err(Error::from)
    })
    .retry(
        ExponentialBuilder::default()
            .with_max_times(MAX_DOWNLOAD_RETRIES)
            .with_max_delay(Duration::from_secs(MAX_DOWNLOAD_DELAY_SECS)),
    )
    .when(|e: &Error| match e {
        // Mirror daedalus' classifier — only retry on transient failures.
        // (Can't delegate to `daedalus::should_retry_download` directly
        // because of the local `Error` wrapper; the predicate below is
        // structurally identical.)
        Error::Fetch { source, .. } => {
            if let Some(status) = source.status() {
                status.is_server_error()
                    || status.as_u16() == 429
                    || status.as_u16() == 408
            } else {
                source.is_timeout()
                    || source.is_connect()
                    || source.is_request()
                    || source.is_body()
            }
        }
        Error::ChecksumFailure { .. } => true,
        // `daedalus::Error` is wrapped via `From` impl; classify the inner.
        Error::Daedalus(inner) => daedalus::should_retry_download(inner),
        _ => false,
    })
    .await?;

    info!(url = %url, "Download completed");
    Ok(val)
}

/// Download a file from multiple mirror URLs with automatic fallback.
///
/// Tries each mirror in order, falling through to the next on a non-retryable
/// failure. The retry+permit wrapping happens inside the per-mirror
/// `download_file` call, so the semaphore is correctly released between
/// retry attempts within a single mirror as well as between mirrors.
///
/// # Arguments
/// * `base` - The base path to append to each mirror URL
/// * `mirrors` - Array of mirror base URLs to try
/// * `sha1` - Optional SHA1 hash for verification
/// * `semaphore` - Semaphore for limiting concurrent downloads
#[instrument(skip(semaphore), fields(mirror_count = mirrors.len()))]
pub async fn download_file_mirrors(
    base: &str,
    mirrors: &[&str],
    sha1: Option<&str>,
    semaphore: Arc<Semaphore>,
) -> Result<bytes::Bytes, Error> {
    if mirrors.is_empty() {
        return Err(crate::infrastructure::error::invalid_input(
            "No mirrors provided",
        ));
    }

    info!(base = %base, mirror_count = mirrors.len(), "Trying mirrors");
    let mut last_err: Option<Error> = None;
    for (idx, mirror) in mirrors.iter().enumerate() {
        let url = format!("{}{}", mirror, base);
        match download_file(&url, sha1, semaphore.clone()).await {
            Ok(bytes) => {
                info!(base = %base, mirror_idx = idx, "Mirror succeeded");
                return Ok(bytes);
            }
            Err(e) => {
                tracing::warn!(
                    base = %base,
                    mirror_idx = idx,
                    error = %e,
                    "Mirror failed, trying next"
                );
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        crate::infrastructure::error::invalid_input("No mirrors succeeded")
    }))
}
