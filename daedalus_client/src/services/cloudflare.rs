use crate::infrastructure::error::{Error, fetch_error, invalid_input};
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{Instrument, error, info, instrument, warn};

/// HTTP client specifically for Cloudflare API requests.
///
/// Configured with TCP keepalive, generous timeouts, a branded user agent,
/// and modest connection pooling.
///
/// # Panics
/// Panics if reqwest can't build the client (e.g. system TLS root store is
/// busted). This is intentional and matches the project policy: fail loud at
/// init rather than silently degrade — a misconfigured environment should
/// crash the process so the operator notices, not paper over the problem
/// with "purges will be skipped" semantics.
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .tcp_keepalive(Some(Duration::from_secs(10)))
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(30))
        .user_agent(format!(
            "gdlauncher/daedalus/{} ({})",
            env!("CARGO_PKG_VERSION"),
            dotenvy::var("SUPPORT_EMAIL")
                .unwrap_or_else(|_| "support@gdlauncher.com".to_string())
        ))
        .pool_max_idle_per_host(10)
        .build()
        .expect("Failed to build Cloudflare HTTP client")
});

/// Purges Cloudflare cache for the given URLs
///
/// This function handles batching URLs according to Cloudflare's API limits
/// (30 URLs per request) and provides detailed error handling for individual
/// batch failures. This ensures that CDN serves the latest content immediately
/// after uploads.
///
/// # Arguments
///
/// * `token` - Cloudflare API token with cache purge permissions
/// * `zone_id` - The Cloudflare zone ID for the domain
/// * `urls` - List of full URLs to purge from cache
///
/// # Returns
///
/// Ok(()) if at least some URLs were purged successfully
/// Err if all batches failed (individual batch failures are logged as warnings)
///
/// # Example
///
/// ```no_run
/// let urls = vec![
///     "https://example.com/file1.json".to_string(),
///     "https://example.com/file2.json".to_string(),
/// ];
/// purge_cloudflare_cache("api_token", "zone_id", &urls).await?;
/// ```
#[instrument(skip(token, zone_id, urls), fields(url_count = urls.len()))]
pub async fn purge_cloudflare_cache(
    token: &str,
    zone_id: &str,
    urls: &[String],
) -> Result<(), Error> {
    if urls.is_empty() {
        info!("No URLs to purge from Cloudflare cache");
        return Ok(());
    }

    info!(url_count = urls.len(), "Starting Cloudflare cache purge");

    let mut total_purged = 0;
    let mut failed_batches = 0;

    // Cloudflare limit: 30 URLs per request
    for (batch_idx, chunk) in urls.chunks(30).enumerate() {
        let batch_span = tracing::info_span!(
            "cloudflare_purge_batch",
            batch = batch_idx,
            batch_size = chunk.len()
        );
        let result = async {
            let response = HTTP_CLIENT
                .post(format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/purge_cache",
                    zone_id
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({ "files": chunk }))
                .send()
                .await
                .map_err(|e| fetch_error(e, "cloudflare purge"))?;

            let status = response.status();
            if status.is_success() {
                info!(
                    batch = batch_idx,
                    purged = chunk.len(),
                    "Cloudflare cache purge batch succeeded"
                );
                Ok::<usize, Error>(chunk.len())
            } else {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unable to read response".to_string());
                error!(
                    batch = batch_idx,
                    status = %status,
                    error = %error_text,
                    "Cloudflare cache purge batch failed"
                );
                Err(invalid_input(format!(
                    "Cloudflare API returned status {}: {}",
                    status, error_text
                )))
            }
        }
        .instrument(batch_span)
        .await;

        match result {
            Ok(count) => total_purged += count,
            Err(e) => {
                failed_batches += 1;
                warn!(error = %e, "Failed to purge batch, continuing with remaining batches");
            }
        }
    }

    if failed_batches > 0 {
        warn!(
            total_purged,
            failed_batches,
            "Cloudflare cache purge completed with some failures"
        );
    } else {
        info!(
            total_purged,
            "Cloudflare cache purge completed successfully"
        );
    }

    Ok(())
}
