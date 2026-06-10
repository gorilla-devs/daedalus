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
/// Ok(()) if at least some URLs were purged successfully (partial batch
/// failures are logged as warnings).
/// Err when every batch failed — callers must not report the purge as done.
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
        // Purges are idempotent, so a transiently failed batch gets one
        // retry — without it a single 5xx/network blip leaves the edge
        // serving the previous root for the full cache TTL.
        let mut result = purge_batch(token, zone_id, chunk, batch_idx).await;
        if let Err((e, transient)) = &result {
            if *transient {
                warn!(
                    batch = batch_idx,
                    error = %e,
                    "Cloudflare purge batch failed transiently; retrying once"
                );
                result = purge_batch(token, zone_id, chunk, batch_idx).await;
            }
        }

        match result {
            Ok(count) => total_purged += count,
            Err((e, _)) => {
                failed_batches += 1;
                warn!(error = %e, "Failed to purge batch, continuing with remaining batches");
            }
        }
    }

    if failed_batches > 0 && total_purged == 0 {
        return Err(invalid_input(format!(
            "Cloudflare cache purge failed for all {} batch(es)",
            failed_batches
        )));
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

/// Issue one purge request for up to 30 URLs. The boolean in the error tuple
/// marks transient failures (network errors, 5xx, 429) that are worth one
/// retry, as opposed to permanent ones (bad token, malformed request).
async fn purge_batch(
    token: &str,
    zone_id: &str,
    chunk: &[String],
    batch_idx: usize,
) -> Result<usize, (Error, bool)> {
    let batch_span = tracing::info_span!(
        "cloudflare_purge_batch",
        batch = batch_idx,
        batch_size = chunk.len()
    );
    async {
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
            .map_err(|e| (fetch_error(e, "cloudflare purge"), true))?;

        let status = response.status();
        if status.is_success() {
            info!(
                batch = batch_idx,
                purged = chunk.len(),
                "Cloudflare cache purge batch succeeded"
            );
            Ok(chunk.len())
        } else {
            let transient =
                status.is_server_error() || status.as_u16() == 429;
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
            Err((
                invalid_input(format!(
                    "Cloudflare API returned status {}: {}",
                    status, error_text
                )),
                transient,
            ))
        }
    }
    .instrument(batch_span)
    .await
}
