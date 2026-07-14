//! Small helpers for the admin JSON documents stored on S3 (pins, run-state,
//! control acks). Centralises the `to_vec_pretty` → `put_object` save pattern
//! these advisory documents share. Loading stays per-document: each admin file
//! has its own failure semantics (run-state reuses the process's last known
//! copy on transient errors, control acks refuse the poll, control.json logs
//! at `error!` with schema-version awareness).

use backon::{ExponentialBuilder, Retryable};
use serde::Serialize;
use std::time::Duration;

/// Serialise `value` as pretty JSON and PUT it to `path` as `application/json`.
///
/// Transient S3 errors are retried with the same policy as the CAS/manifest
/// uploads (5 attempts, 60s cap, `should_retry` classifier). These admin
/// documents (pins, run_state, control_acks) gate idempotency and pin state,
/// so a single 5xx/network blip silently dropping a write can, for example,
/// let an already-applied rollback re-execute on the next control poll.
pub async fn save_json<T: Serialize>(
    bucket: &s3::Bucket,
    path: &str,
    value: &T,
) -> Result<(), crate::infrastructure::error::Error> {
    let bytes = serde_json::to_vec_pretty(value)?;
    (|| async {
        bucket
            .put_object_with_content_type(path, &bytes, "application/json")
            .await
            .map_err(|e| {
                crate::infrastructure::error::s3_error(e, path.to_string())
            })
    })
    .retry(
        ExponentialBuilder::default()
            .with_max_times(5)
            .with_max_delay(Duration::from_secs(60)),
    )
    .when(|e: &crate::infrastructure::error::Error| e.should_retry())
    .await?;
    Ok(())
}
