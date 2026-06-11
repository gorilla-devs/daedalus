//! Small helpers for the admin JSON documents stored on S3 (pins, run-state,
//! control acks). Centralises the `to_vec_pretty` → `put_object` save pattern
//! these advisory documents share. Loading stays per-document: each admin file
//! has its own failure semantics (run-state reuses the process's last known
//! copy on transient errors, control acks refuse the poll, control.json logs
//! at `error!` with schema-version awareness).

use serde::Serialize;

/// Serialise `value` as pretty JSON and PUT it to `path` as `application/json`.
pub async fn save_json<T: Serialize>(
    bucket: &s3::Bucket,
    path: &str,
    value: &T,
) -> Result<(), crate::infrastructure::error::Error> {
    let bytes = serde_json::to_vec_pretty(value)?;
    bucket
        .put_object_with_content_type(path, &bytes, "application/json")
        .await
        .map_err(|e| crate::infrastructure::error::s3_error(e, path.to_string()))?;
    Ok(())
}
