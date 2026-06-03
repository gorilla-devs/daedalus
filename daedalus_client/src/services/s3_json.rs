//! Small helpers for the admin JSON documents stored on S3 (pins, run-state,
//! control acks). Centralises the `get_object` → 404/parse/fetch → fallback
//! load pattern and the `to_vec_pretty` → `put_object` save pattern that these
//! advisory documents share.
//!
//! `control.json` itself does NOT use `load_or_else`: a parse failure there
//! means real operator intents would be dropped, so it has a bespoke
//! schema-version-aware loader that logs at `error!` (see `control::load`).

use serde::{de::DeserializeOwned, Serialize};
use tracing::{info, warn};

/// Load a JSON document from S3, falling back to `default()` on 404, a parse
/// error, or a fetch error. `label` is used only in log lines.
///
/// The fallback is supplied as a constructor (rather than a `Default` bound) so
/// callers whose `new()` differs from the derived `Default` — e.g. it seeds a
/// non-zero `schema_version` — get the right value.
pub async fn load_or_else<T: DeserializeOwned>(
    bucket: &s3::Bucket,
    path: &str,
    label: &str,
    default: impl Fn() -> T,
) -> T {
    match bucket.get_object(path).await {
        Ok(resp) => match serde_json::from_slice::<T>(resp.bytes()) {
            Ok(v) => {
                info!(path = %path, "Loaded {} from S3", label);
                v
            }
            Err(e) => {
                warn!(path = %path, error = %e, "Failed to parse {}; using default", label);
                default()
            }
        },
        Err(s3::error::S3Error::Http(404, _)) => {
            info!(path = %path, "No {} on S3 yet; using default", label);
            default()
        }
        Err(e) => {
            warn!(path = %path, error = %e, "Failed to fetch {}; using default", label);
            default()
        }
    }
}

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
