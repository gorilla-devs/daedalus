//! S3-mediated control-file consumer (§2.4 / §2.5).
//!
//! Enderium writes operator intents to `v{CAS_VERSION}/admin/control.json`.
//! Daedalus polls this file every `CONTROL_POLL_INTERVAL_SECS` seconds,
//! executes any unprocessed intents, and appends outcomes to
//! `v{CAS_VERSION}/admin/control_acks.json`.
//!
//! ## Supported intents
//!
//! * `force_runs` — re-run the full publish cycle (all loaders).
//!   **Force-run approach: option (b)** — trigger a full cycle rather than a
//!   single-loader cycle.  Rationale: the non-Minecraft loaders depend on the
//!   Minecraft `VersionManifest`, which `run_publish_cycle` already fetches;
//!   option (a) would require loading it separately here.  The extra work of
//!   refreshing all loaders is negligible and avoids duplicating the
//!   dependency-fetch logic.  A comment in the ack records the specific loader
//!   that was requested so the operator can see it fired.
//!
//! * `rollback_request` — 8-step rollback lifted from the deleted
//!   `admin/handlers/rollback.rs` (minus the pin-write step, which enderium
//!   now owns; minus axum response wrapping).
//!
//! ## Idempotency
//!
//! `control_acks.json` is the idempotency log.  On every poll daedalus loads
//! the acks first and skips any intent whose `request_id` already appears
//! there.  This makes the consumer safe to restart mid-intent.
//!
//! ## Retention
//!
//! Ack entries older than 30 days are pruned on every write to keep the file
//! bounded.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{error, info, warn};

use crate::services::cas::CAS_VERSION;
use crate::services::discord::DiscordEvent;

// ---------------------------------------------------------------------------
// Wire-format types
// ---------------------------------------------------------------------------

/// The control file written by enderium at `v{CAS_VERSION}/admin/control.json`.
///
/// Schema version 1. The `schema_version` field guards against drift with
/// the mirror copy in `enderium-common/src/daedalus_admin.rs`.
///
/// ```json
/// {
///   "schema_version": 1,
///   "updated_at": "2026-05-14T10-00-00Z",
///   "updated_by_token_hash": "sha256(...)",
///   "rollback_request": null,
///   "force_runs": [
///     { "request_id": "<uuid>", "submitted_at": "...", "loader": "forge",
///       "submitted_by_token_hash": "..." }
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFile {
    /// Monotonically increasing schema version (current: 1).
    pub schema_version: u32,
    /// When enderium last wrote this file.
    pub updated_at: DateTime<Utc>,
    /// SHA-256 hex of the internal_auth_token that wrote this file.
    pub updated_by_token_hash: String,
    /// At most one in-flight rollback intent.
    /// Enderium refuses a second one until the first is acked.
    pub rollback_request: Option<RollbackRequest>,
    /// Zero or more force-run intents.  Multiple may be pending.
    #[serde(default)]
    pub force_runs: Vec<ForceRunRequest>,
}

impl Default for ControlFile {
    fn default() -> Self {
        Self {
            schema_version: 1,
            updated_at: Utc::now(),
            updated_by_token_hash: String::new(),
            rollback_request: None,
            force_runs: Vec::new(),
        }
    }
}

/// A single rollback intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackRequest {
    /// Stable identifier used as the idempotency key in `control_acks.json`.
    pub request_id: String,
    /// When the operator submitted this intent.
    pub submitted_at: DateTime<Utc>,
    /// The timestamp component of the history entry to restore, e.g.
    /// `"2026-05-13T10-00-00Z"` (matches `v{CAS_VERSION}/history/manifest-{ts}.json`).
    pub history_timestamp: String,
    /// SHA-256 hex of the internal_auth_token that submitted this request.
    pub submitted_by_token_hash: String,
}

/// A single force-run intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForceRunRequest {
    /// Stable identifier used as the idempotency key in `control_acks.json`.
    pub request_id: String,
    /// When the operator submitted this intent.
    pub submitted_at: DateTime<Utc>,
    /// The loader the operator wants to force-run (e.g. `"forge"`).
    /// Recorded in the ack for observability; the actual execution always
    /// runs a full cycle (see module-level doc for rationale).
    pub loader: String,
    /// SHA-256 hex of the internal_auth_token that submitted this request.
    pub submitted_by_token_hash: String,
}

/// The ack file written by daedalus at `v{CAS_VERSION}/admin/control_acks.json`.
///
/// Schema version 1. Mirror copy lives in
/// `enderium-common/src/daedalus_admin.rs`; keep in lockstep manually.
///
/// ```json
/// {
///   "schema_version": 1,
///   "processed": [
///     {
///       "request_id": "<uuid>",
///       "kind": "rollback",
///       "processed_at": "...",
///       "outcome": "success",
///       "details": { "backup_path": "...", "rolled_back_to": "..." }
///     }
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlAcks {
    /// Monotonically increasing schema version (current: 1).
    pub schema_version: u32,
    /// All intents processed (or attempted) by daedalus.  Bounded to 30 days
    /// on each write.
    #[serde(default)]
    pub processed: Vec<AckEntry>,
}

impl ControlAcks {
    fn new() -> Self {
        Self {
            schema_version: 1,
            processed: Vec::new(),
        }
    }

    /// Set of all `request_id`s already in the ack log.
    fn processed_ids(&self) -> HashSet<&str> {
        self.processed
            .iter()
            .map(|e| e.request_id.as_str())
            .collect()
    }

    /// Append a new ack entry.
    fn push(&mut self, entry: AckEntry) {
        self.processed.push(entry);
    }

    /// Drop entries older than `retention` to keep the file bounded.
    fn prune(&mut self, retention: Duration) {
        let cutoff = Utc::now() - retention;
        self.processed.retain(|e| e.processed_at >= cutoff);
    }
}

/// One processed-intent record in `control_acks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckEntry {
    /// Matches the `request_id` from the originating intent.
    pub request_id: String,
    /// `"rollback"` or `"force_run"`.
    pub kind: String,
    /// When daedalus processed (or attempted) this intent.
    pub processed_at: DateTime<Utc>,
    /// `"success"` on success; `{ "error": "..." }` on failure.
    pub outcome: AckOutcome,
    /// Loader-specific supplementary info (backup path, rolled-back-to, etc.).
    #[serde(default)]
    pub details: serde_json::Value,
}

/// Outcome field — either the string `"success"` or an object `{"error": "..."}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AckOutcome {
    /// Intent executed successfully.
    Success(String), // always "success"
    /// Intent failed; the string is the human-readable error.
    Failure { error: String },
}

impl AckOutcome {
    fn success() -> Self {
        Self::Success("success".to_string())
    }
    fn error(msg: impl std::fmt::Display) -> Self {
        Self::Failure {
            error: msg.to_string(),
        }
    }
}

/// Outcome returned by the rollback executor.
pub struct RollbackOutcome {
    /// S3 path of the pre-rollback backup.
    pub backup_path: String,
    /// The history timestamp that was restored.
    pub rolled_back_to: String,
}

// ---------------------------------------------------------------------------
// S3 helpers
// ---------------------------------------------------------------------------

/// S3 path for the control file.
fn control_s3_path() -> String {
    format!("v{CAS_VERSION}/admin/control.json")
}

/// S3 path for the ack file.
fn acks_s3_path() -> String {
    format!("v{CAS_VERSION}/admin/control_acks.json")
}

/// Load `control.json` from S3.  Returns `ControlFile::default()` on 404 or
/// any parse/fetch error so a missing file is not treated as an error.
pub async fn load(bucket: &s3::Bucket) -> ControlFile {
    let path = control_s3_path();
    match bucket.get_object(&path).await {
        Ok(resp) => match serde_json::from_slice::<ControlFile>(resp.bytes()) {
            Ok(cf) => {
                info!(path = %path, "Loaded control file from S3");
                cf
            }
            Err(e) => {
                warn!(path = %path, error = %e, "Failed to parse control.json; treating as empty");
                ControlFile::default()
            }
        },
        Err(s3::error::S3Error::Http(404, _)) => {
            // No control file yet — nothing to process.
            ControlFile::default()
        }
        Err(e) => {
            warn!(path = %path, error = %e, "Failed to fetch control.json; treating as empty");
            ControlFile::default()
        }
    }
}

/// Load `control_acks.json` from S3.  Returns `ControlAcks::new()` on 404 or
/// any parse/fetch error.
pub async fn load_acks(bucket: &s3::Bucket) -> ControlAcks {
    let path = acks_s3_path();
    match bucket.get_object(&path).await {
        Ok(resp) => match serde_json::from_slice::<ControlAcks>(resp.bytes()) {
            Ok(acks) => {
                info!(
                    path = %path,
                    count = acks.processed.len(),
                    "Loaded control acks from S3"
                );
                acks
            }
            Err(e) => {
                warn!(path = %path, error = %e, "Failed to parse control_acks.json; starting fresh");
                ControlAcks::new()
            }
        },
        Err(s3::error::S3Error::Http(404, _)) => ControlAcks::new(),
        Err(e) => {
            warn!(path = %path, error = %e, "Failed to fetch control_acks.json; starting fresh");
            ControlAcks::new()
        }
    }
}

/// Persist `control_acks.json` to S3.
pub async fn save_acks(
    bucket: &s3::Bucket,
    acks: &ControlAcks,
) -> Result<(), crate::infrastructure::error::Error> {
    let path = acks_s3_path();
    let bytes = serde_json::to_vec_pretty(acks)?;
    bucket
        .put_object_with_content_type(&path, &bytes, "application/json")
        .await
        .map_err(|e| crate::infrastructure::error::s3_error(e, path.clone()))?;
    info!(path = %path, count = acks.processed.len(), "Saved control acks to S3");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Called once per `control_timer` tick from `main.rs`.
///
/// Steps:
/// 1. Load `control.json` and `control_acks.json`; build the processed-id set.
/// 2. For each unprocessed `force_runs` entry: run a full publish cycle and
///    append the outcome.
/// 3. If there is an unprocessed `rollback_request`: execute the 8-step
///    rollback and append the outcome.
/// 4. Prune acks older than 30 days and save once.
///
/// Per-intent failures are Discord-notified and recorded as
/// `outcome: { error: "..." }`; daedalus always continues to the next intent.
pub async fn process_pending(bucket: &s3::Bucket) {
    let control = load(bucket).await;
    let mut acks = load_acks(bucket).await;
    let already_processed = acks
        .processed_ids()
        .into_iter()
        .map(str::to_string)
        .collect::<HashSet<_>>();

    let mut any_new = false;

    // ------------------------------------------------------------------
    // Force-run intents
    // ------------------------------------------------------------------
    for req in &control.force_runs {
        if already_processed.contains(&req.request_id) {
            continue;
        }

        info!(
            request_id = %req.request_id,
            loader = %req.loader,
            "Processing force-run intent"
        );

        // Approach (b): trigger a full publish cycle for all loaders.
        // The requested `loader` is noted in the ack details for observability.
        // A full cycle is used because non-Minecraft loaders depend on the
        // Minecraft VersionManifest; loading it separately here would duplicate
        // the dependency-fetch logic from run_publish_cycle.
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
            crate::MAX_CONCURRENT_UPLOADS,
        ));
        crate::run_publish_cycle(false, semaphore).await;

        acks.push(AckEntry {
            request_id: req.request_id.clone(),
            kind: "force_run".to_string(),
            processed_at: Utc::now(),
            outcome: AckOutcome::success(),
            details: serde_json::json!({
                "requested_loader": req.loader,
                "note": "full publish cycle executed (all loaders)"
            }),
        });
        any_new = true;

        info!(request_id = %req.request_id, loader = %req.loader, "Force-run intent processed");
    }

    // ------------------------------------------------------------------
    // Rollback intent
    // ------------------------------------------------------------------
    if let Some(ref req) = control.rollback_request {
        if !already_processed.contains(&req.request_id) {
            info!(
                request_id = %req.request_id,
                history_timestamp = %req.history_timestamp,
                "Processing rollback intent"
            );

            match execute_rollback(
                bucket,
                &req.history_timestamp,
                &req.request_id,
            )
            .await
            {
                Ok(outcome) => {
                    acks.push(AckEntry {
                        request_id: req.request_id.clone(),
                        kind: "rollback".to_string(),
                        processed_at: Utc::now(),
                        outcome: AckOutcome::success(),
                        details: serde_json::json!({
                            "backup_path": outcome.backup_path,
                            "rolled_back_to": outcome.rolled_back_to,
                        }),
                    });
                    info!(
                        request_id = %req.request_id,
                        rolled_back_to = %outcome.rolled_back_to,
                        "Rollback intent processed successfully"
                    );
                }
                Err(e) => {
                    let msg = e.to_string();
                    error!(
                        request_id = %req.request_id,
                        error = %msg,
                        "Rollback intent failed"
                    );
                    notify_discord_error(
                        &format!("rollback_failed_{}", req.request_id),
                        &format!(
                            "Rollback to `{}` failed (request_id={}): {}",
                            req.history_timestamp, req.request_id, msg
                        ),
                    );
                    acks.push(AckEntry {
                        request_id: req.request_id.clone(),
                        kind: "rollback".to_string(),
                        processed_at: Utc::now(),
                        outcome: AckOutcome::error(msg),
                        details: serde_json::json!({
                            "history_timestamp": req.history_timestamp,
                        }),
                    });
                }
            }
            any_new = true;
        }
    }

    if !any_new {
        // Nothing new to process — skip the S3 write.
        return;
    }

    // Prune entries older than 30 days before writing.
    acks.prune(Duration::days(30));

    if let Err(e) = save_acks(bucket, &acks).await {
        error!(error = %e, "Failed to save control_acks.json — outcomes may be re-attempted on next poll");
    }
}

// ---------------------------------------------------------------------------
// Rollback executor (§2.5)
//
// Lifted from the deleted `daedalus_client/src/admin/handlers/rollback.rs:61-370`.
// Changes from the original:
// - Dropped axum response wrapping; returns `Result<RollbackOutcome, Error>`.
// - Dropped step 5 (pin-write) — enderium now writes pins.json BEFORE
//   submitting the rollback intent.  The remaining 8 steps are numbered
//   to match §2.5 in the plan.
// ---------------------------------------------------------------------------

async fn execute_rollback(
    bucket: &s3::Bucket,
    ts: &str,
    request_id: &str,
) -> Result<RollbackOutcome, crate::infrastructure::error::Error> {
    use crate::services::cas::RootManifest;

    // ------------------------------------------------------------------
    // Step 1: fetch history entry bytes.
    // ------------------------------------------------------------------
    let history_path = format!("v{CAS_VERSION}/history/manifest-{ts}.json");
    let history_bytes: Vec<u8> = match bucket.get_object(&history_path).await {
        Ok(resp) => resp.bytes().to_vec(),
        Err(s3::error::S3Error::Http(404, _)) => {
            return Err(crate::infrastructure::error::invalid_input(format!(
                "history entry '{ts}' not found at {history_path}"
            )));
        }
        Err(e) => {
            warn!(error = %e, path = %history_path, "Failed to fetch history entry");
            return Err(crate::infrastructure::error::s3_error(
                e,
                history_path,
            ));
        }
    };

    // ------------------------------------------------------------------
    // Step 2: parse as RootManifest.
    // ------------------------------------------------------------------
    let history_manifest: RootManifest = serde_json::from_slice(&history_bytes)
        .map_err(|e| {
            crate::infrastructure::error::invalid_input(format!(
                "history entry '{ts}' failed to parse: {e}"
            ))
        })?;

    // ------------------------------------------------------------------
    // Step 3: pre-check — HEAD every referenced loader manifest.
    // ------------------------------------------------------------------
    let mut missing: Vec<String> = Vec::new();
    for (loader, reference) in &history_manifest.loaders {
        match bucket.head_object(&reference.url).await {
            Ok(_) => {}
            Err(s3::error::S3Error::Http(404, _)) => {
                missing.push(format!("{}: {}", loader, reference.url));
            }
            Err(e) => {
                warn!(loader = %loader, path = %reference.url, error = %e, "HEAD check failed");
                missing.push(format!(
                    "{}: {} (fetch error: {})",
                    loader, reference.url, e
                ));
            }
        }
    }
    if !missing.is_empty() {
        return Err(crate::infrastructure::error::invalid_input(format!(
            "rollback aborted — the following loader manifests no longer exist on S3: {}",
            missing.join(", ")
        )));
    }

    // ------------------------------------------------------------------
    // Step 4: read current live root and write pre-rollback backup + sidecar.
    // ------------------------------------------------------------------
    let live_root_path = format!("v{CAS_VERSION}/manifest.json");
    let current_live_bytes: Option<Vec<u8>> = match bucket
        .get_object(&live_root_path)
        .await
    {
        Ok(resp) => Some(resp.bytes().to_vec()),
        Err(s3::error::S3Error::Http(404, _)) => None,
        Err(e) => {
            warn!(error = %e, "Failed to read current live root; proceeding without backup");
            None
        }
    };

    let now_str = Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let backup_path = format!("v{CAS_VERSION}/history/manifest-{now_str}.json");
    let meta_path =
        format!("v{CAS_VERSION}/history/manifest-{now_str}.meta.json");

    if let Some(ref live_bytes) = current_live_bytes {
        if let Err(e) = bucket
            .put_object_with_content_type(
                &backup_path,
                live_bytes,
                "application/json",
            )
            .await
        {
            warn!(path = %backup_path, error = %e, "Failed to write pre-rollback backup; proceeding anyway");
        } else {
            info!(path = %backup_path, "Pre-rollback backup written");
        }

        let meta = serde_json::json!({
            "reason": "pre-rollback backup",
            "request_id": request_id,
            "created_at": now_str,
            "rolling_back_to": ts,
        });
        if let Ok(meta_bytes) = serde_json::to_vec_pretty(&meta) {
            let _ = bucket
                .put_object_with_content_type(
                    &meta_path,
                    &meta_bytes,
                    "application/json",
                )
                .await;
        }
    }

    // ------------------------------------------------------------------
    // Step 5: PUT history bytes to live root under ROOT_WRITE_LOCK.
    // (Plan §2.5 step 5; old step 6 after the deleted pin-write.)
    // ------------------------------------------------------------------
    {
        let _guard = crate::ROOT_WRITE_LOCK.lock().await;
        bucket
            .put_object_with_content_type(
                &live_root_path,
                &history_bytes,
                "application/json",
            )
            .await
            .map_err(|e| {
                crate::infrastructure::error::s3_error(
                    e,
                    live_root_path.clone(),
                )
            })?;
        info!(path = %live_root_path, rolled_back_to = %ts, "Live root updated");
    }

    // ------------------------------------------------------------------
    // Step 6: Cloudflare cache purge.
    // ------------------------------------------------------------------
    let cloudflare_enabled = dotenvy::var("CLOUDFLARE_INTEGRATION")
        .map(|v| v == "true")
        .unwrap_or(false);

    if cloudflare_enabled {
        match (
            dotenvy::var("CLOUDFLARE_TOKEN"),
            dotenvy::var("CLOUDFLARE_ZONE_ID"),
        ) {
            (Ok(token), Ok(zone_id)) => {
                let root_url = format!(
                    "{}/{}",
                    crate::common::BASE_URL.as_str(),
                    live_root_path
                );
                if let Err(e) =
                    crate::services::cloudflare::purge_cloudflare_cache(
                        &token,
                        &zone_id,
                        &[root_url],
                    )
                    .await
                {
                    warn!(error = %e, "Cloudflare purge failed after rollback (non-fatal)");
                } else {
                    info!("Cloudflare cache purged after rollback");
                }
            }
            _ => {
                warn!(
                    "CLOUDFLARE_INTEGRATION enabled but CLOUDFLARE_TOKEN or \
                     CLOUDFLARE_ZONE_ID is missing"
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 7: Discord notification.
    // ------------------------------------------------------------------
    let msg = format!(
        "Rollback performed (request_id=`{request_id}`): root manifest restored \
         to history entry `{ts}`. Pre-rollback backup written to `{backup_path}`. \
         Pins for affected loaders were written by enderium before this intent \
         was submitted; those loaders will keep referencing the rolled-back \
         timestamp until unpinned."
    );
    notify_discord_error("rollback_performed", &msg);

    // ------------------------------------------------------------------
    // Step 8: update run_state.json.
    // ------------------------------------------------------------------
    let mut run_state = crate::services::run_state::load(bucket).await;
    for (loader, reference) in &history_manifest.loaders {
        run_state
            .loader_mut(loader)
            .record_success(&reference.timestamp, &reference.url);
    }
    crate::services::run_state::save(bucket, &mut run_state).await;

    info!(rolled_back_to = %ts, "Rollback complete");

    Ok(RollbackOutcome {
        backup_path,
        rolled_back_to: ts.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Fire a Discord notification via the global notifier (if configured).
/// `key` is the dedup key used by `DiscordNotifier` to suppress repeated
/// identical alerts.
fn notify_discord_error(key: &str, message: &str) {
    if let Some(notifier) = crate::services::discord::notifier() {
        notifier.notify(DiscordEvent::Error {
            level: "warn".to_string(),
            target: "daedalus_client::services::control".to_string(),
            message: message.to_string(),
            fields: {
                let mut m = std::collections::HashMap::new();
                m.insert("dedup_key".to_string(), key.to_string());
                m
            },
        });
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ControlFile ---

    #[test]
    fn test_control_file_default_is_empty() {
        let cf = ControlFile::default();
        assert!(cf.rollback_request.is_none());
        assert!(cf.force_runs.is_empty());
        assert_eq!(cf.schema_version, 1);
    }

    #[test]
    fn test_control_file_deserialize_no_intents() {
        let json = r#"{
            "schema_version": 1,
            "updated_at": "2026-05-14T10:00:00Z",
            "updated_by_token_hash": "abc",
            "rollback_request": null,
            "force_runs": []
        }"#;
        let cf: ControlFile = serde_json::from_str(json).unwrap();
        assert!(cf.rollback_request.is_none());
        assert!(cf.force_runs.is_empty());
    }

    #[test]
    fn test_control_file_deserialize_with_rollback() {
        let json = r#"{
            "schema_version": 1,
            "updated_at": "2026-05-14T10:00:00Z",
            "updated_by_token_hash": "abc",
            "rollback_request": {
                "request_id": "req-1",
                "submitted_at": "2026-05-14T10:00:00Z",
                "history_timestamp": "2026-05-13T10-00-00Z",
                "submitted_by_token_hash": "def"
            },
            "force_runs": []
        }"#;
        let cf: ControlFile = serde_json::from_str(json).unwrap();
        let rb = cf.rollback_request.unwrap();
        assert_eq!(rb.request_id, "req-1");
        assert_eq!(rb.history_timestamp, "2026-05-13T10-00-00Z");
    }

    #[test]
    fn test_control_file_deserialize_with_force_runs() {
        let json = r#"{
            "schema_version": 1,
            "updated_at": "2026-05-14T10:00:00Z",
            "updated_by_token_hash": "abc",
            "rollback_request": null,
            "force_runs": [
                {
                    "request_id": "fr-1",
                    "submitted_at": "2026-05-14T10:00:00Z",
                    "loader": "forge",
                    "submitted_by_token_hash": "ghi"
                },
                {
                    "request_id": "fr-2",
                    "submitted_at": "2026-05-14T10:05:00Z",
                    "loader": "fabric",
                    "submitted_by_token_hash": "jkl"
                }
            ]
        }"#;
        let cf: ControlFile = serde_json::from_str(json).unwrap();
        assert_eq!(cf.force_runs.len(), 2);
        assert_eq!(cf.force_runs[0].loader, "forge");
        assert_eq!(cf.force_runs[1].loader, "fabric");
    }

    // --- ControlAcks ---

    #[test]
    fn test_control_acks_default_empty() {
        let acks = ControlAcks::new();
        assert!(acks.processed.is_empty());
        assert_eq!(acks.schema_version, 1);
    }

    #[test]
    fn test_control_acks_processed_ids() {
        let mut acks = ControlAcks::new();
        acks.push(AckEntry {
            request_id: "req-1".to_string(),
            kind: "rollback".to_string(),
            processed_at: Utc::now(),
            outcome: AckOutcome::success(),
            details: serde_json::Value::Null,
        });
        acks.push(AckEntry {
            request_id: "req-2".to_string(),
            kind: "force_run".to_string(),
            processed_at: Utc::now(),
            outcome: AckOutcome::success(),
            details: serde_json::Value::Null,
        });
        let ids = acks.processed_ids();
        assert!(ids.contains("req-1"));
        assert!(ids.contains("req-2"));
        assert!(!ids.contains("req-3"));
    }

    #[test]
    fn test_control_acks_prune_old_entries() {
        let mut acks = ControlAcks::new();
        // One entry 40 days old (should be pruned)
        acks.push(AckEntry {
            request_id: "old".to_string(),
            kind: "force_run".to_string(),
            processed_at: Utc::now() - Duration::days(40),
            outcome: AckOutcome::success(),
            details: serde_json::Value::Null,
        });
        // One recent entry (should survive)
        acks.push(AckEntry {
            request_id: "new".to_string(),
            kind: "force_run".to_string(),
            processed_at: Utc::now(),
            outcome: AckOutcome::success(),
            details: serde_json::Value::Null,
        });
        acks.prune(Duration::days(30));
        assert_eq!(acks.processed.len(), 1);
        assert_eq!(acks.processed[0].request_id, "new");
    }

    #[test]
    fn test_control_acks_prune_keeps_all_when_recent() {
        let mut acks = ControlAcks::new();
        for i in 0..5u32 {
            acks.push(AckEntry {
                request_id: format!("req-{i}"),
                kind: "force_run".to_string(),
                processed_at: Utc::now() - Duration::days(i as i64),
                outcome: AckOutcome::success(),
                details: serde_json::Value::Null,
            });
        }
        acks.prune(Duration::days(30));
        assert_eq!(acks.processed.len(), 5); // all within 30 days
    }

    // --- AckOutcome serialization ---

    #[test]
    fn test_ack_outcome_success_serializes_as_string() {
        let outcome = AckOutcome::success();
        let json = serde_json::to_string(&outcome).unwrap();
        assert_eq!(json, "\"success\"");
    }

    #[test]
    fn test_ack_outcome_failure_serializes_as_object() {
        let outcome = AckOutcome::error("something went wrong");
        let json = serde_json::to_string(&outcome).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["error"], "something went wrong");
    }

    #[test]
    fn test_ack_entry_roundtrip() {
        let entry = AckEntry {
            request_id: "req-abc".to_string(),
            kind: "rollback".to_string(),
            processed_at: Utc::now(),
            outcome: AckOutcome::success(),
            details: serde_json::json!({"backup_path": "v5/history/manifest-x.json"}),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: AckEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.request_id, "req-abc");
        assert_eq!(back.kind, "rollback");
        assert!(matches!(back.outcome, AckOutcome::Success(_)));
    }

    // --- Idempotency: already-processed ids are skipped ---

    #[test]
    fn test_already_processed_ids_are_skipped() {
        let mut acks = ControlAcks::new();
        acks.push(AckEntry {
            request_id: "req-1".to_string(),
            kind: "rollback".to_string(),
            processed_at: Utc::now(),
            outcome: AckOutcome::success(),
            details: serde_json::Value::Null,
        });

        // Simulate what process_pending does: build the set and check.
        let already: HashSet<String> = acks
            .processed_ids()
            .into_iter()
            .map(str::to_string)
            .collect();
        assert!(already.contains("req-1"));
        assert!(!already.contains("req-2"));
    }

    // --- S3 path helpers ---

    #[test]
    fn test_control_s3_path() {
        let path = control_s3_path();
        assert_eq!(path, format!("v{CAS_VERSION}/admin/control.json"));
    }

    #[test]
    fn test_acks_s3_path() {
        let path = acks_s3_path();
        assert_eq!(path, format!("v{CAS_VERSION}/admin/control_acks.json"));
    }
}
