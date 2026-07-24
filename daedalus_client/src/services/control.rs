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
//! * `rollback_request` — restore a historical root manifest to the live
//!   `v{CAS_VERSION}/manifest.json`. Loaders that should stay on the
//!   rolled-back build are pinned via `pins.json` (written by enderium before
//!   it submits the intent) so the next publish cycle doesn't move them
//!   forward; unpinned loaders resume updating on the next cycle.
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
//! bounded — except entries whose intent is still present in `control.json`,
//! which are kept regardless of age: the ack is the only thing preventing a
//! still-listed intent from re-executing.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
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

    /// Drop entries older than `retention` to keep the file bounded — except
    /// entries whose `request_id` is still present in the live control file.
    /// Intents stay in `control.json` indefinitely (enderium never clears
    /// them), and the ack log is the ONLY thing standing between an old acked
    /// rollback and its spontaneous re-execution: pruning an ack whose intent
    /// is still live would re-run that intent on the next poll.
    fn prune(&mut self, retention: Duration, live_intent_ids: &HashSet<&str>) {
        let cutoff = Utc::now() - retention;
        self.processed.retain(|e| {
            e.processed_at >= cutoff
                || live_intent_ids.contains(e.request_id.as_str())
        });
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

/// The control-file schema version this build understands. A `control.json`
/// declaring a higher version is refused (its intents are not run) so a
/// forward-incompatible file from a newer enderium surfaces loudly instead of
/// being silently treated as empty.
const SUPPORTED_CONTROL_SCHEMA: u32 = 1;

/// Load `control.json` from S3.  Returns `ControlFile::default()` (empty — no
/// intents) on 404 or any parse/fetch error.
///
/// Unlike the advisory pins/run-state files, a *parse* failure or an
/// unsupported `schema_version` here means real operator intents (rollback /
/// force-run) would be silently dropped, so those cases are logged at `error!`
/// (which the Discord layer forwards) rather than `warn!`. A 404 (no file yet)
/// and a transient fetch error stay quiet.
pub async fn load(bucket: &s3::Bucket) -> ControlFile {
    let path = control_s3_path();
    match bucket.get_object(&path).await {
        Ok(resp) => match serde_json::from_slice::<ControlFile>(resp.bytes()) {
            Ok(cf) => {
                if cf.schema_version > SUPPORTED_CONTROL_SCHEMA {
                    error!(
                        path = %path,
                        schema_version = cf.schema_version,
                        supported = SUPPORTED_CONTROL_SCHEMA,
                        "control.json declares a newer schema_version than this daedalus \
                         supports; refusing to process its intents (upgrade daedalus). Any \
                         pending rollback/force-run will NOT run until then."
                    );
                    return ControlFile::default();
                }
                info!(path = %path, "Loaded control file from S3");
                cf
            }
            Err(e) => {
                error!(path = %path, error = %e, "Failed to parse control.json; operator intents (rollback/force-run) will NOT be processed this poll");
                ControlFile::default()
            }
        },
        Err(s3::error::S3Error::Http(404, _)) => {
            // No control file yet — nothing to process.
            ControlFile::default()
        }
        Err(e) => {
            warn!(path = %path, error = %e, "Failed to fetch control.json; treating as empty this poll");
            ControlFile::default()
        }
    }
}

/// Outcome of loading `control_acks.json` — the idempotency log.
enum ControlAcksLoad {
    /// Log loaded from S3, or absent (404 → empty). Safe to process intents.
    Loaded(ControlAcks),
    /// The log exists but could not be read (parse error, or a fetch error that
    /// leaves us unable to prove what has already run). The caller must skip
    /// this poll: processing intents without the log would re-execute
    /// already-applied rollbacks / force-runs and then overwrite the history
    /// with a fresh empty log.
    Unreadable,
}

/// Load `control_acks.json` from S3.
///
/// A 404 yields an empty log (first deploy). Unlike the advisory pins/run-state
/// files, a *parse* error here is not treated as "absent": silently defaulting
/// to an empty log would drop the idempotency guarantee, so it (and a non-404
/// fetch error) returns `Unreadable` and is logged loudly, leaving the caller to
/// skip the poll rather than re-run intents against a lost log.
async fn load_acks(bucket: &s3::Bucket) -> ControlAcksLoad {
    let path = acks_s3_path();
    match bucket.get_object(&path).await {
        Ok(resp) => match serde_json::from_slice::<ControlAcks>(resp.bytes()) {
            Ok(acks) => {
                info!(path = %path, "Loaded control acks from S3");
                ControlAcksLoad::Loaded(acks)
            }
            Err(e) => {
                error!(
                    path = %path,
                    error = %e,
                    "control_acks.json exists but could not be parsed; skipping ALL control \
                     processing this poll to avoid re-executing already-applied intents and \
                     overwriting the ack history. Inspect or remove the file on S3 to resume."
                );
                ControlAcksLoad::Unreadable
            }
        },
        Err(s3::error::S3Error::Http(404, _)) => {
            info!(path = %path, "No control acks on S3 yet; starting a fresh log");
            ControlAcksLoad::Loaded(ControlAcks::new())
        }
        Err(e) => {
            warn!(
                path = %path,
                error = %e,
                "Failed to fetch control_acks.json; skipping control processing this poll \
                 rather than risk re-executing intents against an unknown ack log"
            );
            ControlAcksLoad::Unreadable
        }
    }
}

/// Persist `control_acks.json` to S3.
pub async fn save_acks(
    bucket: &s3::Bucket,
    acks: &ControlAcks,
) -> Result<(), crate::infrastructure::error::Error> {
    let path = acks_s3_path();
    crate::services::s3_json::save_json(bucket, &path, acks).await?;
    info!(path = %path, count = acks.processed.len(), "Saved control acks to S3");
    Ok(())
}

/// Prune old entries and persist the ack log to S3.
///
/// Called after **each** processed intent so a crash mid-batch cannot lose the
/// ack of an intent whose side effects already committed (which would otherwise
/// re-execute it on the next poll). Pruning keeps every ack still referenced
/// by the live control file regardless of age. A failed write is logged, not
/// fatal.
async fn persist_acks(
    bucket: &s3::Bucket,
    acks: &mut ControlAcks,
    control: &ControlFile,
) {
    let live_intent_ids: HashSet<&str> = control
        .force_runs
        .iter()
        .map(|r| r.request_id.as_str())
        .chain(
            control
                .rollback_request
                .iter()
                .map(|r| r.request_id.as_str()),
        )
        .collect();
    acks.prune(Duration::days(30), &live_intent_ids);
    if let Err(e) = save_acks(bucket, acks).await {
        error!(error = %e, "Failed to save control_acks.json — outcome may be re-attempted on next poll");
    }
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
/// Consecutive failures a rollback intent gets before it is acked as failed
/// instead of retried.
const MAX_ROLLBACK_ATTEMPTS: u32 = 3;

/// Failure counts per rollback intent, for this process.
///
/// A rollback that aborts before changing anything — an unreadable live root, a
/// pre-rollback backup that could not be written — is left unacked so the next
/// poll retries it, which is what those abort paths document. Counting bounds
/// that: an intent whose failure is not transient (a target that genuinely is
/// not there) is acked as failed rather than re-running and alerting every
/// poll forever.
///
/// Process-local deliberately. A restart is a legitimate fresh attempt, and
/// keeping the count out of `control_acks.json` avoids changing a document
/// enderium also reads.
static ROLLBACK_ATTEMPTS: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Records a failed attempt and reports how many this intent has had.
fn record_rollback_failure(request_id: &str) -> u32 {
    let mut attempts = ROLLBACK_ATTEMPTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let count = attempts.entry(request_id.to_string()).or_insert(0);
    *count += 1;
    *count
}

/// Drops the failure count for an intent that is finished, whether it
/// succeeded or was acked as failed.
fn clear_rollback_failures(request_id: &str) {
    ROLLBACK_ATTEMPTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(request_id);
}

pub async fn process_pending(bucket: &s3::Bucket) {
    let control = load(bucket).await;
    let mut acks = match load_acks(bucket).await {
        ControlAcksLoad::Loaded(acks) => acks,
        // Idempotency log unreadable — skip this poll entirely (see load_acks).
        ControlAcksLoad::Unreadable => return,
    };
    let already_processed = acks
        .processed_ids()
        .into_iter()
        .map(str::to_string)
        .collect::<HashSet<_>>();

    // ------------------------------------------------------------------
    // Force-run intents
    // ------------------------------------------------------------------
    // Every force-run does the same thing: one full publish cycle for all
    // loaders (approach (b) — see the module doc). So a poll that finds several
    // unprocessed force-runs runs a single cycle and acks all of them against
    // it, rather than running one identical full cycle per request (which would
    // re-fetch every upstream and re-upload everything N times for no extra
    // effect).
    let pending_force_runs: Vec<&ForceRunRequest> = control
        .force_runs
        .iter()
        .filter(|req| !already_processed.contains(&req.request_id))
        .collect();

    if !pending_force_runs.is_empty() {
        let request_ids: Vec<&str> = pending_force_runs
            .iter()
            .map(|r| r.request_id.as_str())
            .collect();
        info!(
            count = pending_force_runs.len(),
            ?request_ids,
            "Processing force-run intent(s) with a single publish cycle"
        );

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
            crate::MAX_CONCURRENT_UPLOADS,
        ));
        // No first-cycle work: an operator force-run is an extra cycle on top of
        // the schedule, so it neither performs nor retires the startup passes
        // the timer-driven loop owns.
        let cycle = crate::run_publish_cycle(
            crate::FirstRunLoaders::default(),
            semaphore,
        )
        .await;

        // The ack reflects what the cycle actually did — an operator
        // force-running during an outage must see the failure (and may
        // resubmit), not a success for a cycle that published nothing.
        let cycle_outcome = if !cycle.published {
            AckOutcome::error(
                "publish cycle did not reach the publish phase (minecraft retrieval failed or was skipped)",
            )
        } else if !cycle.root_committed {
            AckOutcome::error(
                "publish cycle did not commit a new root manifest (admin state unreadable, or the history/root upload failed); the live root is unchanged — resubmit once the underlying issue clears",
            )
        } else if cycle.failed_loaders.is_empty() {
            AckOutcome::success()
        } else {
            AckOutcome::error(format!(
                "publish cycle completed with failures: {}",
                cycle.failed_loaders.join(", ")
            ))
        };

        // Ack every request the cycle satisfied. The requested `loader` is kept
        // in the ack details for observability even though execution always
        // refreshes all loaders.
        for req in &pending_force_runs {
            acks.push(AckEntry {
                request_id: req.request_id.clone(),
                kind: "force_run".to_string(),
                processed_at: Utc::now(),
                outcome: cycle_outcome.clone(),
                details: serde_json::json!({
                    "requested_loader": req.loader,
                    "note": "full publish cycle executed (all loaders); shared with any other force-runs pending in the same poll"
                }),
            });
        }
        persist_acks(bucket, &mut acks, &control).await;

        info!(
            count = pending_force_runs.len(),
            "Force-run intent(s) processed"
        );
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
                    clear_rollback_failures(&req.request_id);
                    info!(
                        request_id = %req.request_id,
                        rolled_back_to = %outcome.rolled_back_to,
                        "Rollback intent processed successfully"
                    );
                }
                Err(e) => {
                    let msg = e.to_string();
                    let attempts = record_rollback_failure(&req.request_id);
                    if attempts < MAX_ROLLBACK_ATTEMPTS {
                        // Left unacked so the next poll retries, which is what
                        // the abort paths in `execute_rollback` promise: they
                        // stop before changing anything precisely so the intent
                        // can be re-run. Acking here would consume the
                        // operator's intent on the first transient S3 error and
                        // leave the rollback silently undone.
                        warn!(
                            request_id = %req.request_id,
                            history_timestamp = %req.history_timestamp,
                            error = %msg,
                            attempt = attempts,
                            max_attempts = MAX_ROLLBACK_ATTEMPTS,
                            "Rollback intent failed; leaving it pending for the next poll"
                        );
                    } else {
                        // `error!` is auto-forwarded to Discord by DiscordTracingLayer,
                        // so this single log both records and alerts — no separate
                        // Discord notification (which would double-report).
                        error!(
                            request_id = %req.request_id,
                            history_timestamp = %req.history_timestamp,
                            error = %msg,
                            attempts = attempts,
                            "Rollback intent failed on every attempt; giving up"
                        );
                        clear_rollback_failures(&req.request_id);
                        acks.push(AckEntry {
                            request_id: req.request_id.clone(),
                            kind: "rollback".to_string(),
                            processed_at: Utc::now(),
                            outcome: AckOutcome::error(msg),
                            details: serde_json::json!({
                                "history_timestamp": req.history_timestamp,
                                "attempts": attempts,
                            }),
                        });
                    }
                }
            }
            persist_acks(bucket, &mut acks, &control).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Rollback executor (§2.5)
// ---------------------------------------------------------------------------

/// Reject a `history_timestamp` that is not the timestamp grammar daedalus
/// itself emits, before it is interpolated into an S3 object key. rust-s3 signs
/// requests through the `url` crate, which performs RFC 3986 dot-segment
/// removal, so an unvalidated value such as `"/../../manifest"` would normalise
/// to a key outside the intended `v{CAS}/history/` prefix (e.g. onto the live
/// root). Restricting to digits, `-`, `T`, and `Z` makes any `/`, `.`, `%`, or
/// `\` impossible. The millisecond component is optional so older
/// second-resolution history entries stay rollback-targetable.
fn is_valid_history_timestamp(ts: &str) -> bool {
    !ts.is_empty()
        && ts.len() <= 32
        && ts
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'T' || b == b'Z')
}

async fn execute_rollback(
    bucket: &s3::Bucket,
    ts: &str,
    request_id: &str,
) -> Result<RollbackOutcome, crate::infrastructure::error::Error> {
    use crate::services::cas::RootManifest;

    // Validate before the value reaches any `format!`-built S3 key.
    if !is_valid_history_timestamp(ts) {
        return Err(crate::infrastructure::error::invalid_input(format!(
            "invalid history_timestamp '{ts}': expected YYYY-MM-DDTHH-MM-SS[-mmm]Z"
        )));
    }

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
        // No live root yet — nothing to back up; the rollback can proceed.
        Err(s3::error::S3Error::Http(404, _)) => None,
        Err(e) => {
            // Without reading the live root we cannot write the pre-rollback
            // backup, and a rollback with no undo point is not safe to run —
            // abort; the operator's intent stays pending and the next poll
            // retries.
            warn!(error = %e, "Failed to read current live root; aborting rollback (no undo point)");
            return Err(crate::infrastructure::error::s3_error(
                e,
                live_root_path,
            ));
        }
    };

    let now_str = crate::services::cas::now_timestamp();
    let backup_path = format!("v{CAS_VERSION}/history/manifest-{now_str}.json");
    let meta_path =
        format!("v{CAS_VERSION}/history/manifest-{now_str}.meta.json");

    if let Some(ref live_bytes) = current_live_bytes {
        // The backup is the undo point for a mistaken rollback — it must
        // exist before the live root is overwritten. Retried twice; a final
        // failure aborts the rollback (the intent stays pending for the next
        // poll) instead of destroying the only copy of the current root.
        let mut attempts = 0;
        loop {
            attempts += 1;
            match bucket
                .put_object_with_content_type(
                    &backup_path,
                    live_bytes,
                    "application/json",
                )
                .await
            {
                Ok(_) => {
                    info!(path = %backup_path, "Pre-rollback backup written");
                    break;
                }
                Err(e) if attempts < 3 => {
                    warn!(path = %backup_path, error = %e, attempt = attempts, "Pre-rollback backup write failed; retrying");
                }
                Err(e) => {
                    return Err(crate::infrastructure::error::s3_error(
                        e,
                        backup_path,
                    ));
                }
            }
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
        "Rollback performed (request_id=`{request_id}`): root manifest restored to \
         history entry `{ts}`. Pre-rollback backup written to `{backup_path}`. Loaders \
         pinned via pins.json keep referencing the rolled-back timestamp until \
         unpinned; unpinned loaders resume updating on the next publish cycle."
    );
    notify_discord_notice("Rollback performed", &msg);

    // ------------------------------------------------------------------
    // Step 8: update run_state.json. Tag the affected loaders as RolledBack —
    // not Success — so the admin view can tell that a rollback (rather than a
    // fresh build) set their current reference, and that latest_built_timestamp
    // moved backward on purpose.
    // ------------------------------------------------------------------
    let mut run_state = crate::services::run_state::load(bucket).await;
    for (loader, reference) in &history_manifest.loaders {
        run_state
            .loader_mut(loader)
            .record_rollback(&reference.timestamp, &reference.url);
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

/// Fire a positive Discord notice (rendered green, not warning-styled) via the
/// global notifier, if configured. Used for successful operator actions such as
/// a completed rollback. Goes straight to the notifier rather than through a
/// `warn!`/`error!`, which the tracing layer would forward as an alert.
fn notify_discord_notice(title: &str, message: &str) {
    if let Some(notifier) = crate::services::discord::notifier() {
        notifier.notify(DiscordEvent::Notice {
            title: title.to_string(),
            message: message.to_string(),
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
    fn test_is_valid_history_timestamp_accepts_real_formats() {
        assert!(is_valid_history_timestamp("2026-05-13T10-00-00Z"));
        assert!(is_valid_history_timestamp("2026-05-13T10-00-00-123Z"));
    }

    #[test]
    fn test_is_valid_history_timestamp_rejects_traversal_and_junk() {
        for bad in [
            "",
            "/../../manifest",
            "../../admin/control",
            "2026-05-13T10-00-00Z/../manifest",
            "a.b",         // '.' blocked
            "x/y",         // '/' blocked
            "ab%2e%2e",    // '%' blocked
            "back\\slash", // '\\' blocked
        ] {
            assert!(!is_valid_history_timestamp(bad), "should reject {bad:?}");
        }
        // length cap
        assert!(!is_valid_history_timestamp(&"1".repeat(40)));
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
        acks.prune(Duration::days(30), &HashSet::new());
        assert_eq!(acks.processed.len(), 1);
        assert_eq!(acks.processed[0].request_id, "new");
    }

    #[test]
    fn test_control_acks_prune_keeps_live_intents_regardless_of_age() {
        let mut acks = ControlAcks::new();
        // An old acked rollback whose intent is STILL in control.json: the
        // ack must survive pruning or the rollback re-executes spontaneously.
        acks.push(AckEntry {
            request_id: "old-but-live".to_string(),
            kind: "rollback".to_string(),
            processed_at: Utc::now() - Duration::days(90),
            outcome: AckOutcome::success(),
            details: serde_json::Value::Null,
        });
        acks.push(AckEntry {
            request_id: "old-and-gone".to_string(),
            kind: "force_run".to_string(),
            processed_at: Utc::now() - Duration::days(90),
            outcome: AckOutcome::success(),
            details: serde_json::Value::Null,
        });

        let live: HashSet<&str> = ["old-but-live"].into_iter().collect();
        acks.prune(Duration::days(30), &live);

        assert_eq!(acks.processed.len(), 1);
        assert_eq!(acks.processed[0].request_id, "old-but-live");
    }

    #[test]
    fn a_rollback_retries_before_it_is_given_up_on() {
        // The abort paths in execute_rollback stop before changing anything so
        // the intent can be re-run; acking on the first transient S3 error
        // would consume the operator's intent and silently leave the rollback
        // undone.
        let id = "retry-budget-test";
        clear_rollback_failures(id);

        assert_eq!(record_rollback_failure(id), 1);
        assert_eq!(record_rollback_failure(id), 2);
        assert!(
            2 < MAX_ROLLBACK_ATTEMPTS,
            "the first failures must leave the intent pending"
        );
        assert_eq!(record_rollback_failure(id), MAX_ROLLBACK_ATTEMPTS);

        clear_rollback_failures(id);
    }

    #[test]
    fn a_finished_rollback_starts_over_from_zero() {
        // A success, or a give-up that acked, must not leave a count behind for
        // a later intent to inherit.
        let id = "clear-on-finish-test";
        clear_rollback_failures(id);

        record_rollback_failure(id);
        record_rollback_failure(id);
        clear_rollback_failures(id);

        assert_eq!(
            record_rollback_failure(id),
            1,
            "a cleared intent must begin a fresh budget"
        );
        clear_rollback_failures(id);
    }

    #[test]
    fn rollback_attempt_counts_are_tracked_per_intent() {
        let a = "per-intent-a";
        let b = "per-intent-b";
        clear_rollback_failures(a);
        clear_rollback_failures(b);

        record_rollback_failure(a);
        record_rollback_failure(a);
        assert_eq!(
            record_rollback_failure(b),
            1,
            "one struggling intent must not spend another's budget"
        );

        clear_rollback_failures(a);
        clear_rollback_failures(b);
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
        acks.prune(Duration::days(30), &HashSet::new());
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
