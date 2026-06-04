//! Persisted per-loader run state.
//!
//! Written once per cycle to `v{CAS_VERSION}/admin/run_state.json` so the
//! admin server (and operators) can inspect what happened on the last cycle
//! even after a process restart.
//!
//! Daedalus does NOT read this file back for correctness — it is purely
//! observability data derived from the S3 history + in-memory circuit-breaker
//! state.  Missing / malformed admin JSON is therefore treated as "not yet
//! written" and the file is simply overwritten on the next cycle.

use crate::services::cas::CAS_VERSION;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::{info, warn};

/// Path on S3 where the run-state file lives.
pub fn run_state_s3_path() -> String {
    format!("v{CAS_VERSION}/admin/run_state.json")
}

/// Outcome of a single loader's last attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoaderOutcome {
    /// Build, sanity gates, and upload all succeeded.
    Success,
    /// Sanity gate tripped — upload skipped, carry-forward kept.
    SanityGateBlocked,
    /// Remote upstream fetch or S3 upload failed.
    FetchFailure,
    /// Circuit breaker was open; loader was not attempted.
    CircuitOpen,
    /// An operator rollback repointed this loader's root reference at a
    /// historical manifest. A healthy served state (not a failure), but
    /// distinct from a fresh `Success` build.
    RolledBack,
}

impl std::fmt::Display for LoaderOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoaderOutcome::Success => write!(f, "success"),
            LoaderOutcome::SanityGateBlocked => {
                write!(f, "sanity_gate_blocked")
            }
            LoaderOutcome::FetchFailure => write!(f, "fetch_failure"),
            LoaderOutcome::CircuitOpen => write!(f, "circuit_open"),
            LoaderOutcome::RolledBack => write!(f, "rolled_back"),
        }
    }
}

/// State record for a single loader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoaderRunState {
    /// Timestamp of the latest successfully-built manifest, independent of
    /// whether the loader is pinned.  Moves every cycle that passes build +
    /// gates; stays unchanged on gate-blocked or fetch-failure cycles.
    pub latest_built_timestamp: Option<String>,
    /// S3 path of the latest successfully-built manifest.
    pub latest_built_path: Option<String>,
    /// When the last cycle attempted this loader.
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// Outcome of the last attempt.
    pub last_outcome: Option<LoaderOutcome>,
    /// Number of consecutive cycles that did not produce a successful build.
    /// Reset to 0 on `Success`.
    pub consecutive_failures: u32,
}

impl Default for LoaderRunState {
    fn default() -> Self {
        Self {
            latest_built_timestamp: None,
            latest_built_path: None,
            last_attempt_at: None,
            last_outcome: None,
            consecutive_failures: 0,
        }
    }
}

impl LoaderRunState {
    /// Record a successful build-and-upload.
    pub fn record_success(&mut self, timestamp: &str, path: &str) {
        self.latest_built_timestamp = Some(timestamp.to_string());
        self.latest_built_path = Some(path.to_string());
        self.last_attempt_at = Some(Utc::now());
        self.last_outcome = Some(LoaderOutcome::Success);
        self.consecutive_failures = 0;
    }

    /// Record a non-success outcome (sanity gate, fetch failure, circuit open).
    pub fn record_failure(&mut self, outcome: LoaderOutcome) {
        self.last_attempt_at = Some(Utc::now());
        self.last_outcome = Some(outcome);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Record an operator rollback that repointed this loader's root reference
    /// at a historical manifest. Like a successful build this is a healthy
    /// terminal state, so the failure streak resets, but the outcome is tagged
    /// `RolledBack` rather than `Success` so observers can tell a rollback from
    /// a fresh build (and that `latest_built_timestamp` moved backward on
    /// purpose).
    pub fn record_rollback(&mut self, timestamp: &str, path: &str) {
        self.latest_built_timestamp = Some(timestamp.to_string());
        self.latest_built_path = Some(path.to_string());
        self.last_attempt_at = Some(Utc::now());
        self.last_outcome = Some(LoaderOutcome::RolledBack);
        self.consecutive_failures = 0;
    }
}

/// Top-level persisted state document.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunState {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// When this snapshot was written.
    pub written_at: Option<DateTime<Utc>>,
    /// Per-loader records keyed by loader name (e.g. `"minecraft"`, `"forge"`).
    pub loaders: BTreeMap<String, LoaderRunState>,
}

impl RunState {
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            written_at: None,
            loaders: BTreeMap::new(),
        }
    }

    /// Get mutable access to a loader's record, inserting a default if absent.
    pub fn loader_mut(&mut self, loader: &str) -> &mut LoaderRunState {
        self.loaders.entry(loader.to_string()).or_default()
    }

    /// Read-only access to a loader's record.
    pub fn loader(&self, loader: &str) -> Option<&LoaderRunState> {
        self.loaders.get(loader)
    }
}

/// Load run state from S3.
///
/// Returns an empty `RunState` on 404 (first deploy) or any parse error —
/// the file is treated as purely advisory observability data.
pub async fn load(bucket: &s3::Bucket) -> RunState {
    crate::services::s3_json::load_or_else(
        bucket,
        &run_state_s3_path(),
        "run state",
        RunState::new,
    )
    .await
}

/// Persist run state to S3.
///
/// Failure is non-fatal — a missed write just means the admin server sees
/// stale data until the next cycle.
pub async fn save(bucket: &s3::Bucket, state: &mut RunState) {
    state.written_at = Some(Utc::now());
    let path = run_state_s3_path();
    match crate::services::s3_json::save_json(bucket, &path, state).await {
        Ok(_) => info!(path = %path, "Run state saved to S3"),
        Err(e) => {
            warn!(path = %path, error = %e, "Failed to save run state (non-fatal)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_run_state_success() {
        let mut s = LoaderRunState::default();
        s.record_success(
            "2026-01-01T00-00-00Z",
            "v5/manifests/forge/2026-01-01T00-00-00Z.json",
        );
        assert_eq!(s.consecutive_failures, 0);
        assert_eq!(s.last_outcome, Some(LoaderOutcome::Success));
        assert!(s.latest_built_timestamp.is_some());
    }

    #[test]
    fn test_loader_run_state_consecutive_failures() {
        let mut s = LoaderRunState::default();
        s.record_failure(LoaderOutcome::SanityGateBlocked);
        s.record_failure(LoaderOutcome::FetchFailure);
        assert_eq!(s.consecutive_failures, 2);
        assert_eq!(s.last_outcome, Some(LoaderOutcome::FetchFailure));
    }

    #[test]
    fn test_loader_run_state_reset_on_success() {
        let mut s = LoaderRunState::default();
        s.record_failure(LoaderOutcome::FetchFailure);
        s.record_failure(LoaderOutcome::FetchFailure);
        s.record_success("ts", "path");
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn test_run_state_serialization_roundtrip() {
        let mut state = RunState::new();
        state.loader_mut("forge").record_success("ts", "path");
        state
            .loader_mut("fabric")
            .record_failure(LoaderOutcome::CircuitOpen);
        state.written_at = Some(Utc::now());

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: RunState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.schema_version, 1);
        assert!(deserialized.loaders.contains_key("forge"));
        assert!(deserialized.loaders.contains_key("fabric"));
        assert_eq!(
            deserialized.loaders["forge"].last_outcome,
            Some(LoaderOutcome::Success)
        );
    }

    #[test]
    fn test_outcome_display() {
        assert_eq!(LoaderOutcome::Success.to_string(), "success");
        assert_eq!(
            LoaderOutcome::SanityGateBlocked.to_string(),
            "sanity_gate_blocked"
        );
        assert_eq!(LoaderOutcome::CircuitOpen.to_string(), "circuit_open");
        assert_eq!(LoaderOutcome::RolledBack.to_string(), "rolled_back");
    }

    #[test]
    fn test_record_rollback_is_distinct_from_success() {
        let mut s = LoaderRunState::default();
        s.record_failure(LoaderOutcome::FetchFailure);
        s.record_rollback("2026-01-01T00-00-00Z", "v5/manifests/forge/x.json");
        // Tagged as a rollback, not a fresh successful build...
        assert_eq!(s.last_outcome, Some(LoaderOutcome::RolledBack));
        // ...but still a healthy state, so the failure streak resets.
        assert_eq!(s.consecutive_failures, 0);
        assert_eq!(
            s.latest_built_timestamp.as_deref(),
            Some("2026-01-01T00-00-00Z")
        );
    }

    #[test]
    fn test_rolled_back_serializes_snake_case() {
        let json = serde_json::to_string(&LoaderOutcome::RolledBack).unwrap();
        assert_eq!(json, "\"rolled_back\"");
        let back: LoaderOutcome = serde_json::from_str("\"rolled_back\"").unwrap();
        assert_eq!(back, LoaderOutcome::RolledBack);
    }
}
