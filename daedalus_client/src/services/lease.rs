//! Advisory single-writer lease.
//!
//! Two daedalus instances running against the same bucket interleave root
//! manifest PUTs, double-execute control intents, and last-writer-win each
//! other's ack and run-state documents — `ROOT_WRITE_LOCK` is process-local
//! and protects none of that. The realistic overlap is a rolling deploy: the
//! new instance starts while the old one is mid-cycle.
//!
//! The lease is ADVISORY because plain S3 has no conditional writes: two
//! writers racing the same expired lease can both PUT. The double-read
//! settle step (write, wait, read back) resolves that race in all but
//! pathological clock/network cases — the last writer's document survives
//! and the loser keeps waiting. That is a deliberate trade-off: it turns
//! "guaranteed interleaving on every deploy" into "exclusion except under
//! simultaneous-millisecond takeover races", without a new dependency on a
//! locking service.
//!
//! Lifecycle:
//! - `acquire` blocks at startup until the lease is free or expired, then
//!   claims it. A rolling deploy's new instance therefore waits for the old
//!   instance to release (graceful shutdown) or expire (crash).
//! - `spawn_heartbeat` renews the lease in a background task so it stays
//!   valid through arbitrarily long publish cycles. Discovering another
//!   holder mid-flight means this instance lost the lease (e.g. a long
//!   network partition let it expire); it exits immediately rather than
//!   keep writing alongside the new holder.
//! - `release` tombstones the lease on graceful shutdown so the successor
//!   acquires without waiting out the TTL.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info, warn};

use crate::services::cas::CAS_VERSION;

/// How long a lease stays valid without renewal. Must comfortably exceed the
/// heartbeat interval so transient S3 blips don't expire a live holder.
const LEASE_TTL: ChronoDuration = ChronoDuration::seconds(300);
/// Heartbeat renewal cadence.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(60);
/// Settle window between writing a claim and reading it back — long enough
/// for a racing writer's PUT to land and win.
const SETTLE: Duration = Duration::from_secs(3);
/// Poll cadence while waiting for a held lease to free up.
const WAIT_POLL: Duration = Duration::from_secs(15);

/// S3 path of the lease document.
fn lease_s3_path() -> String {
    format!("v{CAS_VERSION}/admin/lease.json")
}

/// The lease document.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseDoc {
    schema_version: u32,
    /// Identity of the instance holding the lease.
    holder: String,
    /// When the holder first acquired it.
    acquired_at: DateTime<Utc>,
    /// Last heartbeat renewal.
    renewed_at: DateTime<Utc>,
    /// The lease is free once this instant passes without renewal.
    expires_at: DateTime<Utc>,
}

impl LeaseDoc {
    fn new(holder: &str, acquired_at: DateTime<Utc>) -> Self {
        let now = Utc::now();
        Self {
            schema_version: 1,
            holder: holder.to_string(),
            acquired_at,
            renewed_at: now,
            expires_at: now + LEASE_TTL,
        }
    }

    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.expires_at
    }
}

/// A unique identity for this process: hostname (set in containers), pid and
/// startup time, so two instances can never collide.
pub fn holder_id() -> String {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string());
    let started = Utc::now().timestamp_millis();
    format!("{host}:{}:{started}", std::process::id())
}

/// Read the current lease. `None` covers "no lease yet" and "unparseable"
/// (a junk document must not deadlock every future instance); transient
/// fetch errors return `Err` so callers can distinguish.
async fn read(
    bucket: &s3::Bucket,
) -> Result<Option<LeaseDoc>, crate::infrastructure::error::Error> {
    let path = lease_s3_path();
    match bucket.get_object(&path).await {
        Ok(resp) => match serde_json::from_slice::<LeaseDoc>(resp.bytes()) {
            Ok(doc) => Ok(Some(doc)),
            Err(e) => {
                warn!(path = %path, error = %e, "Lease document unparseable; treating as absent");
                Ok(None)
            }
        },
        Err(s3::error::S3Error::Http(404, _)) => Ok(None),
        Err(e) => Err(crate::infrastructure::error::s3_error(e, path)),
    }
}

async fn write(
    bucket: &s3::Bucket,
    doc: &LeaseDoc,
) -> Result<(), crate::infrastructure::error::Error> {
    // Route through the shared retrying helper (5 attempts, 60s cap) that every
    // other admin write uses, rather than a bare PUT. Without retries a single
    // transient renewal write failure stalls the S3 lease's `expires_at` for a
    // whole heartbeat, and a run of them lets a reader (the enderium admin) see
    // a live holder's lease as expired.
    crate::services::s3_json::save_json(bucket, &lease_s3_path(), doc).await
}

/// Single-attempt write, used only for the acquisition claim.
///
/// The claim's whole correctness argument is the settle window: write, wait,
/// read back, and whoever's PUT landed last wins. Routing it through the
/// retrying helper defeats that — a racing claimant whose first attempt fails
/// lands its retry seconds later, after the other instance has already read
/// back and concluded it won, so both believe they hold the lease. One attempt
/// keeps the claim inside the window; a failure needs no retry here because
/// `acquire` loops and re-reads anyway.
async fn write_claim_once(
    bucket: &s3::Bucket,
    doc: &LeaseDoc,
) -> Result<(), crate::infrastructure::error::Error> {
    let path = lease_s3_path();
    let bytes = serde_json::to_vec_pretty(doc)?;
    bucket
        .put_object_with_content_type(&path, &bytes, "application/json")
        .await
        .map(|_| ())
        .map_err(|e| crate::infrastructure::error::s3_error(e, path))
}

/// Block until this instance holds the lease.
///
/// Transient S3 errors are retried indefinitely — the lease guards S3
/// writes, so there is nothing useful to do without S3 anyway.
pub async fn acquire(bucket: &s3::Bucket, holder: &str) {
    info!(holder = %holder, "Acquiring the single-writer lease");
    loop {
        match read(bucket).await {
            Ok(existing) => {
                let now = Utc::now();
                match existing {
                    Some(doc)
                        if doc.holder != holder && !doc.is_expired(now) =>
                    {
                        info!(
                            current_holder = %doc.holder,
                            expires_at = %doc.expires_at,
                            "Lease held by another instance; waiting"
                        );
                        tokio::time::sleep(WAIT_POLL).await;
                        continue;
                    }
                    other => {
                        if let Some(doc) = &other {
                            if doc.holder != holder {
                                warn!(
                                    previous_holder = %doc.holder,
                                    expired_at = %doc.expires_at,
                                    "Taking over an expired lease (previous holder crashed or partitioned)"
                                );
                            }
                        }
                        // Claim, settle, read back: the survivor of a
                        // simultaneous claim is whoever's PUT landed last.
                        let claim = LeaseDoc::new(holder, Utc::now());
                        if let Err(e) = write_claim_once(bucket, &claim).await {
                            warn!(error = %e, "Failed to write lease claim; retrying");
                            tokio::time::sleep(WAIT_POLL).await;
                            continue;
                        }
                        tokio::time::sleep(SETTLE).await;
                        match read(bucket).await {
                            Ok(Some(current))
                                if current.holder == holder =>
                            {
                                info!(holder = %holder, "Single-writer lease acquired");
                                return;
                            }
                            Ok(current) => {
                                info!(
                                    winner = %current.map(|c| c.holder).unwrap_or_default(),
                                    "Lost the lease claim race; waiting"
                                );
                                tokio::time::sleep(WAIT_POLL).await;
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to read back lease claim; retrying");
                                tokio::time::sleep(WAIT_POLL).await;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to read lease; retrying");
                tokio::time::sleep(WAIT_POLL).await;
            }
        }
    }
}

/// Renew the lease. Returns `false` when another instance holds it — the
/// caller must stop writing immediately.
///
/// Transient S3 errors return `true` (still considered held): the TTL gives
/// several heartbeats' worth of slack, and a holder that drops its own lease
/// on a single blip would thrash leadership.
/// [`LEASE_TTL`] as a std duration, for comparing against elapsed wall time.
fn lease_ttl_std() -> Duration {
    Duration::from_secs(LEASE_TTL.num_seconds().max(0) as u64)
}

/// What a renewal attempt established about our hold on the lease.
#[derive(Debug, PartialEq, Eq)]
pub enum RenewOutcome {
    /// The lease is ours and its expiry has been pushed out.
    Renewed,
    /// Another instance holds it, or ours lapsed and may have been taken.
    /// Continuing would split-brain the bucket.
    Lost,
    /// S3 could not be reached, so nothing was established either way. Safe
    /// only while the lease we last wrote is still within its TTL — the caller
    /// tracks that, since this call cannot know when the last success was.
    Indeterminate,
}

pub async fn renew(bucket: &s3::Bucket, holder: &str) -> RenewOutcome {
    match read(bucket).await {
        Ok(Some(doc)) if doc.holder == holder => {
            // Our own name on an expired document is not proof we still hold
            // it: the lease lapsed, so another instance was free to take it,
            // and a release tombstones the document by setting expiry into the
            // past precisely so it is not ours any more. Renewing either would
            // reclaim a lease we had given up.
            if doc.expires_at <= Utc::now() {
                error!(
                    holder = %holder,
                    expired_at = %doc.expires_at,
                    "Lease lapsed before this renewal; not reclaiming it"
                );
                return RenewOutcome::Lost;
            }
            let renewed = LeaseDoc {
                renewed_at: Utc::now(),
                expires_at: Utc::now() + LEASE_TTL,
                ..doc
            };
            if let Err(e) = write(bucket, &renewed).await {
                warn!(error = %e, "Failed to renew lease; will retry at the next heartbeat");
                return RenewOutcome::Indeterminate;
            }
            RenewOutcome::Renewed
        }
        Ok(Some(doc)) => {
            error!(
                holder = %holder,
                current_holder = %doc.holder,
                "Lease is held by another instance"
            );
            RenewOutcome::Lost
        }
        Ok(None) => {
            // Vanished (manual deletion?) — reclaim it.
            warn!(holder = %holder, "Lease document missing; reclaiming");
            match write(bucket, &LeaseDoc::new(holder, Utc::now())).await {
                Ok(()) => RenewOutcome::Renewed,
                Err(e) => {
                    warn!(error = %e, "Failed to reclaim the missing lease document");
                    RenewOutcome::Indeterminate
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to read lease during renewal");
            RenewOutcome::Indeterminate
        }
    }
}

/// Background heartbeat. Exits the PROCESS when the lease turns out to be
/// held by someone else: this instance has already lost exclusivity, and
/// continuing to write would interleave root manifests and double-execute
/// control intents with the new holder. The supervisor restarts the process,
/// which then queues behind the lease like any new instance.
pub fn spawn_heartbeat(
    bucket: &'static s3::Bucket,
    holder: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(RENEW_INTERVAL);
        timer
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; skip it (acquire just wrote).
        timer.tick().await;
        // Acquire wrote the document, so the lease is good for a TTL from here.
        let mut last_renewed = tokio::time::Instant::now();
        loop {
            timer.tick().await;
            match renew(bucket, &holder).await {
                RenewOutcome::Renewed => {
                    last_renewed = tokio::time::Instant::now()
                }
                RenewOutcome::Lost => {
                    error!(
                        holder = %holder,
                        "Exiting: the single-writer lease belongs to another instance and continuing would split-brain the bucket"
                    );
                    std::process::exit(1);
                }
                // S3 said nothing either way. The document we last wrote keeps
                // us the holder until its TTL runs out, so retrying is safe up
                // to that point — but past it the lease is expired as far as
                // every other instance is concerned, and one of them can
                // acquire it while we carry on publishing.
                RenewOutcome::Indeterminate => {
                    let since_renewal = last_renewed.elapsed();
                    if since_renewal >= lease_ttl_std() {
                        error!(
                            holder = %holder,
                            seconds_since_renewal = since_renewal.as_secs(),
                            "Exiting: no lease renewal has succeeded within the TTL, so another instance may already hold it"
                        );
                        std::process::exit(1);
                    }
                    warn!(
                        holder = %holder,
                        seconds_since_renewal = since_renewal.as_secs(),
                        "Lease renewal could not be confirmed; retrying at the next heartbeat"
                    );
                }
            }
        }
    })
}

/// Tombstone the lease on graceful shutdown so the successor doesn't wait
/// out the TTL. Best-effort: failing to release just delays the successor.
pub async fn release(bucket: &s3::Bucket, holder: &str) {
    match read(bucket).await {
        Ok(Some(doc)) if doc.holder == holder => {
            let tombstone = LeaseDoc {
                renewed_at: Utc::now(),
                expires_at: Utc::now() - ChronoDuration::seconds(1),
                ..doc
            };
            match write(bucket, &tombstone).await {
                Ok(()) => info!(holder = %holder, "Lease released"),
                Err(e) => {
                    warn!(error = %e, "Failed to release lease; successor waits for expiry")
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expiry() {
        let doc = LeaseDoc::new("a", Utc::now());
        assert!(!doc.is_expired(Utc::now()));
        assert!(doc.is_expired(Utc::now() + LEASE_TTL + ChronoDuration::seconds(1)));
    }

    #[test]
    fn a_tombstoned_lease_reads_as_expired() {
        // release() tombstones by setting expiry into the past. A renewal that
        // ignored expiry would see its own name and push the lease back out,
        // making the successor sit out the full TTL.
        let mut doc = LeaseDoc::new("a", Utc::now());
        doc.expires_at = Utc::now() - ChronoDuration::seconds(1);
        assert!(doc.is_expired(Utc::now()));
    }

    #[test]
    fn the_ttl_converts_to_a_std_duration_for_elapsed_comparisons() {
        assert_eq!(
            lease_ttl_std().as_secs(),
            LEASE_TTL.num_seconds() as u64,
            "the heartbeat compares elapsed wall time against this"
        );
    }

    #[test]
    fn a_renewal_budget_outlasts_several_indeterminate_heartbeats() {
        // An unreachable S3 must not exit the process on the first failed
        // heartbeat: the document already written keeps us the holder until it
        // expires. But the budget has to run out before that, or another
        // instance can acquire while this one carries on publishing.
        assert!(
            RENEW_INTERVAL < lease_ttl_std(),
            "a single missed renewal must not immediately end the lease"
        );
        assert!(
            lease_ttl_std().as_secs() / RENEW_INTERVAL.as_secs() >= 2,
            "there must be room for more than one retry inside the TTL"
        );
    }

    #[test]
    fn test_holder_ids_are_unique_per_process_identity() {
        let a = holder_id();
        assert!(a.contains(':'));
        assert!(a.split(':').count() >= 3);
    }

    #[test]
    fn test_lease_doc_roundtrip() {
        let doc = LeaseDoc::new("host:1:2", Utc::now());
        let json = serde_json::to_string(&doc).unwrap();
        let back: LeaseDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back.holder, "host:1:2");
        assert_eq!(back.schema_version, 1);
    }
}
