//! Per-loader root-reference pins.
//!
//! A pin does NOT pause a loader.  A pinned loader still runs its full cycle —
//! fetch upstream, build, run sanity gates, and (if those pass) upload the
//! fresh loader manifest to its own timestamped S3 path.  The pin changes
//! exactly one thing: when the publish loop assembles the **root manifest**, a
//! pinned loader's reference uses `pinned_to` instead of the freshly-built
//! timestamp.
//!
//! Pin state lives at `v{CAS_VERSION}/admin/pins.json` on S3 so it is durable
//! across restarts and is cleared only by an explicit operator action.

use crate::services::cas::CAS_VERSION;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::{error, info, warn};

/// S3 path where the pins file lives.
pub fn pins_s3_path() -> String {
    format!("v{CAS_VERSION}/admin/pins.json")
}

/// A single loader pin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinEntry {
    /// The loader manifest timestamp to use in the root manifest instead of
    /// the freshly-built one.  Must match the `timestamp` field of an
    /// existing loader manifest on S3.
    pub pinned_to: String,
    /// Human-readable reason (shown by the admin API and in Discord alerts).
    pub reason: String,
    /// When this pin was set (UTC).
    pub set_at: DateTime<Utc>,
    /// SHA-256 hash of the admin token used to set this pin (never store the
    /// raw token).
    pub set_by_token_hash: String,
}

impl PinEntry {
    /// Construct a new pin entry.
    pub fn new(
        pinned_to: impl Into<String>,
        reason: impl Into<String>,
        set_by_token_hash: impl Into<String>,
    ) -> Self {
        Self {
            pinned_to: pinned_to.into(),
            reason: reason.into(),
            set_at: Utc::now(),
            set_by_token_hash: set_by_token_hash.into(),
        }
    }

    /// Age of this pin.
    pub fn age(&self) -> chrono::Duration {
        Utc::now().signed_duration_since(self.set_at)
    }

    /// Returns `true` if the pin is older than `threshold`.
    pub fn is_stale(&self, threshold: chrono::Duration) -> bool {
        self.age() > threshold
    }
}

/// In-memory representation of `pins.json`.
///
/// Keyed by loader name (e.g. `"forge"`, `"fabric"`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Pins(pub BTreeMap<String, PinEntry>);

impl Pins {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Returns the pin for `loader`, if one exists.
    pub fn get(&self, loader: &str) -> Option<&PinEntry> {
        self.0.get(loader)
    }

    /// Set a pin for `loader`.
    pub fn set(&mut self, loader: impl Into<String>, entry: PinEntry) {
        self.0.insert(loader.into(), entry);
    }

    /// Remove a pin for `loader`.  Returns the removed entry, or `None` if
    /// there was no pin.
    pub fn remove(&mut self, loader: &str) -> Option<PinEntry> {
        self.0.remove(loader)
    }

    /// True if `loader` is currently pinned.
    pub fn is_pinned(&self, loader: &str) -> bool {
        self.0.contains_key(loader)
    }

    /// Iterate over all current pins.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PinEntry)> {
        self.0.iter()
    }

    /// Number of active pins.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if there are no active pins.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Result of attempting to load pins, distinguishing an unreadable file from an
/// absent one.
pub enum PinsLoad {
    /// Pins were read — possibly empty, on a 404 first deploy.
    Loaded(Pins),
    /// A non-404 fetch error or a parse failure. The publish loop must NOT
    /// treat this as "no pins active": doing so would republish a rolled-back
    /// loader's fresh build, defeating the pin. The loop holds back the root
    /// commit this cycle instead.
    Unreadable,
}

/// Load pins from S3, distinguishing an unreadable file from an absent one.
///
/// A 404 is "no pins set" (`Loaded` with an empty map). A parse failure or a
/// non-404 fetch error is `Unreadable`: unlike a 404 it must not be silently
/// treated as "no pins active", or a transient blip would drop every active pin
/// for the cycle and republish the very build an operator rolled back from.
pub async fn load_checked(bucket: &s3::Bucket) -> PinsLoad {
    let path = pins_s3_path();
    match bucket.get_object(&path).await {
        Ok(resp) => match serde_json::from_slice::<Pins>(resp.bytes()) {
            Ok(pins) => {
                info!(path = %path, count = pins.len(), "Loaded pins from S3");
                PinsLoad::Loaded(pins)
            }
            Err(e) => {
                error!(path = %path, error = %e, "pins.json exists but could not be parsed; holding back the root publish this cycle rather than dropping an active pin");
                PinsLoad::Unreadable
            }
        },
        Err(s3::error::S3Error::Http(404, _)) => {
            info!(path = %path, "No pins on S3 yet; treating as no active pins");
            PinsLoad::Loaded(Pins::new())
        }
        Err(e) => {
            warn!(path = %path, error = %e, "Failed to fetch pins.json; holding back the root publish this cycle rather than dropping an active pin");
            PinsLoad::Unreadable
        }
    }
}

/// Persist pins to S3.
///
/// Returns an error so callers that need a durable write (e.g. the admin
/// rollback handler) can propagate it.  Callers that call this from the
/// publish loop can choose to log and continue.
pub async fn save(
    bucket: &s3::Bucket,
    pins: &Pins,
) -> Result<(), crate::infrastructure::error::Error> {
    let path = pins_s3_path();
    crate::services::s3_json::save_json(bucket, &path, pins).await?;
    info!(path = %path, count = pins.len(), "Saved pins to S3");
    Ok(())
}

/// Emit a `warn!` for every pin older than `threshold`.
///
/// The `DiscordTracingLayer` auto-forwards `warn!` events, so this is enough
/// to push a Discord reminder.  Called once per cycle by the publish loop.
pub fn warn_stale_pins(pins: &Pins, threshold: chrono::Duration) {
    for (loader, entry) in pins.iter() {
        if entry.is_stale(threshold) {
            let age_hours = entry.age().num_hours();
            warn!(
                loader = %loader,
                pinned_to = %entry.pinned_to,
                age_hours = age_hours,
                reason = %entry.reason,
                "Loader is still pinned (set {} hours ago). Clear it from the enderium admin (daedalus → loader → Clear pin) once upstream has recovered.",
                age_hours,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_roundtrip() {
        let mut pins = Pins::new();
        let entry =
            PinEntry::new("2026-01-01T00-00-00Z", "rollback test", "abc123");
        pins.set("forge", entry.clone());

        let json = serde_json::to_string(&pins).unwrap();
        let back: Pins = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.get("forge").unwrap().pinned_to,
            "2026-01-01T00-00-00Z"
        );
    }

    #[test]
    fn test_pin_is_stale() {
        use chrono::Duration;
        let mut entry = PinEntry::new("ts", "reason", "hash");
        // Manually backdate set_at to 8 hours ago.
        entry.set_at = Utc::now() - Duration::hours(8);
        assert!(entry.is_stale(Duration::hours(6)));
        assert!(!entry.is_stale(Duration::hours(9)));
    }

    #[test]
    fn test_is_pinned() {
        let mut pins = Pins::new();
        assert!(!pins.is_pinned("forge"));
        pins.set("forge", PinEntry::new("ts", "reason", "hash"));
        assert!(pins.is_pinned("forge"));
    }

    #[test]
    fn test_remove_pin() {
        let mut pins = Pins::new();
        pins.set("forge", PinEntry::new("ts", "reason", "hash"));
        let removed = pins.remove("forge");
        assert!(removed.is_some());
        assert!(!pins.is_pinned("forge"));
        assert!(pins.remove("forge").is_none());
    }

    #[test]
    fn test_empty_pins_serializes() {
        let pins = Pins::new();
        let json = serde_json::to_string(&pins).unwrap();
        let back: Pins = serde_json::from_str(&json).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn test_warn_stale_is_silent_for_fresh_pins() {
        use chrono::Duration;
        let mut pins = Pins::new();
        pins.set("forge", PinEntry::new("ts", "reason", "hash"));
        // Should not panic; for fresh pins nothing is logged
        warn_stale_pins(&pins, Duration::hours(6));
    }
}
