//! Discord webhook notifications.
//!
//! Mirrors the design of `betterstack.rs`: events go through a bounded mpsc
//! channel into a single consumer task that batches and ships to a Discord
//! webhook. `on_event` never blocks — full queue means the event is dropped
//! and counted, never backpressured into tracing call sites.
//!
//! Three notification surfaces:
//! - Auto-capture: an opt-in `DiscordTracingLayer` mirrors `error!`/`warn!`
//!   tracing events into Discord, deduplicated and rate-limited.
//! - Explicit calls: `report_new_mc_version`, `report_new_loader_support`,
//!   `report_error_context` from anywhere in the codebase via the global
//!   `DISCORD` notifier.
//!
//! Webhook failures NEVER propagate. The whole module is best-effort
//! observability — a Discord outage must not stall the metadata pipeline.

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OnceCell, mpsc, oneshot};
use tracing::{info, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Maximum embeds per Discord message (Discord API limit).
const MAX_EMBEDS_PER_MESSAGE: usize = 10;
/// Character budget for one webhook message: Discord rejects messages whose
/// embeds total more than 6000 characters across titles, descriptions and
/// fields. Kept under the hard limit for headroom (markdown rendering counts
/// can differ slightly).
const MESSAGE_CHAR_BUDGET: usize = 5800;
/// Maximum events buffered before drop.
const CHANNEL_CAPACITY: usize = 400;
/// Default flush interval.
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// Suppress duplicate error events with the same fingerprint for this long.
/// Prevents a hot retry loop on a single failing URL from spamming Discord
/// with thousands of identical messages.
const ERROR_DEDUP_TTL: Duration = Duration::from_secs(300);
/// Maximum length of a Discord embed description.
const DISCORD_DESC_MAX: usize = 4000;
/// HTTP timeout for each webhook POST.
const POST_TIMEOUT: Duration = Duration::from_secs(15);

/// Global notifier handle. Lives for the process lifetime.
pub static DISCORD: OnceCell<Arc<DiscordNotifier>> = OnceCell::const_new();

/// Convenience: returns the global notifier if initialized.
pub fn notifier() -> Option<Arc<DiscordNotifier>> {
    DISCORD.get().cloned()
}

/// Event sent to the Discord consumer. Variants render to different embed shapes.
#[derive(Debug, Clone)]
pub enum DiscordEvent {
    /// A new vanilla Minecraft version was observed in Mojang's manifest.
    NewMinecraftVersion {
        id: String,
        version_type: String,
        release_time: Option<String>,
    },
    /// A modloader gained support for a Minecraft version we hadn't seen it
    /// associated with before. Emitted at most once per (loader, mc_version)
    /// pair across the process's persistent state.
    NewLoaderSupport {
        loader: String,
        mc_version: String,
        loader_version: String,
    },
    /// Caught error / issue surfaced via either the tracing layer or an
    /// explicit `report_error_context` call.
    Error {
        level: String,
        target: String,
        message: String,
        fields: HashMap<String, String>,
    },
    /// A positive / informational operator notice that should reach the channel
    /// without the warning styling of `Error` — e.g. a rollback that completed
    /// successfully. Sent directly via `notify`, not through the tracing layer
    /// (which only forwards `warn!`/`error!`).
    Notice { title: String, message: String },
}

/// Notifier — cheap clone, send freely.
pub struct DiscordNotifier {
    tx: mpsc::Sender<DiscordEvent>,
    /// Tracks recent error fingerprints to suppress duplicates. A std mutex
    /// (not an async lock): the critical section is a map probe/insert, and
    /// the callers are synchronous tracing contexts that cannot await.
    error_dedup: std::sync::Mutex<HashMap<String, Instant>>,
}

pub struct DiscordHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl DiscordHandle {
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Err(e) = self.join.await {
            warn!(error = %e, "Discord consumer task panicked during shutdown");
        }
    }
}

impl DiscordNotifier {
    pub fn new(
        webhook_url: String,
        username: Option<String>,
        flush_interval: Option<Duration>,
    ) -> (Arc<Self>, DiscordHandle) {
        let (tx, rx) = mpsc::channel::<DiscordEvent>(CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let join = tokio::spawn(consumer_loop(
            rx,
            shutdown_rx,
            webhook_url,
            username.unwrap_or_else(|| "GDL Daedalus".to_string()),
            flush_interval.unwrap_or(DEFAULT_FLUSH_INTERVAL),
        ));

        let notifier = Arc::new(Self {
            tx,
            error_dedup: std::sync::Mutex::new(HashMap::new()),
        });

        (
            notifier,
            DiscordHandle {
                shutdown_tx: Some(shutdown_tx),
                join,
            },
        )
    }

    /// Try to enqueue an event. Never blocks; drops on full queue.
    pub fn notify(&self, event: DiscordEvent) {
        let _ = self.tx.try_send(event);
    }

    /// Helper: explicit "we just added support for Minecraft `mc_version`
    /// in `loader` for the first time" notification.
    pub fn report_new_loader_support(
        &self,
        loader: &str,
        mc_version: &str,
        loader_version: &str,
    ) {
        self.notify(DiscordEvent::NewLoaderSupport {
            loader: loader.to_string(),
            mc_version: mc_version.to_string(),
            loader_version: loader_version.to_string(),
        });
    }

    /// Helper: explicit "new vanilla Minecraft version" notification.
    pub fn report_new_mc_version(
        &self,
        id: &str,
        version_type: &str,
        release_time: Option<&str>,
    ) {
        self.notify(DiscordEvent::NewMinecraftVersion {
            id: id.to_string(),
            version_type: version_type.to_string(),
            release_time: release_time.map(|s| s.to_string()),
        });
    }

    /// Helper: explicit error context — used at error sites that already
    /// have rich context that the tracing layer might not see (e.g. a
    /// caller decided to `warn!` rather than `error!` but still wants
    /// operator visibility).
    pub fn report_error_context(&self, context: &str, error: impl ToString) {
        let message = format!("{context}: {}", error.to_string());
        if self.should_send_error(&message) {
            let mut fields = HashMap::new();
            fields.insert("context".to_string(), context.to_string());
            self.notify(DiscordEvent::Error {
                level: "error".to_string(),
                target: "daedalus_client".to_string(),
                message,
                fields,
            });
        }
    }

    /// True if the same error message hasn't been pushed recently.
    fn should_send_error(&self, message: &str) -> bool {
        self.should_send_fingerprint(message)
    }

    /// Dedup by arbitrary fingerprint string. Caller chooses the granularity:
    /// the tracing layer fingerprints by (level + message + fields) so two
    /// per-version warnings differing in their fields stay distinct; the
    /// explicit `report_*` helpers fingerprint by message alone since the
    /// caller already shaped the string to be unique.
    ///
    /// Takes the mutex unconditionally: the only time dedup matters is
    /// concurrent bursts of identical events, which is exactly when a
    /// try-lock would fail open and let every duplicate through.
    pub fn should_send_fingerprint(&self, fingerprint: &str) -> bool {
        let now = Instant::now();
        let mut map = self
            .error_dedup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(last) = map.get(fingerprint) {
            if now.duration_since(*last) < ERROR_DEDUP_TTL {
                return false;
            }
        }
        map.retain(|_, t| now.duration_since(*t) < ERROR_DEDUP_TTL);
        map.insert(fingerprint.to_string(), now);
        true
    }
}

/// Tracing layer that forwards `error!` and `warn!` events to Discord via
/// the global notifier. Cheap-no-op when `DISCORD` is uninitialized.
pub struct DiscordTracingLayer;

impl DiscordTracingLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DiscordTracingLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for DiscordTracingLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // Forward warn and error. Warn is the level the codebase uses for
        // "this version was skipped / not parseable / failed status code"
        // — exactly the class of issue operators want surfaced. info and
        // below stay out of Discord to avoid drowning the channel.
        let level = *event.metadata().level();
        if level != tracing::Level::ERROR && level != tracing::Level::WARN {
            return;
        }

        // Only forward events from our own crates — reqwest/hyper/etc.
        // occasionally warn at the transport layer and we don't want them.
        let target = event.metadata().target();
        if !is_app_target(target) {
            return;
        }

        // Don't forward events emitted by the notifier transports themselves.
        // A Discord/Betterstack ship failure logs a `warn!`/`error!`, which
        // would otherwise be re-enqueued here — a feedback loop that floods the
        // bounded channel and crowds out real alerts during an outage.
        if target.starts_with("daedalus_client::services::discord")
            || target.starts_with("daedalus_client::services::betterstack")
        {
            return;
        }

        let Some(notifier) = DISCORD.get().cloned() else {
            return;
        };

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        // Message comes from the "message" field if present; otherwise we
        // concatenate other fields to produce something useful.
        let message = visitor.fields.remove("message").unwrap_or_else(|| {
            visitor
                .fields
                .values()
                .cloned()
                .collect::<Vec<_>>()
                .join(" | ")
        });

        if message.is_empty() {
            return;
        }

        // Fingerprint = level + message + sorted field key/value pairs.
        // Two skipped-version warnings differing only in `forge_id` field
        // produce distinct fingerprints and both make it through; identical
        // events fired in a tight loop (e.g. a stuck retry) dedup.
        let fingerprint = build_fingerprint(&level, &message, &visitor.fields);
        if !notifier.should_send_fingerprint(&fingerprint) {
            return;
        }

        notifier.notify(DiscordEvent::Error {
            level: format!("{:?}", level).to_lowercase(),
            target: target.to_string(),
            message,
            fields: visitor.fields,
        });
    }
}

/// True if the target is one of ours — accepts `daedalus_client`,
/// `daedalus`, and any nested module of those. Filters out
/// transport-layer warnings from reqwest/hyper/rustls/etc.
fn is_app_target(target: &str) -> bool {
    target == "daedalus_client"
        || target == "daedalus"
        || target.starts_with("daedalus_client::")
        || target.starts_with("daedalus::")
}

/// Truncate `s` to at most `max` Unicode characters, appending `…` when
/// truncated. Slicing by byte index (`&s[..max]`) panics when `max` lands
/// inside a multi-byte UTF-8 character, so we truncate on char boundaries.
fn truncate_for_discord(s: String, max: usize) -> String {
    // Byte length is an upper bound on the char count, so this fast path is
    // correct and avoids walking the string for the common short case.
    if s.len() <= max {
        return s;
    }
    if s.chars().count() <= max {
        return s;
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn build_fingerprint(
    level: &tracing::Level,
    message: &str,
    fields: &HashMap<String, String>,
) -> String {
    // Sort field entries so the fingerprint is stable across runs.
    let mut field_entries: Vec<(&String, &String)> = fields.iter().collect();
    field_entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = String::with_capacity(message.len() + 32);
    out.push_str(&format!("{level:?}|{message}"));
    for (k, v) in field_entries {
        out.push('|');
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

#[derive(Default)]
struct FieldVisitor {
    fields: HashMap<String, String>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        self.fields
            .insert(field.name().to_string(), format!("{:?}", value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
}

#[derive(Serialize)]
struct WebhookPayload {
    username: String,
    embeds: Vec<Embed>,
}

#[derive(Serialize, Clone)]
struct Embed {
    title: String,
    description: String,
    color: u32,
    timestamp: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<EmbedField>,
}

#[derive(Serialize, Clone)]
struct EmbedField {
    name: String,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    inline: Option<bool>,
}

/// Background consumer: accumulates events, flushes on batch full or timer
/// tick, drains+ships on shutdown signal. Webhook failures are logged and
/// the batch is dropped — we never block the pipeline on Discord.
async fn consumer_loop(
    mut rx: mpsc::Receiver<DiscordEvent>,
    mut shutdown_rx: oneshot::Receiver<()>,
    webhook_url: String,
    username: String,
    flush_interval: Duration,
) {
    let client = match reqwest::Client::builder()
        .timeout(POST_TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to build Discord HTTP client, notifications disabled");
            return;
        }
    };

    let mut buffer: Vec<DiscordEvent> = Vec::new();
    let mut timer = tokio::time::interval(flush_interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_rx => break,
            _ = timer.tick() => {
                if !buffer.is_empty() {
                    flush(&client, &webhook_url, &username, std::mem::take(&mut buffer)).await;
                }
            }
            msg = rx.recv() => match msg {
                Some(event) => {
                    buffer.push(event);
                    if buffer.len() >= MAX_EMBEDS_PER_MESSAGE {
                        flush(&client, &webhook_url, &username, std::mem::take(&mut buffer)).await;
                    }
                }
                None => break,
            }
        }
    }

    // Drain anything remaining in the channel before exit.
    while let Ok(event) = rx.try_recv() {
        buffer.push(event);
    }
    if !buffer.is_empty() {
        flush(&client, &webhook_url, &username, buffer).await;
    }
}

async fn flush(
    client: &reqwest::Client,
    webhook_url: &str,
    username: &str,
    events: Vec<DiscordEvent>,
) {
    // Pack greedily under BOTH webhook caps: at most 10 embeds per message
    // AND a total character budget across the whole message. Chunking by
    // count alone made a bursty batch of verbose warnings exceed the 6000
    // character message limit — Discord 400s and the entire chunk of alerts
    // is dropped, precisely during incidents.
    let mut batch: Vec<Embed> = Vec::new();
    let mut batch_chars = 0usize;

    for event in events {
        let embed =
            shrink_embed_to_budget(event_to_embed(event), MESSAGE_CHAR_BUDGET);
        let chars = embed_char_count(&embed);

        if !batch.is_empty()
            && (batch.len() >= MAX_EMBEDS_PER_MESSAGE
                || batch_chars + chars > MESSAGE_CHAR_BUDGET)
        {
            send_batch(client, webhook_url, username, std::mem::take(&mut batch))
                .await;
            batch_chars = 0;
        }

        batch_chars += chars;
        batch.push(embed);
    }

    if !batch.is_empty() {
        send_batch(client, webhook_url, username, batch).await;
    }
}

async fn send_batch(
    client: &reqwest::Client,
    webhook_url: &str,
    username: &str,
    embeds: Vec<Embed>,
) {
    let embed_count = embeds.len();
    let payload = WebhookPayload {
        username: username.to_string(),
        embeds,
    };

    if let Err(e) = post_webhook(client, webhook_url, &payload).await {
        warn!(error = %e, embed_count, "Discord webhook flush failed");
    }
}

/// Characters this embed contributes to the message-wide limit.
fn embed_char_count(embed: &Embed) -> usize {
    embed.title.chars().count()
        + embed.description.chars().count()
        + embed
            .fields
            .iter()
            .map(|f| f.name.chars().count() + f.value.chars().count())
            .sum::<usize>()
}

/// Cut a single embed down to the message budget so it can always ship alone:
/// the description shrinks first, then trailing fields drop. An embed built
/// from a long message plus several 1000-character field values can exceed
/// the whole-message budget by itself.
fn shrink_embed_to_budget(mut embed: Embed, budget: usize) -> Embed {
    let overflow = embed_char_count(&embed).saturating_sub(budget);
    if overflow > 0 {
        let desc_chars = embed.description.chars().count();
        let keep = desc_chars.saturating_sub(overflow).max(16);
        embed.description = truncate_for_discord(embed.description, keep);
        while embed_char_count(&embed) > budget && !embed.fields.is_empty() {
            embed.fields.pop();
        }
    }
    embed
}

async fn post_webhook(
    client: &reqwest::Client,
    webhook_url: &str,
    payload: &WebhookPayload,
) -> Result<(), String> {
    let response = client
        .post(webhook_url)
        .header("Content-Type", "application/json")
        .json(payload)
        .send()
        .await
        .map_err(|e| format!("send error: {e}"))?;

    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        // Best-effort: read the retry_after, log it, and drop the batch.
        // This is observability, not load-bearing data; backing off here
        // would require a queue persistence layer we don't want to maintain.
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("?");
        return Err(format!("rate limited (retry_after={retry_after})"));
    }

    if !response.status().is_success() {
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        return Err(format!("HTTP {status}: {body}"));
    }

    Ok(())
}

fn event_to_embed(event: DiscordEvent) -> Embed {
    match event {
        DiscordEvent::NewMinecraftVersion {
            id,
            version_type,
            release_time,
        } => {
            let mut fields = vec![EmbedField {
                name: "Type".to_string(),
                value: version_type,
                inline: Some(true),
            }];
            if let Some(rt) = release_time {
                fields.push(EmbedField {
                    name: "Released".to_string(),
                    value: rt,
                    inline: Some(true),
                });
            }
            Embed {
                title: format!("🟢 New Minecraft version: {id}"),
                description: "A new vanilla Minecraft version has been added to the manifest.".to_string(),
                color: 0x2ecc71, // green
                timestamp: Utc::now().to_rfc3339(),
                fields,
            }
        }
        DiscordEvent::NewLoaderSupport {
            loader,
            mc_version,
            loader_version,
        } => Embed {
            title: format!(
                "🆕 {loader}: first support for Minecraft {mc_version}"
            ),
            description: format!(
                "A `{loader}` build is now available for Minecraft `{mc_version}`."
            ),
            color: 0x3498db, // blue
            timestamp: Utc::now().to_rfc3339(),
            fields: vec![EmbedField {
                name: "Loader version".to_string(),
                value: loader_version,
                inline: Some(true),
            }],
        },
        DiscordEvent::Error {
            level,
            target,
            message,
            fields,
        } => {
            let truncated = truncate_for_discord(message, DISCORD_DESC_MAX);
            let mut embed_fields = vec![EmbedField {
                name: "Target".to_string(),
                value: target,
                inline: Some(true),
            }];
            for (k, v) in fields.into_iter().take(8) {
                if k == "message" {
                    continue;
                }
                let value = truncate_for_discord(v, 1000);
                embed_fields.push(EmbedField {
                    name: k,
                    value,
                    inline: Some(true),
                });
            }
            // Red for errors (hard failure), amber for warnings (issues
            // that don't crash the cycle but mean coverage is degraded:
            // skipped versions, unparsable upstream data, partial fetches).
            let (icon, color) = match level.as_str() {
                "error" => ("🛑", 0xe74c3c),
                _ => ("⚠️", 0xf39c12),
            };
            Embed {
                title: format!("{icon} Daedalus {level}"),
                description: format!("```\n{truncated}\n```"),
                color,
                timestamp: Utc::now().to_rfc3339(),
                fields: embed_fields,
            }
        }
        DiscordEvent::Notice { title, message } => Embed {
            title: format!("✅ {title}"),
            description: truncate_for_discord(message, DISCORD_DESC_MAX),
            color: 0x2ecc71, // green
            timestamp: Utc::now().to_rfc3339(),
            fields: vec![],
        },
    }
}

/// Initialize the global Discord notifier from `DISCORD_WEBHOOK_URL`.
/// Idempotent — calling twice is a no-op. Returns the handle if init
/// succeeded; the caller should `.shutdown().await` it before process exit
/// to ship any pending events.
pub fn try_init_from_env() -> Option<DiscordHandle> {
    let webhook_url = dotenvy::var("DISCORD_WEBHOOK_URL").ok()?;
    if webhook_url.is_empty() {
        return None;
    }

    let username = dotenvy::var("DISCORD_USERNAME").ok();
    let (notifier, handle) = DiscordNotifier::new(webhook_url, username, None);
    match DISCORD.set(notifier) {
        Ok(()) => {
            info!("Discord notifier initialized");
            Some(handle)
        }
        Err(_) => {
            warn!("Discord notifier already initialized; ignoring");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_to_embed_new_mc_version() {
        let embed = event_to_embed(DiscordEvent::NewMinecraftVersion {
            id: "1.21.4".to_string(),
            version_type: "release".to_string(),
            release_time: Some("2024-12-03T10:00:00Z".to_string()),
        });
        assert!(embed.title.contains("1.21.4"));
        assert_eq!(embed.color, 0x2ecc71);
    }

    #[test]
    fn test_event_to_embed_new_loader() {
        let embed = event_to_embed(DiscordEvent::NewLoaderSupport {
            loader: "forge".to_string(),
            mc_version: "1.21.4".to_string(),
            loader_version: "54.0.1".to_string(),
        });
        assert!(embed.title.contains("forge"));
        assert!(embed.title.contains("1.21.4"));
    }

    #[test]
    fn test_event_to_embed_notice_is_green_not_warning() {
        let embed = event_to_embed(DiscordEvent::Notice {
            title: "Rollback performed".to_string(),
            message: "root manifest restored to history entry `x`".to_string(),
        });
        assert!(embed.title.starts_with("✅"));
        assert!(embed.title.contains("Rollback performed"));
        // Green — distinct from the amber/red used for Error events.
        assert_eq!(embed.color, 0x2ecc71);
    }

    #[tokio::test]
    async fn test_dedupe_blocks_repeated_errors() {
        let (notifier, _handle) = DiscordNotifier::new(
            "https://example.invalid".to_string(),
            None,
            None,
        );
        assert!(notifier.should_send_error("boom"));
        assert!(!notifier.should_send_error("boom"));
        assert!(notifier.should_send_error("different"));
    }

    #[test]
    fn test_truncate_for_discord_short_passthrough() {
        assert_eq!(truncate_for_discord("hello".to_string(), 4000), "hello");
    }

    #[test]
    fn test_truncate_for_discord_multibyte_no_panic() {
        // 5000 multi-byte chars = 10_000 bytes. Byte-slicing near the 4000
        // boundary used to panic ("byte index is not a char boundary").
        let out = truncate_for_discord("é".repeat(5000), 4000);
        assert!(out.chars().count() <= 4000);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn test_error_embed_long_multibyte_message_does_not_panic() {
        // Regression: an Error event whose message + field values straddle the
        // byte cutoff on a multi-byte char must produce an embed, not panic.
        let mut fields = std::collections::HashMap::new();
        fields.insert("detail".to_string(), "ü".repeat(5000));
        let embed = event_to_embed(DiscordEvent::Error {
            level: "error".to_string(),
            target: "daedalus_client::x".to_string(),
            message: "字".repeat(5000),
            fields,
        });
        assert!(embed.description.contains('…'));
    }
}
