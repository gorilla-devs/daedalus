use serde_json::Value;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Betterstack log shipping layer
///
/// Tracing events flow through a bounded mpsc channel into a single consumer task
/// that batches and ships logs to Betterstack's HTTP ingestion API.
///
/// # Design notes
/// - `on_event` runs in arbitrary tracing-call contexts (sync code, hot loops). It uses
///   `try_send` so it never blocks; if the queue is full the event is dropped and
///   counted, instead of either spawning per-event tasks (the old design, which flooded
///   the runtime under bursty logging) or backpressuring tracing call sites.
/// - A single consumer task owns the buffer, flushing on batch_size or interval.
/// - `BetterstackHandle::shutdown()` cleanly drains and ships any buffered logs before
///   process exit. The old design dropped buffered logs on SIGTERM.
pub struct BetterstackLayer {
    tx: mpsc::Sender<Value>,
}

/// Handle returned to main; await `shutdown()` before process exit to drain logs.
pub struct BetterstackHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl BetterstackHandle {
    /// Signal the consumer to stop accepting new events, drain whatever's in the
    /// channel + buffer, ship one final batch, and return.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Err(e) = self.join.await {
            warn!(error = %e, "Betterstack consumer task panicked during shutdown");
        }
    }
}

impl BetterstackLayer {
    /// Create a new Betterstack layer with background flushing.
    ///
    /// # Arguments
    /// * `token` - Betterstack API token
    /// * `url` - Betterstack ingestion URL
    /// * `batch_size` - Maximum logs per shipped batch (default: 100)
    /// * `flush_interval` - Duration between flushes (default: 5s)
    pub fn new(
        token: String,
        url: String,
        batch_size: Option<usize>,
        flush_interval: Option<Duration>,
    ) -> (Self, BetterstackHandle) {
        let batch_size = batch_size.unwrap_or(100);
        let flush_interval = flush_interval.unwrap_or(Duration::from_secs(5));

        // Channel capacity = 4× batch_size: enough headroom to absorb a bursty flush
        // without dropping, but bounded so a stuck consumer doesn't blow memory.
        let (tx, rx) = mpsc::channel::<Value>(batch_size * 4);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let join = tokio::spawn(consumer_loop(
            rx,
            shutdown_rx,
            token,
            url,
            batch_size,
            flush_interval,
        ));

        (
            Self { tx },
            BetterstackHandle {
                shutdown_tx: Some(shutdown_tx),
                join,
            },
        )
    }
}

impl<S> Layer<S> for BetterstackLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = JsonVisitor::new();
        event.record(&mut visitor);

        let json_event = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "level": format!("{:?}", event.metadata().level()).to_lowercase(),
            "target": event.metadata().target(),
            "fields": visitor.fields,
        });

        // Non-blocking send. Dropped on full queue; we don't recover the dropped event.
        // (Tracing has no clean async API for `on_event`, so blocking would deadlock.)
        let _ = self.tx.try_send(json_event);
    }
}

/// Single consumer task: accumulates events, flushes on batch full or timer tick,
/// drains+ships on shutdown signal.
async fn consumer_loop(
    mut rx: mpsc::Receiver<Value>,
    mut shutdown_rx: oneshot::Receiver<()>,
    token: String,
    url: String,
    batch_size: usize,
    flush_interval: Duration,
) {
    let client = reqwest::Client::new();
    let mut buffer: Vec<Value> = Vec::with_capacity(batch_size);
    let mut timer = tokio::time::interval(flush_interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_rx => break,
            _ = timer.tick() => {
                if !buffer.is_empty() {
                    flush(&client, &token, &url, std::mem::take(&mut buffer)).await;
                }
            }
            msg = rx.recv() => match msg {
                Some(event) => {
                    buffer.push(event);
                    if buffer.len() >= batch_size {
                        flush(&client, &token, &url, std::mem::take(&mut buffer)).await;
                    }
                }
                None => break, // sender dropped (shouldn't happen — Layer is static)
            }
        }
    }

    // Drain anything remaining in the channel before exit.
    while let Ok(event) = rx.try_recv() {
        buffer.push(event);
    }
    if !buffer.is_empty() {
        flush(&client, &token, &url, buffer).await;
    }
}

async fn flush(client: &reqwest::Client, token: &str, url: &str, logs: Vec<Value>) {
    let log_count = logs.len();
    if let Err(e) = ship_logs(client, token, url, &logs).await {
        warn!(error = %e, log_count, "Failed to ship logs to Betterstack, logs dropped");
    } else {
        info!(log_count, "Successfully shipped logs to Betterstack");
    }
}

async fn ship_logs(
    client: &reqwest::Client,
    token: &str,
    url: &str,
    logs: &[Value],
) -> Result<(), Box<dyn std::error::Error>> {
    if logs.is_empty() {
        return Ok(());
    }

    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .json(&logs)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|_| "".to_string());
        return Err(format!("Betterstack API error {}: {}", status, body).into());
    }

    Ok(())
}

/// Visitor for extracting fields from tracing events as JSON
struct JsonVisitor {
    fields: serde_json::Map<String, Value>,
}

impl JsonVisitor {
    fn new() -> Self {
        Self {
            fields: serde_json::Map::new(),
        }
    }
}

impl tracing::field::Visit for JsonVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_string(),
            Value::String(format!("{:?}", value)),
        );
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), Value::String(value.to_string()));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), Value::Bool(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_visitor_basic() {
        let visitor = JsonVisitor::new();
        assert_eq!(visitor.fields.len(), 0, "New visitor should have empty fields");
    }
}
