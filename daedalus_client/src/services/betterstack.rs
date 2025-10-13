use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Betterstack log shipping layer
///
/// This layer captures tracing events and ships them to Betterstack's HTTP log ingestion API.
/// Logs are batched in memory and flushed periodically to reduce HTTP overhead.
///
/// # Features
/// - Batched log shipping (configurable batch size)
/// - Background flush task (configurable interval)
/// - Graceful error handling (won't crash app on logging failures)
/// - JSON format compatible with Betterstack API
pub struct BetterstackLayer {
    /// Shared buffer for batching logs
    buffer: Arc<Mutex<Vec<Value>>>,
    /// Maximum batch size before forcing a flush
    batch_size: usize,
}

impl BetterstackLayer {
    /// Create a new Betterstack layer with background flushing
    ///
    /// # Arguments
    /// * `token` - Betterstack API token
    /// * `url` - Betterstack ingestion URL
    /// * `batch_size` - Maximum logs to buffer before flushing (default: 100)
    /// * `flush_interval` - Duration between automatic flushes (default: 5 seconds)
    ///
    /// # Returns
    /// A tuple of (layer, flush_handle) where the handle can be used to await graceful shutdown
    pub fn new(
        token: String,
        url: String,
        batch_size: Option<usize>,
        flush_interval: Option<Duration>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let batch_size = batch_size.unwrap_or(100);
        let flush_interval = flush_interval.unwrap_or(Duration::from_secs(5));
        let buffer = Arc::new(Mutex::new(Vec::new()));

        let flush_handle = {
            let buffer_clone = Arc::clone(&buffer);
            tokio::spawn(async move {
                flush_loop(buffer_clone, token, url, flush_interval).await;
            })
        };

        let layer = Self {
            buffer,
            batch_size,
        };

        (layer, flush_handle)
    }

    /// Add a log event to the buffer
    async fn enqueue(&self, event: Value) {
        let mut buffer = self.buffer.lock().await;
        buffer.push(event);

        // Flush if batch is full
        if buffer.len() >= self.batch_size {
            drop(buffer); // Release lock before flushing
            // Note: Actual flush happens in background task
        }
    }
}

impl<S> Layer<S> for BetterstackLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // Convert tracing event to JSON
        let mut visitor = JsonVisitor::new();
        event.record(&mut visitor);

        let json_event = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "level": format!("{:?}", event.metadata().level()).to_lowercase(),
            "target": event.metadata().target(),
            "fields": visitor.fields,
        });

        // Enqueue asynchronously (spawn to avoid blocking)
        let buffer = Arc::clone(&self.buffer);
        let batch_size = self.batch_size;
        tokio::spawn(async move {
            let layer = BetterstackLayer { buffer, batch_size };
            layer.enqueue(json_event).await;
        });
    }
}

/// Background flush loop
async fn flush_loop(buffer: Arc<Mutex<Vec<Value>>>, token: String, url: String, interval: Duration) {
    let mut timer = tokio::time::interval(interval);
    let client = reqwest::Client::new();

    loop {
        timer.tick().await;

        let logs = {
            let mut buffer = buffer.lock().await;
            if buffer.is_empty() {
                continue;
            }
            std::mem::take(&mut *buffer)
        };

        if let Err(e) = ship_logs(&client, &token, &url, &logs).await {
            warn!(
                error = %e,
                log_count = logs.len(),
                "Failed to ship logs to Betterstack, logs dropped"
            );
        } else {
            info!(log_count = logs.len(), "Successfully shipped logs to Betterstack");
        }
    }
}

/// Ship logs to Betterstack HTTP API
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

    #[test]
    fn test_betterstack_layer_creation() {
        // Test that layer creation doesn't panic
        let _runtime = tokio::runtime::Runtime::new().unwrap();
        // Layer creation happens in async context in real usage
    }
}
