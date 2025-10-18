use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Circuit breaker state
#[derive(Debug, Clone)]
enum BreakerState {
    /// Circuit is closed, allowing requests through
    Closed { failures: u32 },
    /// Circuit is open, rejecting all requests
    Open { opened_at: Instant },
    /// Circuit is half-open, allowing a test request through
    HalfOpen,
}

/// Circuit breaker errors
#[derive(Debug)]
pub enum CircuitBreakerError {
    /// Circuit is open, request rejected
    Open,
    /// Request failed
    Failed(crate::infrastructure::error::Error),
}

impl std::fmt::Display for CircuitBreakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerError::Open => write!(f, "Circuit breaker is open"),
            CircuitBreakerError::Failed(e) => write!(f, "Request failed: {}", e),
        }
    }
}

impl std::error::Error for CircuitBreakerError {}

/// Circuit breaker for preventing cascading failures
///
/// Tracks consecutive failures and "opens" the circuit after reaching a threshold,
/// causing all subsequent requests to fail fast. After a reset timeout, the circuit
/// transitions to half-open state, allowing a test request through.
pub struct CircuitBreaker {
    /// Name of the circuit breaker (for logging)
    name: String,
    /// Number of consecutive failures before opening the circuit
    failure_threshold: u32,
    /// Duration to wait before attempting to close the circuit
    reset_timeout: Duration,
    /// Current state of the circuit breaker
    state: Arc<Mutex<BreakerState>>,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker
    ///
    /// # Arguments
    /// * `name` - Name for logging purposes
    /// * `failure_threshold` - Number of consecutive failures before opening
    /// * `reset_timeout` - Duration to wait before trying again
    pub fn new(name: impl Into<String>, failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            name: name.into(),
            failure_threshold,
            reset_timeout,
            state: Arc::new(Mutex::new(BreakerState::Closed { failures: 0 })),
        }
    }

    /// Executes a future with circuit breaker protection
    ///
    /// # Concurrency Model
    ///
    /// This implementation intentionally releases the state lock before executing
    /// the future to avoid holding the lock during potentially long-running I/O
    /// operations. This means:
    ///
    /// - Multiple requests may execute concurrently when the circuit is closed
    /// - In half-open state, multiple test requests may execute if they arrive
    ///   while another is in flight (this is acceptable for our use case)
    /// - State changes are atomic but not synchronized with request execution
    ///
    /// This design prioritizes throughput over strict serialization of requests.
    ///
    /// # Returns
    /// - `Ok(T)` if the operation succeeded
    /// - `Err(CircuitBreakerError::Open)` if the circuit is open
    /// - `Err(CircuitBreakerError::Failed(e))` if the operation failed
    pub async fn call<F, T, E>(&self, future: F) -> Result<T, CircuitBreakerError>
    where
        F: Future<Output = Result<T, E>>,
        E: Into<crate::infrastructure::error::Error>,
    {
        // Check current state
        let mut state = self.state.lock().await;

        if let BreakerState::Open { opened_at } = *state {
            // Check if reset timeout has elapsed
            if opened_at.elapsed() >= self.reset_timeout {
                info!(
                    breaker = %self.name,
                    "Circuit breaker transitioning from open to half-open"
                );
                *state = BreakerState::HalfOpen;
            } else {
                // Circuit is still open, reject request
                return Err(CircuitBreakerError::Open);
            }
        }

        // Release lock before executing the future
        drop(state);

        // Execute the future
        match future.await {
            Ok(result) => {
                // Success - reset or close the circuit
                let mut state = self.state.lock().await;
                match *state {
                    BreakerState::HalfOpen => {
                        info!(
                            breaker = %self.name,
                            "Circuit breaker transitioning from half-open to closed"
                        );
                        *state = BreakerState::Closed { failures: 0 };
                    }
                    BreakerState::Closed { .. } => {
                        *state = BreakerState::Closed { failures: 0 };
                    }
                    _ => {}
                }
                Ok(result)
            }
            Err(error) => {
                let error = error.into();

                // Failure - increment counter or reopen circuit
                let mut state = self.state.lock().await;
                match *state {
                    BreakerState::HalfOpen => {
                        warn!(
                            breaker = %self.name,
                            error = %error,
                            "Circuit breaker transitioning from half-open to open"
                        );
                        *state = BreakerState::Open {
                            opened_at: Instant::now(),
                        };
                    }
                    BreakerState::Closed { failures } => {
                        let new_failures = failures + 1;
                        if new_failures >= self.failure_threshold {
                            warn!(
                                breaker = %self.name,
                                failures = new_failures,
                                threshold = self.failure_threshold,
                                "Circuit breaker opening due to consecutive failures"
                            );
                            *state = BreakerState::Open {
                                opened_at: Instant::now(),
                            };
                        } else {
                            *state = BreakerState::Closed {
                                failures: new_failures,
                            };
                        }
                    }
                    _ => {}
                }

                Err(CircuitBreakerError::Failed(error))
            }
        }
    }

    /// Returns the current state of the circuit breaker (for monitoring/debugging)
    #[allow(dead_code)]
    pub async fn is_open(&self) -> bool {
        matches!(*self.state.lock().await, BreakerState::Open { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_closes_on_success() {
        let breaker = CircuitBreaker::new("test", 3, Duration::from_millis(100));

        // Should succeed
        let result = breaker.call(async { Ok::<_, crate::infrastructure::error::Error>(42) }).await;
        assert!(result.is_ok());
        assert!(!breaker.is_open().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_threshold() {
        let breaker = CircuitBreaker::new("test", 3, Duration::from_millis(100));

        // Fail 3 times
        for _ in 0..3 {
            let _ = breaker.call(async { Err::<(), _>(crate::infrastructure::error::invalid_input("error")) }).await;
        }

        // Circuit should be open
        assert!(breaker.is_open().await);

        // Next call should be rejected immediately
        let result = breaker.call(async { Ok::<_, crate::infrastructure::error::Error>(42) }).await;
        assert!(matches!(result, Err(CircuitBreakerError::Open)));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_after_timeout() {
        let breaker = CircuitBreaker::new("test", 2, Duration::from_millis(50));

        // Fail twice to open circuit
        for _ in 0..2 {
            let _ = breaker.call(async { Err::<(), _>(crate::infrastructure::error::invalid_input("error")) }).await;
        }

        assert!(breaker.is_open().await);

        // Wait for reset timeout
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Next call should go through (half-open state)
        let result = breaker.call(async { Ok::<_, crate::infrastructure::error::Error>(42) }).await;
        assert!(result.is_ok());

        // Circuit should be closed again
        assert!(!breaker.is_open().await);
    }
}
