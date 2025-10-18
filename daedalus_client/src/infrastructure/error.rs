use thiserror::Error;

/// Structured error types for daedalus_client
///
/// Uses thiserror for ergonomic error definitions.
/// Span context is captured by using #[instrument] on functions.
#[derive(Error, Debug)]
pub enum ErrorKind {
    /// Network fetch error with context
    #[error("Failed to fetch {item}: {source}")]
    Fetch {
        #[source]
        source: reqwest::Error,
        item: String,
    },

    /// S3 storage error with file context
    #[error("S3 error for file '{file}': {source}")]
    S3 {
        #[source]
        source: Box<s3::error::S3Error>,
        file: String,
    },

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    SerdeJSON(#[from] serde_json::Error),

    /// XML parsing error
    #[error("XML error: {0}")]
    SerdeXML(#[from] serde_xml_rs::Error),

    /// Zip file error
    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    /// File I/O error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Checksum validation failure
    #[error("Checksum mismatch for {url}: expected {expected}, got {actual} after {tries} tries")]
    ChecksumFailure {
        url: String,
        expected: String,
        actual: String,
        tries: u32,
    },

    /// Invalid input data
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Missing required field
    #[error("Missing required field: {field} in {context}")]
    MissingField { field: String, context: String },

    /// Version parsing error
    #[error("Failed to parse version '{version}': {reason}")]
    VersionParse { version: String, reason: String },

    /// Maven artifact parsing error
    #[error("Failed to parse maven artifact '{artifact}': {reason}")]
    ArtifactParse { artifact: String, reason: String },

    /// Environment variable missing
    #[error("Missing environment variable: {0}")]
    EnvVarMissing(String),

    /// Task join error
    #[error("Task join error: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),

    /// Semaphore acquire error
    #[error("Semaphore acquire error: {0}")]
    SemaphoreAcquire(#[from] tokio::sync::AcquireError),

    /// Daedalus library error
    #[error("Daedalus error: {0}")]
    Daedalus(#[from] daedalus::Error),

    /// Semver parsing error
    #[error("Semver parse error: {0}")]
    SemverParse(#[from] semver::Error),

    /// Generic error with context
    #[error("{context}: {source}")]
    Generic {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Main error type
///
/// Currently just wraps ErrorKind directly. Span context can be added
/// by using tracing spans around operations that produce errors.
pub type Error = ErrorKind;

/// Bridge from anyhow::Error to our structured errors
///
/// This allows gradual migration from anyhow to structured errors.
/// Eventually all anyhow usage will be replaced with specific error types.
impl From<anyhow::Error> for ErrorKind {
    fn from(error: anyhow::Error) -> Self {
        ErrorKind::Generic {
            context: "Legacy anyhow error".to_string(),
            source: error.into(),
        }
    }
}

/// Error classification helpers
impl ErrorKind {
    /// Determines if this error is permanent (won't be fixed by retrying)
    ///
    /// Permanent errors include:
    /// - JSON/XML parsing errors (data is malformed)
    /// - Invalid input (won't change on retry)
    /// - Missing required fields (structural issue)
    ///
    /// Transient errors include:
    /// - Network failures (might work next time)
    /// - Checksum mismatches (file might be re-uploaded)
    /// - 404 errors (resource might appear later)
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            ErrorKind::SerdeJSON(_)
                | ErrorKind::SerdeXML(_)
                | ErrorKind::InvalidInput(_)
                | ErrorKind::MissingField { .. }
                | ErrorKind::VersionParse { .. }
                | ErrorKind::ArtifactParse { .. }
                | ErrorKind::Zip(_)
        )
    }

    /// Determines if this error should trigger a retry
    ///
    /// Retryable errors include:
    /// - Network failures (temporary)
    /// - Checksum failures (might be fixed)
    /// - 5xx server errors (temporary)
    pub fn should_retry(&self) -> bool {
        match self {
            ErrorKind::Fetch { source, .. } => {
                // Retry on network errors, timeouts, or 5xx errors
                source.is_timeout()
                    || source.is_connect()
                    || source
                        .status()
                        .map(|s| s.is_server_error())
                        .unwrap_or(false)
            }
            ErrorKind::ChecksumFailure { .. } => true,
            ErrorKind::S3 { .. } => true,
            _ => false,
        }
    }

    /// Determines if this error indicates a not-found resource
    pub fn is_not_found(&self) -> bool {
        match self {
            ErrorKind::Fetch { source, .. } => {
                source.status().map(|s| s.as_u16() == 404).unwrap_or(false)
            }
            _ => false,
        }
    }

    /// Determines if this error is a network-related issue
    pub fn is_network_error(&self) -> bool {
        matches!(
            self,
            ErrorKind::Fetch { .. } | ErrorKind::ChecksumFailure { .. }
        )
    }
}

/// Helper function to create a fetch error with context
pub fn fetch_error(source: reqwest::Error, item: impl Into<String>) -> Error {
    Error::from(ErrorKind::Fetch {
        source,
        item: item.into(),
    })
}

/// Helper function to create an S3 error with context
pub fn s3_error(source: s3::error::S3Error, file: impl Into<String>) -> Error {
    Error::from(ErrorKind::S3 {
        source: Box::new(source),
        file: file.into(),
    })
}

/// Helper function to create an invalid input error
pub fn invalid_input(message: impl Into<String>) -> Error {
    Error::from(ErrorKind::InvalidInput(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_classification() {
        // Permanent errors
        assert!(ErrorKind::SerdeJSON(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "test"
        )))
        .is_permanent());
        assert!(ErrorKind::InvalidInput("test".to_string()).is_permanent());

        // Transient errors
        let checksum_err = ErrorKind::ChecksumFailure {
            url: "http://test".to_string(),
            expected: "abc".to_string(),
            actual: "def".to_string(),
            tries: 3,
        };
        assert!(!checksum_err.is_permanent());
        assert!(checksum_err.should_retry());
    }

    #[test]
    fn test_error_display() {
        let err = ErrorKind::ChecksumFailure {
            url: "http://test.com/file.jar".to_string(),
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
            tries: 3,
        };

        let display = format!("{}", err);
        assert!(display.contains("Checksum mismatch"));
        assert!(display.contains("http://test.com/file.jar"));
        assert!(display.contains("abc123"));
        assert!(display.contains("def456"));
    }
}
