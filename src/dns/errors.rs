//! Enhanced error types for DNS operations with context and recovery information

use std::fmt;
use std::error::Error;
use std::io;
use std::sync::PoisonError;
use std::time::Duration;

/// DNS operation error with detailed context
#[derive(Debug)]
pub enum DnsError {
    /// Network I/O errors
    Network(NetworkError),
    /// Protocol parsing/formatting errors  
    Protocol(ProtocolError),
    /// Resource exhaustion errors
    ResourceExhaustion(ResourceError),
    /// Configuration errors
    Configuration(ConfigError),
    /// Cache operation errors
    Cache(CacheError),
    /// Timeout errors with context
    Timeout(TimeoutError),
    /// Rate limiting errors
    RateLimited(RateLimitError),
    /// Generic operational error
    Operation(OperationError),
}

#[derive(Debug)]
pub struct NetworkError {
    pub kind: NetworkErrorKind,
    pub endpoint: Option<String>,
    pub retry_after: Option<Duration>,
    pub source: Option<io::Error>,
}

#[derive(Debug)]
pub enum NetworkErrorKind {
    ConnectionRefused,
    ConnectionTimeout,
    BindFailed,
    SendFailed,
    ReceiveFailed,
    ProtocolMismatch,
}

#[derive(Debug)]
pub struct ProtocolError {
    pub kind: ProtocolErrorKind,
    pub packet_id: Option<u16>,
    pub query_name: Option<String>,
    pub recoverable: bool,
}

#[derive(Debug)]
pub enum ProtocolErrorKind {
    MalformedPacket,
    InvalidDomainName,
    UnsupportedRecordType,
    ResponseMismatch,
    TruncatedMessage,
    InvalidRcode,
}

#[derive(Debug)]
pub struct ResourceError {
    pub kind: ResourceErrorKind,
    pub limit: usize,
    pub current: usize,
    pub mitigation: String,
}

#[derive(Debug)]
pub enum ResourceErrorKind {
    MemoryExhausted,
    ConnectionLimitReached,
    ThreadPoolExhausted,
    CacheFull,
    QueueFull,
}

#[derive(Debug)]
pub struct ConfigError {
    pub parameter: String,
    pub value: String,
    pub reason: String,
    pub suggestion: String,
}

#[derive(Debug)]
pub struct CacheError {
    pub operation: CacheOperation,
    pub key: Option<String>,
    pub reason: String,
}

#[derive(Debug)]
pub enum CacheOperation {
    Store,
    Retrieve,
    Evict,
    Clear,
    Persist,
}

#[derive(Debug)]
pub struct TimeoutError {
    pub operation: String,
    pub duration: Duration,
    pub attempts: u32,
    pub next_retry: Option<Duration>,
}

#[derive(Debug)]
pub struct RateLimitError {
    pub client: String,
    pub limit: u32,
    pub window: Duration,
    pub retry_after: Duration,
}

#[derive(Debug)]
pub struct OperationError {
    pub context: String,
    pub details: String,
    pub recovery_hint: Option<String>,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Network(e) => write!(f, "Network error: {:?}", e.kind),
            DnsError::Protocol(e) => write!(f, "Protocol error: {:?}", e.kind),
            DnsError::ResourceExhaustion(e) => {
                write!(f, "Resource exhausted: {:?} ({}/{})", e.kind, e.current, e.limit)
            }
            DnsError::Configuration(e) => {
                write!(f, "Configuration error: {} = {} ({})", e.parameter, e.value, e.reason)
            }
            DnsError::Cache(e) => write!(f, "Cache error during {:?}: {}", e.operation, e.reason),
            DnsError::Timeout(e) => {
                write!(f, "Operation '{}' timed out after {:?}", e.operation, e.duration)
            }
            DnsError::RateLimited(e) => {
                write!(f, "Rate limited: {} exceeded {} requests per {:?}", 
                       e.client, e.limit, e.window)
            }
            DnsError::Operation(e) => write!(f, "Operation failed: {} - {}", e.context, e.details),
        }
    }
}

impl Error for DnsError {}

// Conversion traits for common error types
impl From<io::Error> for DnsError {
    fn from(err: io::Error) -> Self {
        DnsError::Network(NetworkError {
            kind: match err.kind() {
                io::ErrorKind::ConnectionRefused => NetworkErrorKind::ConnectionRefused,
                io::ErrorKind::TimedOut => NetworkErrorKind::ConnectionTimeout,
                io::ErrorKind::AddrInUse => NetworkErrorKind::BindFailed,
                _ => NetworkErrorKind::SendFailed,
            },
            endpoint: None,
            retry_after: None,
            source: Some(err),
        })
    }
}

impl<T> From<PoisonError<T>> for DnsError {
    fn from(_: PoisonError<T>) -> Self {
        DnsError::Operation(OperationError {
            context: "Lock acquisition".to_string(),
            details: "A lock was poisoned by a panicked thread".to_string(),
            recovery_hint: Some("Consider restarting the affected component".to_string()),
        })
    }
}

/// Result type alias for DNS operations
pub type DnsResult<T> = Result<T, DnsError>;

/// Builder for creating detailed error contexts
pub struct ErrorContext {
    error: DnsError,
}

impl ErrorContext {
    pub fn network(kind: NetworkErrorKind) -> Self {
        ErrorContext {
            error: DnsError::Network(NetworkError {
                kind,
                endpoint: None,
                retry_after: None,
                source: None,
            }),
        }
    }

    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        if let DnsError::Network(ref mut e) = self.error {
            e.endpoint = Some(endpoint);
        }
        self
    }

    pub fn with_retry_after(mut self, duration: Duration) -> Self {
        if let DnsError::Network(ref mut e) = self.error {
            e.retry_after = Some(duration);
        }
        self
    }

    pub fn build(self) -> DnsError {
        self.error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = DnsError::ResourceExhaustion(ResourceError {
            kind: ResourceErrorKind::ConnectionLimitReached,
            limit: 1000,
            current: 1001,
            mitigation: "Increase connection pool size".to_string(),
        });
        
        let display = format!("{}", error);
        assert!(display.contains("Resource exhausted"));
        assert!(display.contains("1001/1000"));
    }

    #[test]
    fn test_error_context_builder() {
        let error = ErrorContext::network(NetworkErrorKind::ConnectionRefused)
            .with_endpoint("8.8.8.8:53".to_string())
            .with_retry_after(Duration::from_secs(5))
            .build();
        
        if let DnsError::Network(e) = error {
            assert_eq!(e.endpoint, Some("8.8.8.8:53".to_string()));
            assert_eq!(e.retry_after, Some(Duration::from_secs(5)));
        } else {
            panic!("Expected Network error");
        }
    }
}