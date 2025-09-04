/// DNS Query Retry Policy and Circuit Breaker Implementation
/// 
/// Provides retry logic with exponential backoff and circuit breaker pattern
/// to handle upstream server failures gracefully.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::dns::client::{ClientError, DnsClient};
use crate::dns::protocol::{DnsPacket, QueryType};

/// Configuration for retry policy
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial backoff duration
    pub initial_backoff: Duration,
    /// Maximum backoff duration
    pub max_backoff: Duration,
    /// Backoff multiplier (e.g., 2.0 for exponential)
    pub backoff_multiplier: f32,
    /// Jitter factor (0.0 to 1.0) to randomize backoff
    pub jitter_factor: f32,
    /// Timeout for individual query attempts
    pub query_timeout: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
            query_timeout: Duration::from_secs(5),
        }
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow normally
    Closed,
    /// Circuit is open, requests are rejected
    Open { opened_at: Instant },
    /// Circuit is half-open, limited requests allowed for testing
    HalfOpen { testing_since: Instant },
}

/// Configuration for circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to open circuit
    pub failure_threshold: u32,
    /// Success threshold to close circuit from half-open
    pub success_threshold: u32,
    /// Duration to keep circuit open before testing
    pub open_duration: Duration,
    /// Maximum duration for half-open state
    pub half_open_timeout: Duration,
    /// Window for tracking failures
    pub failure_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            open_duration: Duration::from_secs(30),
            half_open_timeout: Duration::from_secs(10),
            failure_window: Duration::from_secs(60),
        }
    }
}

/// Circuit breaker for a specific upstream server
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: RwLock<CircuitState>,
    failure_count: RwLock<u32>,
    success_count: RwLock<u32>,
    last_failure_time: RwLock<Option<Instant>>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: RwLock::new(CircuitState::Closed),
            failure_count: RwLock::new(0),
            success_count: RwLock::new(0),
            last_failure_time: RwLock::new(None),
        }
    }

    /// Check if circuit allows request
    pub fn allow_request(&self) -> bool {
        let mut state = self.state.write().expect("Failed to acquire state lock");
        
        match *state {
            CircuitState::Closed => true,
            CircuitState::Open { opened_at } => {
                // Check if enough time has passed to try half-open
                if opened_at.elapsed() >= self.config.open_duration {
                    *state = CircuitState::HalfOpen { 
                        testing_since: Instant::now() 
                    };
                    log::info!("Circuit breaker transitioning to half-open state");
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen { testing_since } => {
                // Allow limited requests in half-open state
                if testing_since.elapsed() <= self.config.half_open_timeout {
                    true
                } else {
                    // Timeout in half-open, reopen circuit
                    *state = CircuitState::Open { 
                        opened_at: Instant::now() 
                    };
                    log::warn!("Circuit breaker half-open timeout, reopening");
                    false
                }
            }
        }
    }

    /// Record successful request
    pub fn record_success(&self) {
        let mut state = self.state.write().expect("Failed to acquire state lock");
        let mut success_count = self.success_count.write().expect("Failed to acquire success count lock");
        let mut failure_count = self.failure_count.write().expect("Failed to acquire failure count lock");
        
        *success_count += 1;
        
        match *state {
            CircuitState::HalfOpen { .. } => {
                if *success_count >= self.config.success_threshold {
                    *state = CircuitState::Closed;
                    *failure_count = 0;
                    *success_count = 0;
                    log::info!("Circuit breaker closed after successful recovery");
                }
            }
            CircuitState::Closed => {
                // Reset failure count on success in closed state
                *failure_count = 0;
            }
            _ => {}
        }
    }

    /// Record failed request
    pub fn record_failure(&self) {
        let mut state = self.state.write().expect("Failed to acquire state lock");
        let mut failure_count = self.failure_count.write().expect("Failed to acquire failure count lock");
        let mut last_failure = self.last_failure_time.write().expect("Failed to acquire last failure lock");
        let now = Instant::now();
        
        // Check if failures are within window
        if let Some(last) = *last_failure {
            if now.duration_since(last) > self.config.failure_window {
                // Reset count if outside window
                *failure_count = 1;
            } else {
                *failure_count += 1;
            }
        } else {
            *failure_count = 1;
        }
        
        *last_failure = Some(now);
        
        match *state {
            CircuitState::Closed => {
                if *failure_count >= self.config.failure_threshold {
                    *state = CircuitState::Open { 
                        opened_at: Instant::now() 
                    };
                    log::warn!(
                        "Circuit breaker opened after {} failures", 
                        *failure_count
                    );
                }
            }
            CircuitState::HalfOpen { .. } => {
                // Single failure in half-open reopens circuit
                *state = CircuitState::Open { 
                    opened_at: Instant::now() 
                };
                *failure_count = 0;
                log::warn!("Circuit breaker reopened after failure in half-open state");
            }
            _ => {}
        }
    }

    /// Get current circuit state
    pub fn get_state(&self) -> CircuitState {
        self.state.read().expect("Failed to acquire state lock").clone()
    }
}

/// Manager for circuit breakers per upstream server
pub struct CircuitBreakerManager {
    breakers: Arc<RwLock<HashMap<SocketAddr, Arc<CircuitBreaker>>>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreakerManager {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Get or create circuit breaker for server
    pub fn get_breaker(&self, server: SocketAddr) -> Arc<CircuitBreaker> {
        let mut breakers = self.breakers.write().expect("Failed to acquire breakers lock");
        
        breakers.entry(server)
            .or_insert_with(|| Arc::new(CircuitBreaker::new(self.config.clone())))
            .clone()
    }

    /// Check if server is available
    pub fn is_server_available(&self, server: SocketAddr) -> bool {
        self.get_breaker(server).allow_request()
    }

    /// Record success for server
    pub fn record_success(&self, server: SocketAddr) {
        self.get_breaker(server).record_success();
    }

    /// Record failure for server
    pub fn record_failure(&self, server: SocketAddr) {
        self.get_breaker(server).record_failure();
    }
}

/// DNS client with retry and circuit breaker capabilities
pub struct ResilientDnsClient<C: DnsClient> {
    inner_client: C,
    retry_config: RetryConfig,
    circuit_manager: Arc<CircuitBreakerManager>,
}

impl<C: DnsClient> ResilientDnsClient<C> {
    pub fn new(
        client: C, 
        retry_config: RetryConfig,
        circuit_config: CircuitBreakerConfig,
    ) -> Self {
        Self {
            inner_client: client,
            retry_config,
            circuit_manager: Arc::new(CircuitBreakerManager::new(circuit_config)),
        }
    }

    /// Send query with retry logic and circuit breaker
    pub fn send_query_with_retry(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket, ClientError> {
        let server_addr: SocketAddr = format!("{}:{}", server.0, server.1)
            .parse()
            .map_err(|_| ClientError::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid server address")
            ))?;

        // Check circuit breaker first
        if !self.circuit_manager.is_server_available(server_addr) {
            log::warn!("Circuit breaker open for {}, skipping", server_addr);
            return Err(ClientError::TimeOut);
        }

        let mut last_error = None;
        let mut backoff = self.retry_config.initial_backoff;

        for attempt in 0..=self.retry_config.max_retries {
            if attempt > 0 {
                // Apply backoff with jitter
                let jitter = if self.retry_config.jitter_factor > 0.0 {
                    let jitter_range = backoff.as_millis() as f32 * self.retry_config.jitter_factor;
                    Duration::from_millis(
                        (rand::random::<f32>() * jitter_range) as u64
                    )
                } else {
                    Duration::ZERO
                };

                let sleep_duration = backoff + jitter;
                log::debug!(
                    "Retry attempt {} for {} after {:?} backoff", 
                    attempt, qname, sleep_duration
                );
                
                std::thread::sleep(sleep_duration);

                // Update backoff for next iteration
                let new_backoff = Duration::from_millis(
                    (backoff.as_millis() as f32 * self.retry_config.backoff_multiplier) as u64
                );
                backoff = new_backoff.min(self.retry_config.max_backoff);
            }

            // Add timeout to query
            let start = Instant::now();
            let result = self.inner_client.send_query(qname, qtype, server, recursive);
            let elapsed = start.elapsed();

            match result {
                Ok(packet) => {
                    self.circuit_manager.record_success(server_addr);
                    log::debug!(
                        "Query for {} succeeded on attempt {} in {:?}", 
                        qname, attempt + 1, elapsed
                    );
                    return Ok(packet);
                }
                Err(e) => {
                    last_error = Some(e);
                    
                    // Check if error is retryable
                    if !self.is_retryable_error(&last_error) {
                        self.circuit_manager.record_failure(server_addr);
                        log::error!(
                            "Non-retryable error for {}: {:?}", 
                            qname, last_error
                        );
                        break;
                    }

                    if attempt < self.retry_config.max_retries {
                        log::warn!(
                            "Query for {} failed on attempt {}, will retry: {:?}", 
                            qname, attempt + 1, last_error
                        );
                    } else {
                        self.circuit_manager.record_failure(server_addr);
                        log::error!(
                            "Query for {} failed after {} attempts", 
                            qname, self.retry_config.max_retries + 1
                        );
                    }
                }
            }
        }

        Err(last_error.unwrap_or(ClientError::TimeOut))
    }

    /// Determine if an error is retryable
    fn is_retryable_error(&self, error: &Option<ClientError>) -> bool {
        match error {
            Some(ClientError::TimeOut) => true,
            Some(ClientError::Io(e)) => {
                // Retry on network errors
                matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut |
                    std::io::ErrorKind::ConnectionRefused |
                    std::io::ErrorKind::ConnectionReset |
                    std::io::ErrorKind::ConnectionAborted |
                    std::io::ErrorKind::UnexpectedEof
                )
            }
            Some(ClientError::LookupFailed) => true,
            _ => false,
        }
    }
}

/// Extension methods for adding retry to existing DNS clients
pub trait RetryableClient: DnsClient + Sized {
    fn with_retry(self, config: RetryConfig) -> ResilientDnsClient<Self> {
        ResilientDnsClient::new(
            self,
            config,
            CircuitBreakerConfig::default(),
        )
    }

    fn with_retry_and_circuit_breaker(
        self, 
        retry_config: RetryConfig,
        circuit_config: CircuitBreakerConfig,
    ) -> ResilientDnsClient<Self> {
        ResilientDnsClient::new(self, retry_config, circuit_config)
    }
}

// Implement for all DnsClient types
impl<T: DnsClient> RetryableClient for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_state_transitions() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            open_duration: Duration::from_millis(100),
            half_open_timeout: Duration::from_millis(50),
            failure_window: Duration::from_secs(60),
        };

        let breaker = CircuitBreaker::new(config);

        // Initial state should be closed
        assert_eq!(breaker.get_state(), CircuitState::Closed);
        assert!(breaker.allow_request());

        // Record failures to open circuit
        breaker.record_failure();
        assert_eq!(breaker.get_state(), CircuitState::Closed);
        breaker.record_failure();
        
        // Should now be open
        match breaker.get_state() {
            CircuitState::Open { .. } => {}
            _ => panic!("Circuit should be open"),
        }
        assert!(!breaker.allow_request());

        // Wait for open duration
        std::thread::sleep(Duration::from_millis(101));
        
        // Should transition to half-open
        assert!(breaker.allow_request());
        match breaker.get_state() {
            CircuitState::HalfOpen { .. } => {}
            _ => panic!("Circuit should be half-open"),
        }

        // Success in half-open should eventually close
        breaker.record_success();
        breaker.record_success();
        assert_eq!(breaker.get_state(), CircuitState::Closed);
    }

    #[test]
    fn test_exponential_backoff() {
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0,
            query_timeout: Duration::from_secs(5),
        };

        let mut backoff = config.initial_backoff;
        
        // First retry: 100ms
        assert_eq!(backoff.as_millis(), 100);
        
        // Second retry: 200ms
        backoff = Duration::from_millis(
            (backoff.as_millis() as f32 * config.backoff_multiplier) as u64
        );
        assert_eq!(backoff.as_millis(), 200);
        
        // Third retry: 400ms
        backoff = Duration::from_millis(
            (backoff.as_millis() as f32 * config.backoff_multiplier) as u64
        );
        assert_eq!(backoff.as_millis(), 400);
    }
}