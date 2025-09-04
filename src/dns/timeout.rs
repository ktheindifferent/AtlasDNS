/// DNS Query Timeout Handler
/// 
/// Provides configurable timeout handling for DNS queries with proper
/// cancellation and resource cleanup.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::time::{timeout, sleep};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::dns::client::ClientError;
use crate::dns::protocol::{DnsPacket, QueryType};

/// Timeout configuration for DNS queries
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Default timeout for DNS queries
    pub query_timeout: Duration,
    /// Timeout for recursive queries
    pub recursive_timeout: Duration,
    /// Timeout for TCP connections
    pub tcp_connect_timeout: Duration,
    /// Timeout for UDP queries
    pub udp_timeout: Duration,
    /// Maximum retries on timeout
    pub max_retries: u32,
    /// Timeout backoff multiplier
    pub backoff_multiplier: f32,
    /// Maximum timeout duration
    pub max_timeout: Duration,
    /// Enable adaptive timeout based on RTT
    pub adaptive: bool,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(5),
            recursive_timeout: Duration::from_secs(10),
            tcp_connect_timeout: Duration::from_secs(5),
            udp_timeout: Duration::from_secs(2),
            max_retries: 2,
            backoff_multiplier: 1.5,
            max_timeout: Duration::from_secs(30),
            adaptive: true,
        }
    }
}

/// Query timeout tracker
#[derive(Debug)]
struct QueryTimeout {
    query_id: Uuid,
    query_type: QueryType,
    domain: String,
    started_at: Instant,
    deadline: Instant,
    attempts: u32,
    cancel_tx: Option<oneshot::Sender<()>>,
}

/// Timeout handler for DNS queries
pub struct TimeoutHandler {
    config: TimeoutConfig,
    active_queries: Arc<Mutex<HashMap<Uuid, QueryTimeout>>>,
    rtt_tracker: Arc<Mutex<RttTracker>>,
}

/// RTT (Round-Trip Time) tracker for adaptive timeouts
#[derive(Debug)]
struct RttTracker {
    /// RTT samples per server
    samples: HashMap<SocketAddr, Vec<Duration>>,
    /// Maximum samples to keep per server
    max_samples: usize,
}

impl RttTracker {
    fn new() -> Self {
        Self {
            samples: HashMap::new(),
            max_samples: 100,
        }
    }

    /// Record an RTT sample
    fn record(&mut self, server: SocketAddr, rtt: Duration) {
        let samples = self.samples.entry(server).or_insert_with(Vec::new);
        samples.push(rtt);
        
        // Keep only recent samples
        if samples.len() > self.max_samples {
            samples.drain(0..samples.len() - self.max_samples);
        }
    }

    /// Get estimated timeout for server
    fn get_timeout(&self, server: SocketAddr, base_timeout: Duration) -> Duration {
        if let Some(samples) = self.samples.get(&server) {
            if !samples.is_empty() {
                // Calculate P99 RTT
                let mut sorted = samples.clone();
                sorted.sort();
                let p99_idx = (samples.len() as f64 * 0.99) as usize;
                let p99_rtt = sorted.get(p99_idx).copied().unwrap_or(base_timeout);
                
                // Use 3x P99 as timeout, capped at base_timeout
                return (p99_rtt * 3).min(base_timeout);
            }
        }
        base_timeout
    }

    /// Get average RTT for server
    fn get_average_rtt(&self, server: SocketAddr) -> Option<Duration> {
        if let Some(samples) = self.samples.get(&server) {
            if !samples.is_empty() {
                let sum: Duration = samples.iter().sum();
                return Some(sum / samples.len() as u32);
            }
        }
        None
    }
}

impl TimeoutHandler {
    /// Create a new timeout handler
    pub fn new(config: TimeoutConfig) -> Self {
        Self {
            config,
            active_queries: Arc::new(Mutex::new(HashMap::new())),
            rtt_tracker: Arc::new(Mutex::new(RttTracker::new())),
        }
    }

    /// Execute a DNS query with timeout
    pub async fn query_with_timeout<F, Fut>(
        &self,
        domain: &str,
        query_type: QueryType,
        server: SocketAddr,
        query_fn: F,
    ) -> Result<DnsPacket, ClientError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<DnsPacket, ClientError>>,
    {
        let query_id = Uuid::new_v4();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        
        // Determine timeout based on adaptive settings
        let base_timeout = self.config.query_timeout;
        let timeout_duration = if self.config.adaptive {
            self.rtt_tracker.lock()
                .map(|tracker| tracker.get_timeout(server, base_timeout))
                .unwrap_or(base_timeout)
        } else {
            base_timeout
        };

        // Register query
        {
            let mut queries = self.active_queries.lock()
                .map_err(|_| ClientError::PoisonedLock)?;
            queries.insert(query_id, QueryTimeout {
                query_id,
                query_type,
                domain: domain.to_string(),
                started_at: Instant::now(),
                deadline: Instant::now() + timeout_duration,
                attempts: 0,
                cancel_tx: Some(cancel_tx),
            });
        }

        // Execute query with timeout
        let start = Instant::now();
        let result = tokio::select! {
            res = timeout(timeout_duration, query_fn()) => {
                match res {
                    Ok(Ok(packet)) => {
                        // Record successful RTT
                        let rtt = start.elapsed();
                        if let Ok(mut tracker) = self.rtt_tracker.lock() {
                            tracker.record(server, rtt);
                        }
                        log::debug!("Query for {} completed in {:?}", domain, rtt);
                        Ok(packet)
                    }
                    Ok(Err(e)) => {
                        log::warn!("Query for {} failed: {:?}", domain, e);
                        Err(e)
                    }
                    Err(_) => {
                        log::warn!("Query for {} timed out after {:?}", domain, timeout_duration);
                        Err(ClientError::TimeOut)
                    }
                }
            }
            _ = cancel_rx => {
                log::info!("Query for {} was cancelled", domain);
                Err(ClientError::TimeOut)
            }
        };

        // Clean up query record
        if let Ok(mut queries) = self.active_queries.lock() {
            queries.remove(&query_id);
        }

        result
    }

    /// Execute a query with retries on timeout
    pub async fn query_with_retry<F, Fut>(
        &self,
        domain: &str,
        query_type: QueryType,
        server: SocketAddr,
        query_fn: F,
    ) -> Result<DnsPacket, ClientError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<DnsPacket, ClientError>>,
    {
        let mut timeout_duration = self.config.query_timeout;
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                // Apply backoff
                timeout_duration = Duration::from_secs_f32(
                    timeout_duration.as_secs_f32() * self.config.backoff_multiplier
                ).min(self.config.max_timeout);
                
                log::debug!(
                    "Retrying query for {} (attempt {}/{}), timeout: {:?}",
                    domain, attempt + 1, self.config.max_retries + 1, timeout_duration
                );
                
                // Small delay before retry
                sleep(Duration::from_millis(100 * attempt as u64)).await;
            }

            match timeout(timeout_duration, query_fn()).await {
                Ok(Ok(packet)) => {
                    // Record successful RTT
                    if let Ok(mut tracker) = self.rtt_tracker.lock() {
                        tracker.record(server, Instant::now().duration_since(Instant::now()));
                    }
                    return Ok(packet);
                }
                Ok(Err(e)) if !is_timeout_error(&e) => {
                    // Non-timeout error, don't retry
                    return Err(e);
                }
                Ok(Err(e)) => {
                    last_error = Some(e);
                }
                Err(_) => {
                    last_error = Some(ClientError::TimeOut);
                }
            }
        }

        log::error!(
            "Query for {} failed after {} attempts",
            domain, self.config.max_retries + 1
        );
        Err(last_error.unwrap_or(ClientError::TimeOut))
    }

    /// Cancel a query
    pub fn cancel_query(&self, query_id: Uuid) -> Result<(), ClientError> {
        let mut queries = self.active_queries.lock()
            .map_err(|_| ClientError::PoisonedLock)?;
        
        if let Some(mut query) = queries.remove(&query_id) {
            if let Some(cancel_tx) = query.cancel_tx.take() {
                let _ = cancel_tx.send(());
                log::info!("Cancelled query {} for {}", query_id, query.domain);
            }
        }
        
        Ok(())
    }

    /// Cancel all active queries
    pub fn cancel_all_queries(&self) -> Result<(), ClientError> {
        let mut queries = self.active_queries.lock()
            .map_err(|_| ClientError::PoisonedLock)?;
        
        for (_, mut query) in queries.drain() {
            if let Some(cancel_tx) = query.cancel_tx.take() {
                let _ = cancel_tx.send(());
            }
        }
        
        log::info!("Cancelled all active queries");
        Ok(())
    }

    /// Get active query count
    pub fn active_query_count(&self) -> usize {
        self.active_queries.lock()
            .map(|q| q.len())
            .unwrap_or(0)
    }

    /// Get timeout statistics
    pub fn get_stats(&self) -> TimeoutStats {
        let active_count = self.active_query_count();
        let rtt_samples = self.rtt_tracker.lock()
            .map(|tracker| {
                tracker.samples.iter()
                    .map(|(server, samples)| (*server, samples.len()))
                    .collect()
            })
            .unwrap_or_default();
        
        TimeoutStats {
            active_queries: active_count,
            rtt_samples,
            config: self.config.clone(),
        }
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Clean up stale queries
                if let Ok(mut queries) = self.active_queries.lock() {
                    let now = Instant::now();
                    queries.retain(|id, query| {
                        if now > query.deadline + Duration::from_secs(60) {
                            log::warn!("Removing stale query {} for {}", id, query.domain);
                            false
                        } else {
                            true
                        }
                    });
                }
                
                // Clean up old RTT samples
                if let Ok(mut tracker) = self.rtt_tracker.lock() {
                    tracker.samples.retain(|_, samples| !samples.is_empty());
                }
            }
        });
    }
}

/// Timeout statistics
#[derive(Debug)]
pub struct TimeoutStats {
    pub active_queries: usize,
    pub rtt_samples: HashMap<SocketAddr, usize>,
    pub config: TimeoutConfig,
}

/// Check if error is timeout-related
fn is_timeout_error(error: &ClientError) -> bool {
    matches!(error, ClientError::TimeOut)
}

/// Async timeout wrapper for DNS operations
pub async fn with_timeout<T, F, Fut>(
    duration: Duration,
    f: F,
) -> Result<T, ClientError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, ClientError>>,
{
    match timeout(duration, f()).await {
        Ok(result) => result,
        Err(_) => {
            log::warn!("Operation timed out after {:?}", duration);
            Err(ClientError::TimeOut)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_timeout_handler() {
        let config = TimeoutConfig {
            query_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let handler = TimeoutHandler::new(config);
        
        // Test successful query
        let server = SocketAddr::from_str("8.8.8.8:53").unwrap();
        let result = handler.query_with_timeout(
            "example.com",
            QueryType::A,
            server,
            || async {
                sleep(Duration::from_millis(50)).await;
                Ok(DnsPacket::new())
            },
        ).await;
        
        assert!(result.is_ok());
        
        // Test timeout
        let result = handler.query_with_timeout(
            "example.com",
            QueryType::A,
            server,
            || async {
                sleep(Duration::from_millis(200)).await;
                Ok(DnsPacket::new())
            },
        ).await;
        
        assert!(matches!(result, Err(ClientError::TimeOut)));
    }

    #[test]
    fn test_rtt_tracker() {
        let mut tracker = RttTracker::new();
        let server = SocketAddr::from_str("8.8.8.8:53").unwrap();
        
        // Record some samples
        tracker.record(server, Duration::from_millis(10));
        tracker.record(server, Duration::from_millis(20));
        tracker.record(server, Duration::from_millis(15));
        
        // Check average
        let avg = tracker.get_average_rtt(server);
        assert!(avg.is_some());
        assert_eq!(avg.unwrap().as_millis(), 15);
        
        // Check timeout calculation
        let timeout = tracker.get_timeout(server, Duration::from_secs(5));
        assert!(timeout <= Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_with_timeout_wrapper() {
        // Test successful operation
        let result = with_timeout(Duration::from_millis(100), || async {
            sleep(Duration::from_millis(50)).await;
            Ok::<_, ClientError>(42)
        }).await;
        
        assert_eq!(result.unwrap(), 42);
        
        // Test timeout
        let result = with_timeout(Duration::from_millis(100), || async {
            sleep(Duration::from_millis(200)).await;
            Ok::<_, ClientError>(42)
        }).await;
        
        assert!(matches!(result, Err(ClientError::TimeOut)));
    }
}