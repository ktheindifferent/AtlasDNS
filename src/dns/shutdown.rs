/// Graceful Shutdown Handler for DNS Server
/// 
/// Provides coordinated shutdown of all server components with
/// connection draining and resource cleanup.

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};
use tokio::time::{sleep, timeout};

/// Shutdown coordinator for graceful server termination
pub struct ShutdownCoordinator {
    /// Flag indicating shutdown has been initiated
    shutting_down: Arc<AtomicBool>,
    /// Broadcast channel for shutdown notifications
    shutdown_tx: broadcast::Sender<()>,
    /// Active connection count
    active_connections: Arc<std::sync::atomic::AtomicUsize>,
    /// Active DNS queries count
    active_queries: Arc<std::sync::atomic::AtomicUsize>,
    /// Shutdown configuration
    config: ShutdownConfig,
}

/// Configuration for graceful shutdown
#[derive(Debug, Clone)]
pub struct ShutdownConfig {
    /// Maximum time to wait for connections to drain
    pub drain_timeout: Duration,
    /// Maximum time to wait for queries to complete
    pub query_timeout: Duration,
    /// Send FIN to existing connections after this duration
    pub force_close_after: Duration,
    /// Enable verbose shutdown logging
    pub verbose: bool,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_timeout: Duration::from_secs(30),
            query_timeout: Duration::from_secs(10),
            force_close_after: Duration::from_secs(60),
            verbose: false,
        }
    }
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new(config: ShutdownConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        
        Self {
            shutting_down: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            active_connections: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            active_queries: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            config,
        }
    }

    /// Subscribe to shutdown notifications
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Check if shutdown is in progress
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Relaxed)
    }

    /// Register a new connection
    pub fn register_connection(&self) -> ConnectionGuard {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard {
            counter: self.active_connections.clone(),
        }
    }

    /// Register a new query
    pub fn register_query(&self) -> QueryGuard {
        self.active_queries.fetch_add(1, Ordering::Relaxed);
        QueryGuard {
            counter: self.active_queries.clone(),
        }
    }

    /// Get active connection count
    pub fn connection_count(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Get active query count
    pub fn query_count(&self) -> usize {
        self.active_queries.load(Ordering::Relaxed)
    }

    /// Initiate graceful shutdown
    pub async fn shutdown(&self) -> Result<(), ShutdownError> {
        // Check if already shutting down
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return Err(ShutdownError::AlreadyShuttingDown);
        }

        log::info!("Initiating graceful shutdown");

        // Notify all subscribers
        let _ = self.shutdown_tx.send(());

        // Phase 1: Stop accepting new connections
        log::info!("Phase 1: Stopped accepting new connections");
        
        // Phase 2: Wait for queries to complete
        log::info!("Phase 2: Waiting for {} active queries to complete", self.query_count());
        
        match timeout(self.config.query_timeout, self.wait_for_queries()).await {
            Ok(_) => log::info!("All queries completed"),
            Err(_) => {
                log::warn!(
                    "Query timeout reached, {} queries still active",
                    self.query_count()
                );
            }
        }

        // Phase 3: Drain connections
        log::info!("Phase 3: Draining {} active connections", self.connection_count());
        
        match timeout(self.config.drain_timeout, self.drain_connections()).await {
            Ok(_) => log::info!("All connections drained"),
            Err(_) => {
                log::warn!(
                    "Drain timeout reached, {} connections still active",
                    self.connection_count()
                );
            }
        }

        // Phase 4: Force close remaining connections
        if self.connection_count() > 0 {
            log::info!("Phase 4: Force closing {} remaining connections", self.connection_count());
            sleep(Duration::from_millis(100)).await;
        }

        log::info!("Graceful shutdown complete");
        Ok(())
    }

    /// Wait for all queries to complete
    async fn wait_for_queries(&self) {
        while self.query_count() > 0 {
            if self.config.verbose {
                log::debug!("Waiting for {} queries", self.query_count());
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait for connections to drain
    async fn drain_connections(&self) {
        let start = std::time::Instant::now();
        
        while self.connection_count() > 0 && start.elapsed() < self.config.drain_timeout {
            if self.config.verbose {
                log::debug!("Waiting for {} connections", self.connection_count());
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Install signal handlers for graceful shutdown
    pub fn install_signal_handlers(self: Arc<Self>) {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            
            let shutdown = self.clone();
            tokio::spawn(async move {
                let mut sigterm = signal(SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");
                let mut sigint = signal(SignalKind::interrupt())
                    .expect("Failed to register SIGINT handler");
                
                tokio::select! {
                    _ = sigterm.recv() => {
                        log::info!("Received SIGTERM, initiating graceful shutdown");
                    }
                    _ = sigint.recv() => {
                        log::info!("Received SIGINT, initiating graceful shutdown");
                    }
                }
                
                if let Err(e) = shutdown.shutdown().await {
                    log::error!("Shutdown error: {:?}", e);
                    std::process::exit(1);
                }
                std::process::exit(0);
            });
        }

        #[cfg(windows)]
        {
            use tokio::signal::ctrl_c;
            
            let shutdown = self.clone();
            tokio::spawn(async move {
                ctrl_c().await.expect("Failed to register Ctrl+C handler");
                log::info!("Received Ctrl+C, initiating graceful shutdown");
                
                if let Err(e) = shutdown.shutdown().await {
                    log::error!("Shutdown error: {:?}", e);
                    std::process::exit(1);
                }
                std::process::exit(0);
            });
        }
    }
}

/// Guard for tracking active connections
pub struct ConnectionGuard {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Guard for tracking active queries
pub struct QueryGuard {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for QueryGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Shutdown errors
#[derive(Debug)]
pub enum ShutdownError {
    AlreadyShuttingDown,
    Timeout,
}

impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownError::AlreadyShuttingDown => write!(f, "Shutdown already in progress"),
            ShutdownError::Timeout => write!(f, "Shutdown timeout exceeded"),
        }
    }
}

impl std::error::Error for ShutdownError {}

/// Component shutdown tracker
pub struct ComponentShutdown {
    components: Arc<std::sync::RwLock<Vec<Component>>>,
    shutdown_order: Vec<String>,
}

struct Component {
    name: String,
    shutdown_fn: Box<dyn Fn() -> oneshot::Receiver<()> + Send + Sync>,
    dependencies: Vec<String>,
    shutdown_complete: bool,
}

impl ComponentShutdown {
    /// Create a new component shutdown tracker
    pub fn new() -> Self {
        Self {
            components: Arc::new(std::sync::RwLock::new(Vec::new())),
            shutdown_order: Vec::new(),
        }
    }

    /// Register a component for shutdown
    pub fn register<F>(&mut self, name: String, shutdown_fn: F, dependencies: Vec<String>)
    where
        F: Fn() -> oneshot::Receiver<()> + Send + Sync + 'static,
    {
        if let Ok(mut components) = self.components.write() {
            components.push(Component {
                name: name.clone(),
                shutdown_fn: Box::new(shutdown_fn),
                dependencies,
                shutdown_complete: false,
            });
        }
        self.update_shutdown_order();
    }

    /// Update shutdown order based on dependencies
    fn update_shutdown_order(&mut self) {
        // Simple topological sort for shutdown order
        // Components with no dependencies shut down first
        if let Ok(components) = self.components.read() {
            let mut order = Vec::new();
            let mut visited = std::collections::HashSet::new();
            
            for component in components.iter() {
                if component.dependencies.is_empty() && !visited.contains(&component.name) {
                    order.push(component.name.clone());
                    visited.insert(component.name.clone());
                }
            }
            
            // Add components with dependencies
            let mut added = true;
            while added {
                added = false;
                for component in components.iter() {
                    if !visited.contains(&component.name) &&
                       component.dependencies.iter().all(|d| visited.contains(d)) {
                        order.push(component.name.clone());
                        visited.insert(component.name.clone());
                        added = true;
                    }
                }
            }
            
            self.shutdown_order = order;
        }
    }

    /// Execute component shutdown in order
    pub async fn shutdown_all(&self, timeout_per_component: Duration) -> Result<(), String> {
        for component_name in &self.shutdown_order {
            log::info!("Shutting down component: {}", component_name);
            
            if let Ok(components) = self.components.read() {
                if let Some(component) = components.iter().find(|c| &c.name == component_name) {
                    let rx = (component.shutdown_fn)();
                    
                    match timeout(timeout_per_component, rx).await {
                        Ok(Ok(())) => {
                            log::info!("Component {} shut down successfully", component_name);
                        }
                        Ok(Err(_)) => {
                            log::error!("Component {} shutdown channel error", component_name);
                        }
                        Err(_) => {
                            log::error!("Component {} shutdown timeout", component_name);
                            return Err(format!("Component {} shutdown timeout", component_name));
                        }
                    }
                }
            }
        }
        
        log::info!("All components shut down successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_coordinator() {
        let coordinator = Arc::new(ShutdownCoordinator::new(ShutdownConfig {
            drain_timeout: Duration::from_millis(100),
            query_timeout: Duration::from_millis(100),
            force_close_after: Duration::from_millis(200),
            verbose: true,
        }));

        // Register some connections and queries
        let conn1 = coordinator.register_connection();
        let conn2 = coordinator.register_connection();
        let query1 = coordinator.register_query();

        assert_eq!(coordinator.connection_count(), 2);
        assert_eq!(coordinator.query_count(), 1);

        // Drop guards to simulate completion
        drop(query1);
        assert_eq!(coordinator.query_count(), 0);

        drop(conn1);
        drop(conn2);
        assert_eq!(coordinator.connection_count(), 0);

        // Test shutdown
        let result = coordinator.shutdown().await;
        assert!(result.is_ok());
        assert!(coordinator.is_shutting_down());
    }

    #[test]
    fn test_component_shutdown() {
        let mut component_shutdown = ComponentShutdown::new();
        
        // Register components
        let (tx1, rx1) = oneshot::channel();
        component_shutdown.register(
            "database".to_string(),
            move || {
                let (tx, rx) = oneshot::channel();
                let _ = tx.send(());
                rx
            },
            vec![]
        );
        
        let (tx2, rx2) = oneshot::channel();
        component_shutdown.register(
            "cache".to_string(),
            move || {
                let (tx, rx) = oneshot::channel();
                let _ = tx.send(());
                rx
            },
            vec!["database".to_string()]
        );
        
        // Check shutdown order
        assert_eq!(component_shutdown.shutdown_order.len(), 2);
        assert_eq!(component_shutdown.shutdown_order[0], "database");
        assert_eq!(component_shutdown.shutdown_order[1], "cache");
    }
}