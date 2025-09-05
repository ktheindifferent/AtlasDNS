/// Panic Recovery Middleware for Web Server
/// 
/// Provides automatic recovery from panics in request handlers,
/// ensuring the server continues running even when individual requests fail.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::thread;
use tiny_http::{Request, Response};
use serde_json::json;

/// Panic handler middleware
pub struct PanicHandler {
    /// Enable detailed error messages (only in development)
    debug_mode: bool,
    /// Panic counter for monitoring
    panic_count: Arc<std::sync::atomic::AtomicU64>,
}

impl PanicHandler {
    /// Create a new panic handler
    pub fn new(debug_mode: bool) -> Self {
        Self {
            debug_mode,
            panic_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Install global panic handler
    pub fn install_global_handler() {
        // Set custom panic hook
        panic::set_hook(Box::new(|panic_info| {
            let location = panic_info.location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "unknown location".to_string());
            
            let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic payload".to_string()
            };
            
            let thread_name = thread::current()
                .name()
                .unwrap_or("unknown")
                .to_string();
            
            // Log panic with context
            log::error!(
                "PANIC in thread '{}' at {}: {}",
                thread_name, location, message
            );
            
            // Send to Sentry if configured
            #[cfg(feature = "sentry")]
            sentry::capture_message(
                &format!("Panic: {} at {}", message, location),
                sentry::Level::Error
            );
            
            // Log stack trace if available
            let backtrace = std::backtrace::Backtrace::capture();
            if backtrace.status() == std::backtrace::BacktraceStatus::Captured {
                log::error!("Backtrace:\n{}", backtrace);
            }
        }));
    }

    /// Wrap a request handler with panic recovery
    pub fn wrap_handler<F, R>(&self, handler: F) -> impl Fn(Request) -> Result<Response<R>, String>
    where
        F: Fn(Request) -> Result<Response<R>, String> + panic::RefUnwindSafe,
        R: std::io::Read + Send + 'static,
    {
        let panic_count = self.panic_count.clone();
        let debug_mode = self.debug_mode;
        
        move |request: Request| {
            // Capture request info before processing
            let method = request.method().to_string();
            let url = request.url().to_string();
            let remote_addr = request.remote_addr().to_string();
            
            // Run handler with panic protection
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                handler(request)
            }));
            
            match result {
                Ok(response) => response,
                Err(panic_err) => {
                    // Increment panic counter
                    panic_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    
                    // Extract panic message
                    let panic_message = if let Some(s) = panic_err.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_err.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Unknown panic".to_string()
                    };
                    
                    // Log panic details
                    log::error!(
                        "Request panic: {} {} from {} - {}",
                        method, url, remote_addr, panic_message
                    );
                    
                    // Create error response
                    let error_response = if debug_mode {
                        json!({
                            "error": "Internal server error",
                            "message": panic_message,
                            "request": {
                                "method": method,
                                "url": url,
                                "remote_addr": remote_addr
                            }
                        })
                    } else {
                        json!({
                            "error": "Internal server error",
                            "message": "An unexpected error occurred"
                        })
                    };
                    
                    let response_body = error_response.to_string();
                    
                    Err(format!(
                        "HTTP/1.1 500 Internal Server Error\r\n\
                        Content-Type: application/json\r\n\
                        Content-Length: {}\r\n\
                        \r\n\
                        {}",
                        response_body.len(),
                        response_body
                    ))
                }
            }
        }
    }

    /// Get panic statistics
    pub fn get_panic_count(&self) -> u64 {
        self.panic_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reset panic counter
    pub fn reset_panic_count(&self) {
        self.panic_count.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Async panic boundary for tokio tasks
pub async fn with_panic_boundary<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        panic::catch_unwind(AssertUnwindSafe(f))
            .map_err(|e| {
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic in async task".to_string()
                };
                log::error!("Async task panic: {}", msg);
                msg
            })
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

/// Thread panic monitor
pub struct PanicMonitor {
    monitors: Arc<std::sync::RwLock<Vec<ThreadMonitor>>>,
}

#[derive(Debug, Clone)]
struct ThreadMonitor {
    thread_id: thread::ThreadId,
    thread_name: String,
    panic_count: u64,
    last_panic: Option<std::time::Instant>,
}

impl PanicMonitor {
    /// Create a new panic monitor
    pub fn new() -> Self {
        Self {
            monitors: Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    /// Start monitoring current thread
    pub fn monitor_thread(&self, name: String) {
        let thread_id = thread::current().id();
        
        if let Ok(mut monitors) = self.monitors.write() {
            monitors.push(ThreadMonitor {
                thread_id,
                thread_name: name,
                panic_count: 0,
                last_panic: None,
            });
        }
    }

    /// Record a panic for current thread
    pub fn record_panic(&self) {
        let thread_id = thread::current().id();
        let now = std::time::Instant::now();
        
        if let Ok(mut monitors) = self.monitors.write() {
            if let Some(monitor) = monitors.iter_mut().find(|m| m.thread_id == thread_id) {
                monitor.panic_count += 1;
                monitor.last_panic = Some(now);
                
                // Log if thread is panicking frequently
                if monitor.panic_count > 5 {
                    log::warn!(
                        "Thread '{}' has panicked {} times",
                        monitor.thread_name, monitor.panic_count
                    );
                }
            }
        }
    }

    /// Get panic statistics for all threads
    pub fn get_stats(&self) -> Vec<(String, u64)> {
        if let Ok(monitors) = self.monitors.read() {
            monitors.iter()
                .map(|m| (m.thread_name.clone(), m.panic_count))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Check if any thread is unhealthy (too many panics)
    pub fn check_health(&self, threshold: u64) -> bool {
        if let Ok(monitors) = self.monitors.read() {
            monitors.iter().all(|m| m.panic_count < threshold)
        } else {
            false
        }
    }
}

/// Panic recovery wrapper for specific operations
pub fn recover_from_panic<F, T>(operation: F, default: T) -> T
where
    F: FnOnce() -> T + panic::UnwindSafe,
{
    match panic::catch_unwind(operation) {
        Ok(result) => result,
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            log::error!("Recovered from panic: {}", msg);
            default
        }
    }
}

/// Panic boundary for critical sections
#[macro_export]
macro_rules! panic_boundary {
    ($expr:expr) => {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $expr))
    };
    ($expr:expr, $default:expr) => {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $expr))
            .unwrap_or_else(|_| $default)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_recovery() {
        let handler = PanicHandler::new(true);
        assert_eq!(handler.get_panic_count(), 0);
        
        // Test recovery from panic
        let result = recover_from_panic(
            || panic!("test panic"),
            "recovered"
        );
        assert_eq!(result, "recovered");
    }

    #[test]
    fn test_panic_monitor() {
        let monitor = PanicMonitor::new();
        monitor.monitor_thread("test_thread".to_string());
        
        // Record some panics
        monitor.record_panic();
        monitor.record_panic();
        
        let stats = monitor.get_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].0, "test_thread");
        assert_eq!(stats[0].1, 2);
        
        // Check health with threshold
        assert!(monitor.check_health(5));
        assert!(!monitor.check_health(2));
    }

    #[test]
    fn test_panic_boundary_macro() {
        let result = panic_boundary!(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        
        let result = panic_boundary!(panic!("test"), 0);
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn test_async_panic_boundary() {
        let result = with_panic_boundary(|| 42).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        
        let result = with_panic_boundary(|| panic!("async panic")).await;
        assert!(result.is_err());
    }
}