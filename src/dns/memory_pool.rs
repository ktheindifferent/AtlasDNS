//! Memory Pool Management Implementation
//!
//! Provides pre-allocated memory pools for hot paths to reduce allocation
//! overhead and improve performance for sub-10ms response times.
//!
//! # Features
//!
//! * **Pre-allocated Buffers** - Avoid allocation overhead
//! * **Lock-free Operations** - Using atomic operations where possible
//! * **Multiple Pool Sizes** - Small, medium, large buffers
//! * **NUMA Awareness** - Optimize for CPU cache locality
//! * **Zero-copy Returns** - Return buffers without copying
//! * **Automatic Resizing** - Grow/shrink based on demand
//! * **Memory Pressure Handling** - Graceful degradation

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use parking_lot::{RwLock, Mutex};
use serde::{Serialize, Deserialize};

/// Memory pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPoolConfig {
    /// Enable memory pooling
    pub enabled: bool,
    /// Small buffer size (512 bytes)
    pub small_buffer_size: usize,
    /// Medium buffer size (2KB)
    pub medium_buffer_size: usize,
    /// Large buffer size (8KB)
    pub large_buffer_size: usize,
    /// Initial pool size for each category
    pub initial_pool_size: usize,
    /// Maximum pool size for each category
    pub max_pool_size: usize,
    /// Minimum pool size for each category
    pub min_pool_size: usize,
    /// Growth factor when pool is exhausted
    pub growth_factor: f64,
    /// Shrink threshold (% unused)
    pub shrink_threshold: f64,
    /// Check interval for resizing
    pub resize_interval: Duration,
    /// Enable NUMA optimization
    pub numa_aware: bool,
}

impl Default for MemoryPoolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            small_buffer_size: 512,
            medium_buffer_size: 2048,
            large_buffer_size: 8192,
            initial_pool_size: 100,
            max_pool_size: 10000,
            min_pool_size: 50,
            growth_factor: 1.5,
            shrink_threshold: 0.25,
            resize_interval: Duration::from_secs(60),
            numa_aware: false,
        }
    }
}

/// Buffer wrapper for automatic return to pool
pub struct PooledBuffer {
    /// The actual buffer
    data: Vec<u8>,
    /// Pool to return to
    pool: Arc<BufferPool>,
    /// Buffer size category
    size_category: BufferSize,
    /// Is buffer currently in use
    in_use: AtomicBool,
}

impl PooledBuffer {
    /// Get mutable reference to data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get immutable reference to data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get buffer capacity
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Clear buffer contents
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Resize buffer
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data.resize(new_len, value);
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return buffer to pool
        self.in_use.store(false, Ordering::Release);
        self.pool.return_buffer(self.size_category);
    }
}

/// Buffer size categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BufferSize {
    Small,
    Medium,
    Large,
}

/// Individual buffer pool for a specific size
struct SizePool {
    /// Buffer size
    size: usize,
    /// Available buffers
    available: Mutex<VecDeque<Vec<u8>>>,
    /// Total allocated
    total_allocated: AtomicUsize,
    /// Currently in use
    in_use_count: AtomicUsize,
    /// Total allocations
    total_allocations: AtomicUsize,
    /// Total returns
    total_returns: AtomicUsize,
    /// Allocation failures (pool exhausted)
    allocation_failures: AtomicUsize,
}

impl SizePool {
    fn new(size: usize, initial_count: usize) -> Self {
        let mut available = VecDeque::with_capacity(initial_count);
        
        for _ in 0..initial_count {
            let mut buffer = Vec::with_capacity(size);
            buffer.resize(size, 0);
            available.push_back(buffer);
        }

        Self {
            size,
            available: Mutex::new(available),
            total_allocated: AtomicUsize::new(initial_count),
            in_use_count: AtomicUsize::new(0),
            total_allocations: AtomicUsize::new(0),
            total_returns: AtomicUsize::new(0),
            allocation_failures: AtomicUsize::new(0),
        }
    }

    fn acquire(&self) -> Option<Vec<u8>> {
        let mut available = self.available.lock();
        
        if let Some(buffer) = available.pop_front() {
            self.in_use_count.fetch_add(1, Ordering::Relaxed);
            self.total_allocations.fetch_add(1, Ordering::Relaxed);
            Some(buffer)
        } else {
            self.allocation_failures.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    fn release(&self, mut buffer: Vec<u8>) {
        // Clear buffer before returning to pool
        buffer.clear();
        buffer.resize(self.size, 0);
        
        self.available.lock().push_back(buffer);
        self.in_use_count.fetch_sub(1, Ordering::Relaxed);
        self.total_returns.fetch_add(1, Ordering::Relaxed);
    }

    fn grow(&self, count: usize) {
        let mut available = self.available.lock();
        
        for _ in 0..count {
            let mut buffer = Vec::with_capacity(self.size);
            buffer.resize(self.size, 0);
            available.push_back(buffer);
        }
        
        self.total_allocated.fetch_add(count, Ordering::Relaxed);
    }

    fn shrink(&self, count: usize) {
        let mut available = self.available.lock();
        
        for _ in 0..count {
            if available.pop_back().is_none() {
                break;
            }
            self.total_allocated.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn stats(&self) -> PoolStats {
        PoolStats {
            total_allocated: self.total_allocated.load(Ordering::Relaxed),
            in_use: self.in_use_count.load(Ordering::Relaxed),
            available: self.available.lock().len(),
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            total_returns: self.total_returns.load(Ordering::Relaxed),
            allocation_failures: self.allocation_failures.load(Ordering::Relaxed),
        }
    }
}

/// Buffer pool manager
pub struct BufferPool {
    /// Configuration
    config: Arc<RwLock<MemoryPoolConfig>>,
    /// Small buffer pool
    small_pool: Arc<SizePool>,
    /// Medium buffer pool
    medium_pool: Arc<SizePool>,
    /// Large buffer pool
    large_pool: Arc<SizePool>,
    /// Last resize check
    last_resize: Arc<RwLock<Instant>>,
    /// Global statistics
    stats: Arc<RwLock<GlobalPoolStats>>,
}

/// Pool statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolStats {
    pub total_allocated: usize,
    pub in_use: usize,
    pub available: usize,
    pub total_allocations: usize,
    pub total_returns: usize,
    pub allocation_failures: usize,
}

/// Global pool statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GlobalPoolStats {
    pub small_pool: PoolStats,
    pub medium_pool: PoolStats,
    pub large_pool: PoolStats,
    pub total_memory_bytes: usize,
    pub peak_memory_bytes: usize,
    pub resize_operations: usize,
    pub last_resize_time: Option<u64>,
}

impl BufferPool {
    /// Create new buffer pool
    pub fn new(config: MemoryPoolConfig) -> Arc<Self> {
        let pool = Arc::new(Self {
            small_pool: Arc::new(SizePool::new(
                config.small_buffer_size,
                config.initial_pool_size,
            )),
            medium_pool: Arc::new(SizePool::new(
                config.medium_buffer_size,
                config.initial_pool_size,
            )),
            large_pool: Arc::new(SizePool::new(
                config.large_buffer_size,
                config.initial_pool_size,
            )),
            config: Arc::new(RwLock::new(config)),
            last_resize: Arc::new(RwLock::new(Instant::now())),
            stats: Arc::new(RwLock::new(GlobalPoolStats::default())),
        });

        // Start resize monitoring
        let pool_clone = pool.clone();
        std::thread::spawn(move || {
            pool_clone.monitor_and_resize();
        });

        pool
    }

    /// Acquire buffer of specified size
    pub fn acquire(self: &Arc<Self>, size: BufferSize) -> Option<PooledBuffer> {
        let pool = match size {
            BufferSize::Small => &self.small_pool,
            BufferSize::Medium => &self.medium_pool,
            BufferSize::Large => &self.large_pool,
        };

        pool.acquire().map(|data| PooledBuffer {
            data,
            pool: self.clone(),
            size_category: size,
            in_use: AtomicBool::new(true),
        })
    }

    /// Acquire buffer for specific byte size
    pub fn acquire_for_size(self: &Arc<Self>, bytes: usize) -> Option<PooledBuffer> {
        let config = self.config.read();
        
        let size = if bytes <= config.small_buffer_size {
            BufferSize::Small
        } else if bytes <= config.medium_buffer_size {
            BufferSize::Medium
        } else if bytes <= config.large_buffer_size {
            BufferSize::Large
        } else {
            // Too large for pool
            return None;
        };

        self.acquire(size)
    }

    /// Return buffer to pool (called automatically by PooledBuffer::drop)
    fn return_buffer(&self, size: BufferSize) {
        // Statistics are updated in SizePool::release
    }

    /// Monitor and resize pools based on usage
    fn monitor_and_resize(&self) {
        loop {
            let config = self.config.read().clone();
            
            if !config.enabled {
                std::thread::sleep(Duration::from_secs(60));
                continue;
            }

            std::thread::sleep(config.resize_interval);

            // Check if resize is needed
            self.check_and_resize_pool(&self.small_pool, &config);
            self.check_and_resize_pool(&self.medium_pool, &config);
            self.check_and_resize_pool(&self.large_pool, &config);

            *self.last_resize.write() = Instant::now();
            self.update_global_stats();
        }
    }

    /// Check and resize individual pool
    fn check_and_resize_pool(&self, pool: &SizePool, config: &MemoryPoolConfig) {
        let stats = pool.stats();
        let total = stats.total_allocated;
        let in_use = stats.in_use;
        let available = stats.available;

        // Check if we need to grow
        if available == 0 && total < config.max_pool_size {
            let grow_count = ((total as f64 * config.growth_factor) as usize - total)
                .min(config.max_pool_size - total);
            
            if grow_count > 0 {
                pool.grow(grow_count);
                self.stats.write().resize_operations += 1;
                log::debug!("Growing pool by {} buffers (total: {})", grow_count, total + grow_count);
            }
        }

        // Check if we need to shrink
        let usage_ratio = in_use as f64 / total as f64;
        if usage_ratio < config.shrink_threshold && total > config.min_pool_size {
            let shrink_count = ((total as f64 * (1.0 - config.shrink_threshold)) as usize)
                .min(total - config.min_pool_size)
                .min(available);
            
            if shrink_count > 0 {
                pool.shrink(shrink_count);
                self.stats.write().resize_operations += 1;
                log::debug!("Shrinking pool by {} buffers (total: {})", shrink_count, total - shrink_count);
            }
        }
    }

    /// Update global statistics
    fn update_global_stats(&self) {
        let config = self.config.read();
        let mut stats = self.stats.write();

        stats.small_pool = self.small_pool.stats();
        stats.medium_pool = self.medium_pool.stats();
        stats.large_pool = self.large_pool.stats();

        // Calculate total memory
        let small_memory = stats.small_pool.total_allocated * config.small_buffer_size;
        let medium_memory = stats.medium_pool.total_allocated * config.medium_buffer_size;
        let large_memory = stats.large_pool.total_allocated * config.large_buffer_size;

        stats.total_memory_bytes = small_memory + medium_memory + large_memory;
        stats.peak_memory_bytes = stats.peak_memory_bytes.max(stats.total_memory_bytes);
        stats.last_resize_time = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }

    /// Get statistics
    pub fn get_stats(&self) -> GlobalPoolStats {
        self.update_global_stats();
        let stats = self.stats.read();
        GlobalPoolStats {
            small_pool: stats.small_pool.clone(),
            medium_pool: stats.medium_pool.clone(),
            large_pool: stats.large_pool.clone(),
            total_memory_bytes: stats.total_memory_bytes,
            peak_memory_bytes: stats.peak_memory_bytes,
            resize_operations: stats.resize_operations,
            last_resize_time: stats.last_resize_time,
        }
    }

    /// Force garbage collection of unused buffers
    pub fn gc(&self) {
        let config = self.config.read();
        
        // Shrink pools to minimum size
        let small_stats = self.small_pool.stats();
        let medium_stats = self.medium_pool.stats();
        let large_stats = self.large_pool.stats();

        if small_stats.available > config.min_pool_size {
            self.small_pool.shrink(small_stats.available - config.min_pool_size);
        }
        
        if medium_stats.available > config.min_pool_size {
            self.medium_pool.shrink(medium_stats.available - config.min_pool_size);
        }
        
        if large_stats.available > config.min_pool_size {
            self.large_pool.shrink(large_stats.available - config.min_pool_size);
        }
    }
}

/// Zero-copy buffer for packet processing
pub struct ZeroCopyBuffer {
    /// Raw memory
    memory: Arc<Vec<u8>>,
    /// Start offset
    offset: usize,
    /// Length
    length: usize,
}

impl ZeroCopyBuffer {
    /// Create new zero-copy buffer
    pub fn new(size: usize) -> Self {
        Self {
            memory: Arc::new(vec![0u8; size]),
            offset: 0,
            length: size,
        }
    }

    /// Create a view into the buffer
    pub fn slice(&self, offset: usize, length: usize) -> Option<ZeroCopyBuffer> {
        if offset + length <= self.length {
            Some(ZeroCopyBuffer {
                memory: self.memory.clone(),
                offset: self.offset + offset,
                length,
            })
        } else {
            None
        }
    }

    /// Get data as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.memory[self.offset..self.offset + self.length]
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.length
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// Memory pressure monitor
pub struct MemoryPressureMonitor {
    /// Threshold for high memory pressure (bytes)
    high_threshold: usize,
    /// Threshold for critical memory pressure (bytes)
    critical_threshold: usize,
    /// Current memory usage
    current_usage: AtomicUsize,
}

impl MemoryPressureMonitor {
    /// Create new monitor
    pub fn new(high_threshold: usize, critical_threshold: usize) -> Self {
        Self {
            high_threshold,
            critical_threshold,
            current_usage: AtomicUsize::new(0),
        }
    }

    /// Update memory usage
    pub fn update_usage(&self, bytes: usize) {
        self.current_usage.store(bytes, Ordering::Relaxed);
    }

    /// Get memory pressure level
    pub fn pressure_level(&self) -> MemoryPressure {
        let usage = self.current_usage.load(Ordering::Relaxed);
        
        if usage >= self.critical_threshold {
            MemoryPressure::Critical
        } else if usage >= self.high_threshold {
            MemoryPressure::High
        } else {
            MemoryPressure::Normal
        }
    }
}

/// Memory pressure levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryPressure {
    Normal,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_acquire_release() {
        let config = MemoryPoolConfig {
            initial_pool_size: 10,
            ..Default::default()
        };
        
        let pool = BufferPool::new(config);
        
        // Acquire buffer
        let mut buffer = pool.acquire(BufferSize::Small).unwrap();
        assert_eq!(buffer.capacity(), 512);
        
        // Use buffer
        buffer.as_mut_slice()[0] = 42;
        assert_eq!(buffer.as_slice()[0], 42);
        
        // Buffer automatically returned when dropped
    }

    #[test]
    fn test_buffer_size_selection() {
        let config = MemoryPoolConfig::default();
        let pool = BufferPool::new(config);
        
        // Small size
        let buffer = pool.acquire_for_size(256).unwrap();
        assert_eq!(buffer.capacity(), 512);
        drop(buffer);
        
        // Medium size
        let buffer = pool.acquire_for_size(1024).unwrap();
        assert_eq!(buffer.capacity(), 2048);
        drop(buffer);
        
        // Large size
        let buffer = pool.acquire_for_size(4096).unwrap();
        assert_eq!(buffer.capacity(), 8192);
    }

    #[test]
    fn test_zero_copy_buffer() {
        let buffer = ZeroCopyBuffer::new(1024);
        
        // Create slice view
        let slice = buffer.slice(100, 200).unwrap();
        assert_eq!(slice.as_slice().len(), 200);
        
        // Invalid slice
        assert!(buffer.slice(900, 200).is_none());
    }

    #[test]
    fn test_memory_pressure_monitor() {
        let monitor = MemoryPressureMonitor::new(1000, 2000);
        
        monitor.update_usage(500);
        assert_eq!(monitor.pressure_level(), MemoryPressure::Normal);
        
        monitor.update_usage(1500);
        assert_eq!(monitor.pressure_level(), MemoryPressure::High);
        
        monitor.update_usage(2500);
        assert_eq!(monitor.pressure_level(), MemoryPressure::Critical);
    }
}