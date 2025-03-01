use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time::interval;
use serde::Serialize;
use warp::Filter;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Metrics errors
#[derive(Error, Debug)]
pub enum MetricsError {
    #[error("Metrics not initialized")]
    NotInitialized,
    
    #[error("Counter not found: {0}")]
    CounterNotFound(String),
    
    #[error("Timer not found: {0}")]
    TimerNotFound(String),
    
    #[error("Server error: {0}")]
    ServerError(#[from] std::io::Error),
    
    #[error("Invalid metric name: {0}")]
    InvalidName(String),
}

/// Result type for metrics operations
type MetricsResult<T> = Result<T, MetricsError>;

/// Atomic counter for metrics
#[derive(Debug)]
struct Counter {
    value: AtomicU64,
    description: String,
}

impl Counter {
    fn new(description: &str) -> Self {
        Self {
            value: AtomicU64::new(0),
            description: description.to_string(),
        }
    }
    
    fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }
    
    fn add(&self, value: u64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }
    
    fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Timer for measuring durations
#[derive(Debug)]
struct Timer {
    count: AtomicU64,
    sum: AtomicU64,     // in nanoseconds
    min: AtomicU64,     // in nanoseconds
    max: AtomicU64,     // in nanoseconds
    description: String,
}

impl Timer {
    fn new(description: &str) -> Self {
        Self {
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            min: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
            description: description.to_string(),
        }
    }
    
    fn record(&self, duration: Duration) {
        let nanos = duration.as_nanos() as u64;
        
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(nanos, Ordering::Relaxed);
        
        // Update min
        let mut current_min = self.min.load(Ordering::Relaxed);
        while nanos < current_min {
            match self.min.compare_exchange_weak(
                current_min,
                nanos,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_min = actual,
            }
        }
        
        // Update max
        let mut current_max = self.max.load(Ordering::Relaxed);
        while nanos > current_max {
            match self.max.compare_exchange_weak(
                current_max,
                nanos,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }
    }
    
    fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
    
    fn sum(&self) -> Duration {
        Duration::from_nanos(self.sum.load(Ordering::Relaxed))
    }
    
    fn min(&self) -> Duration {
        let min = self.min.load(Ordering::Relaxed);
        if min == u64::MAX {
            Duration::from_nanos(0)
        } else {
            Duration::from_nanos(min)
        }
    }
    
    fn max(&self) -> Duration {
        Duration::from_nanos(self.max.load(Ordering::Relaxed))
    }
    
    fn avg(&self) -> Duration {
        let count = self.count();
        let sum = self.sum.load(Ordering::Relaxed);
        
        if count == 0 {
            Duration::from_nanos(0)
        } else {
            Duration::from_nanos(sum / count)
        }
    }
}

/// Metrics registry
struct MetricsRegistry {
    counters: RwLock<HashMap<String, Arc<Counter>>>,
    timers: RwLock<HashMap<String, Arc<Timer>>>,
    enabled: AtomicBool,
}

impl MetricsRegistry {
    fn new(enabled: bool) -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            timers: RwLock::new(HashMap::new()),
            enabled: AtomicBool::new(enabled),
        }
    }
    
    async fn register_counter(&self, name: &str, description: &str) -> Arc<Counter> {
        let mut counters = self.counters.write().await;
        
        counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Counter::new(description)))
            .clone()
    }
    
    async fn register_timer(&self, name: &str, description: &str) -> Arc<Timer> {
        let mut timers = self.timers.write().await;
        
        timers
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Timer::new(description)))
            .clone()
    }
    
    async fn get_counter(&self, name: &str) -> MetricsResult<Arc<Counter>> {
        let counters = self.counters.read().await;
        
        counters
            .get(name)
            .cloned()
            .ok_or_else(|| MetricsError::CounterNotFound(name.to_string()))
    }
    
    async fn get_timer(&self, name: &str) -> MetricsResult<Arc<Timer>> {
        let timers = self.timers.read().await;
        
        timers
            .get(name)
            .cloned()
            .ok_or_else(|| MetricsError::TimerNotFound(name.to_string()))
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    
    fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }
    
    fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }
    
    async fn collect_metrics(&self) -> Metrics {
        let counters = self.counters.read().await;
        let timers = self.timers.read().await;
        
        let counter_metrics: Vec<CounterMetric> = counters
            .iter()
            .map(|(name, counter)| CounterMetric {
                name: name.clone(),
                value: counter.value(),
                description: counter.description.clone(),
            })
            .collect();
        
        let timer_metrics: Vec<TimerMetric> = timers
            .iter()
            .map(|(name, timer)| TimerMetric {
                name: name.clone(),
                count: timer.count(),
                sum_ms: timer.sum().as_millis() as u64,
                min_ms: timer.min().as_millis() as u64,
                max_ms: timer.max().as_millis() as u64,
                avg_ms: timer.avg().as_millis() as u64,
                description: timer.description.clone(),
            })
            .collect();
        
        Metrics {
            counters: counter_metrics,
            timers: timer_metrics,
        }
    }
}

/// Global metrics registry
static mut METRICS: Option<Arc<MetricsRegistry>> = None;

/// Initialize the metrics system
pub fn init(enabled: bool) -> Arc<MetricsRegistry> {
    let registry = Arc::new(MetricsRegistry::new(enabled));
    
    unsafe {
        METRICS = Some(registry.clone());
    }
    
    registry
}

/// Get the global metrics registry
pub fn registry() -> MetricsResult<Arc<MetricsRegistry>> {
    unsafe {
        METRICS.clone().ok_or(MetricsError::NotInitialized)
    }
}

/// Helper function to time a block of code
pub struct TimerGuard {
    start: Instant,
    timer: Arc<Timer>,
    enabled: bool,
}

impl TimerGuard {
    pub fn new(timer: Arc<Timer>, enabled: bool) -> Self {
        Self {
            start: Instant::now(),
            timer,
            enabled,
        }
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        if self.enabled {
            let duration = self.start.elapsed();
            self.timer.record(duration);
        }
    }
}

/// Counter metric for JSON serialization
#[derive(Serialize, Debug)]
pub struct CounterMetric {
    pub name: String,
    pub value: u64,
    pub description: String,
}

/// Timer metric for JSON serialization
#[derive(Serialize, Debug)]
pub struct TimerMetric {
    pub name: String,
    pub count: u64,
    pub sum_ms: u64,
    pub min_ms: u64,
    pub max_ms: u64,
    pub avg_ms: u64,
    pub description: String,
}

/// Complete metrics structure for JSON serialization
#[derive(Serialize, Debug)]
pub struct Metrics {
    pub counters: Vec<CounterMetric>,
    pub timers: Vec<TimerMetric>,
}

/// Start a metrics HTTP server
pub async fn start_server(addr: SocketAddr) -> MetricsResult<()> {
    let registry = registry()?;
    
    // Define routes
    let metrics_route = warp::path("metrics")
        .and(warp::get())
        .and_then(move || {
            let registry = registry.clone();
            async move {
                let metrics = registry.collect_metrics().await;
                Ok::<_, warp::Rejection>(warp::reply::json(&metrics))
            }
        });
    
    // Health check route
    let health_route = warp::path("health")
        .and(warp::get())
        .map(|| "OK");
    
    let routes = metrics_route.or(health_route);
    
    // Start the server
    println!("Starting metrics server on {}", addr);
    tokio::spawn(async move {
        warp::serve(routes).run(addr).await;
    });
    
    Ok(())
}

/// Helper functions for common metrics operations
pub async fn increment_counter(name: &str) -> MetricsResult<()> {
    let registry = registry()?;
    
    if registry.is_enabled() {
        if let Ok(counter) = registry.get_counter(name).await {
            counter.increment();
        }
    }
    
    Ok(())
}

pub async fn add_to_counter(name: &str, value: u64) -> MetricsResult<()> {
    let registry = registry()?;
    
    if registry.is_enabled() {
        if let Ok(counter) = registry.get_counter(name).await {
            counter.add(value);
        }
    }
    
    Ok(())
}

pub async fn start_timer(name: &str) -> MetricsResult<TimerGuard> {
    let registry = registry()?;
    let enabled = registry.is_enabled();
    
    if enabled {
        if let Ok(timer) = registry.get_timer(name).await {
            return Ok(TimerGuard::new(timer, true));
        }
    }
    
    // If metrics is disabled or timer doesn't exist, return a dummy timer
    let dummy_timer = Arc::new(Timer::new("dummy"));
    Ok(TimerGuard::new(dummy_timer, false))
}

/// DNS-specific metrics registration
pub async fn register_dns_metrics() -> MetricsResult<()> {
    let registry = registry()?;
    
    // Register counters
    registry.register_counter("dns.requests.total", "Total number of DNS requests received").await;
    registry.register_counter("dns.requests.success", "Number of successful DNS responses").await;
    registry.register_counter("dns.requests.error", "Number of failed DNS requests").await;
    registry.register_counter("dns.requests.timeout", "Number of timed out DNS requests").await;
    registry.register_counter("dns.cache.hits", "Number of DNS cache hits").await;
    registry.register_counter("dns.cache.misses", "Number of DNS cache misses").await;
    
    // Register timers
    registry.register_timer("dns.request.duration", "Time taken to process DNS requests").await;
    registry.register_timer("dns.upstream.duration", "Time taken for upstream DNS resolution").await;
    registry.register_timer("dns.cache.lookup.duration", "Time taken for cache lookups").await;
    
    Ok(())
}

/// Start periodic metrics reporting to the console (useful for debugging)
pub async fn start_console_reporter(interval_sec: u64) -> MetricsResult<()> {
    let registry = registry()?;
    
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(interval_sec));
        
        loop {
            interval.tick().await;
            
            if registry.is_enabled() {
                let metrics = registry.collect_metrics().await;
                println!("=== Metrics Report ===");
                
                println!("Counters:");
                for counter in &metrics.counters {
                    println!("  {} = {} ({})", counter.name, counter.value, counter.description);
                }
                
                println!("Timers:");
                for timer in &metrics.timers {
                    println!(
                        "  {} = count: {}, avg: {}ms, min: {}ms, max: {}ms ({})",
                        timer.name,
                        timer.count,
                        timer.avg_ms,
                        timer.min_ms,
                        timer.max_ms,
                        timer.description
                    );
                }
                
                println!("=====================");
            }
        }
    });
    
    Ok(())
}

// Example of how to use the metrics in your DNS proxy code:
/*
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize metrics
    metrics::init(true);
    
    // Register DNS metrics
    metrics::register_dns_metrics().await?;
    
    // Start metrics server
    metrics::start_server("127.0.0.1:9091".parse()?).await?;
    
    // Optionally start console reporter for debugging
    metrics::start_console_reporter(30).await?;
    
    // Your DNS proxy logic here
    loop {
        // When handling a DNS request:
        metrics::increment_counter("dns.requests.total").await?;
        
        // Time DNS request processing
        let timer = metrics::start_timer("dns.request.duration").await?;
        
        // Check cache
        let cache_timer = metrics::start_timer("dns.cache.lookup.duration").await?;
        let cache_hit = check_dns_cache();
        drop(cache_timer);
        
        if cache_hit {
            metrics::increment_counter("dns.cache.hits").await?;
        } else {
            metrics::increment_counter("dns.cache.misses").await?;
            
            // Resolve via upstream DNS
            let upstream_timer = metrics::start_timer("dns.upstream.duration").await?;
            let result = resolve_dns_upstream();
            drop(upstream_timer);
            
            if result.is_ok() {
                metrics::increment_counter("dns.requests.success").await?;
            } else {
                metrics::increment_counter("dns.requests.error").await?;
            }
        }
        
        // Timer automatically records when it goes out of scope
        drop(timer);
        
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn check_dns_cache() -> bool {
    // Your cache lookup logic
    false
}

fn resolve_dns_upstream() -> Result<(), ()> {
    // Your upstream DNS resolution logic
    Ok(())
}
*/