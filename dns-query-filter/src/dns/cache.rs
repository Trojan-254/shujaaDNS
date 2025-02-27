use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::Arc;
use thiserror::Error;
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::RecordType;
use crate::utils::logging::{debug, info, warn, error};
use crate::utils::metrics::increment_counter;

/// Errors that can occur during DNS cache operations
#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Entry expired")]
    EntryExpired,
    
    #[error("Entry not found")]
    EntryNotFound,
    
    #[error("Invalid cache key")]
    InvalidKey,
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Memory limit exceeded")]
    MemoryLimitExceeded,
}

/// Result type for cache operations
type CacheResult<T> = Result<T, CacheError>;

/// Structure to hold a cached DNS response with metadata
#[derive(Clone, Debug)]
struct CacheEntry {
    /// The DNS response message
    response: Message,
    
    /// When this entry was created
    created_at: Instant,
    
    /// Time-to-live in seconds
    ttl: u32,
    
    /// Size of the entry in bytes (approximate)
    size_bytes: usize,
    
    /// Number of times this entry has been accessed
    access_count: u32,
}

impl CacheEntry {
    /// Create a new cache entry
    fn new(response: Message, ttl: u32) -> Self {
        // Approximate size calculation: 
        // - Fixed overhead for the struct
        // - Serialized size of the DNS message 
        // This is approximate but good enough for cache management
        let size_bytes = match response.to_vec() {
            Ok(bytes) => bytes.len() + std::mem::size_of::<Self>(),
            Err(_) => 1024, // Default assumption if serialization fails
        };
        
        Self {
            response,
            created_at: Instant::now(),
            ttl,
            size_bytes,
            access_count: 0,
        }
    }
    
    /// Check if this entry has expired
    fn is_expired(&self) -> bool {
        let age = Instant::now().duration_since(self.created_at).as_secs() as u32;
        age >= self.ttl
    }
    
    /// Record an access to this entry
    fn record_access(&mut self) {
        self.access_count += 1;
    }
    
    /// Get the effective TTL remaining (0 if expired)
    fn remaining_ttl(&self) -> u32 {
        let age = Instant::now().duration_since(self.created_at).as_secs() as u32;
        if age >= self.ttl {
            0
        } else {
            self.ttl - age
        }
    }
    
    /// Update DNS response TTLs based on remaining cache TTL
    fn update_response_ttls(&self) -> Message {
        let mut updated_response = self.response.clone();
        let remaining = self.remaining_ttl();
        
        // Update TTLs in all record sections
        for record in updated_response.answers_mut() {
            // Never set TTL higher than the original
            let current_ttl = record.ttl();
            if current_ttl > remaining {
                record.set_ttl(remaining);
            }
        }
        
        for record in updated_response.name_servers_mut() {
            let current_ttl = record.ttl();
            if current_ttl > remaining {
                record.set_ttl(remaining);
            }
        }
        
        for record in updated_response.additionals_mut() {
            let current_ttl = record.ttl();
            if current_ttl > remaining {
                record.set_ttl(remaining);
            }
        }
        
        updated_response
    }
}

/// Cache key combining domain name and record type
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct CacheKey {
    domain: String,
    record_type: RecordType,
}

impl CacheKey {
    fn new(domain: &str, record_type: RecordType) -> Self {
        // Normalize domain name by ensuring it's lowercase and has trailing dot
        let normalized = if domain.ends_with('.') {
            domain.to_lowercase()
        } else {
            format!("{}.", domain.to_lowercase())
        };
        
        Self {
            domain: normalized,
            record_type,
        }
    }
}

/// Configuration for DNS cache
#[derive(Clone, Debug)]
pub struct DnsCacheConfig {
    /// Maximum number of entries to keep in cache
    pub max_entries: usize,
    
    /// Maximum memory usage in bytes (approximate)
    pub max_memory_bytes: usize,
    
    /// Minimum TTL to use (overrides smaller TTLs)
    pub min_ttl: u32,
    
    /// Maximum TTL to use (overrides larger TTLs)
    pub max_ttl: u32,
    
    /// How often to run cleanup in seconds
    pub cleanup_interval_secs: u64,
    
    /// Enable negative caching (NXDOMAIN, etc.)
    pub enable_negative_caching: bool,
    
    /// TTL for negative responses
    pub negative_ttl: u32,
    
    /// Whether to prefetch entries nearing expiration
    pub enable_prefetch: bool,
    
    /// Prefetch when TTL reaches this percentage of original
    pub prefetch_threshold_percent: u8,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            max_memory_bytes: 50 * 1024 * 1024, // 50 MB
            min_ttl: 60,      // 1 minute
            max_ttl: 86400,   // 24 hours
            cleanup_interval_secs: 300, // 5 minutes
            enable_negative_caching: true,
            negative_ttl: 300, // 5 minutes
            enable_prefetch: true,
            prefetch_threshold_percent: 10,
        }
    }
}

/// The DNS response cache implementation
pub struct DnsCache {
    /// The actual cache storage - domain+type -> entry mapping
    entries: HashMap<CacheKey, CacheEntry>,
    
    /// Configuration for this cache instance
    config: DnsCacheConfig,
    
    /// Current memory usage (approximate)
    memory_usage: usize,
    
    /// Number of cache hits since creation
    hit_count: u64,
    
    /// Number of cache misses since creation
    miss_count: u64,
    
    /// Number of entries evicted due to memory or count limits
    eviction_count: u64,
    
    /// Creation time of this cache instance
    created_at: Instant,
    
    /// Last cleanup time
    last_cleanup: Instant,
    
    /// Callback for prefetching entries (will be set by the DnsProxy)
    prefetch_callback: Option<Arc<dyn Fn(String, RecordType) + Send + Sync>>,
}

impl DnsCache {
    /// Create a new DNS cache with default configuration
    pub fn new() -> Self {
        Self::with_config(DnsCacheConfig::default())
    }
    
    /// Create a new DNS cache with custom configuration
    pub fn with_config(config: DnsCacheConfig) -> Self {
        Self {
            entries: HashMap::with_capacity(config.max_entries / 2),
            config,
            memory_usage: 0,
            hit_count: 0,
            miss_count: 0,
            eviction_count: 0,
            created_at: Instant::now(),
            last_cleanup: Instant::now(),
            prefetch_callback: None,
        }
    }
    
    /// Set a callback function for prefetching cache entries
    pub fn set_prefetch_callback<F>(&mut self, callback: F)
    where
        F: Fn(String, RecordType) + Send + Sync + 'static,
    {
        self.prefetch_callback = Some(Arc::new(callback));
    }
    
    /// Get an entry from the cache
    pub fn get(&self, domain: &str, record_type: RecordType) -> Option<Message> {
        let key = CacheKey::new(domain, record_type);
        
        match self.entries.get(&key) {
            Some(entry) if !entry.is_expired() => {
                // Clone the entry for modification
                let mut entry_clone = entry.clone();
                entry_clone.record_access();
                
                // Check if we should trigger prefetch
                if self.config.enable_prefetch && self.prefetch_callback.is_some() {
                    let original_ttl = entry.ttl;
                    let remaining_ttl = entry.remaining_ttl();
                    let threshold = (original_ttl as f64 * (self.config.prefetch_threshold_percent as f64 / 100.0)) as u32;
                    
                    if remaining_ttl <= threshold {
                        // The entry is close to expiration, trigger prefetch
                        if let Some(ref callback) = self.prefetch_callback {
                            let domain_clone = domain.to_string();
                            let callback_clone = Arc::clone(callback);
                            
                            // Spawn a task to refresh this entry
                            tokio::spawn(async move {
                                callback_clone(domain_clone, record_type);
                            });
                            
                            debug!("Triggered prefetch for {}, type {:?}", domain, record_type);
                        }
                    }
                }
                
                // Get response with updated TTLs
                let response = entry_clone.update_response_ttls();
                
                // Update metrics
                increment_counter("dns_cache_hit");
                
                Some(response)
            },
            Some(_) => {
                // Entry exists but is expired
                increment_counter("dns_cache_expired");
                None
            },
            None => {
                // Entry doesn't exist
                increment_counter("dns_cache_miss");
                None
            }
        }
    }
    
    /// Insert a new entry into the cache
    pub fn insert(&mut self, domain: &str, record_type: RecordType, response: Message, ttl: u32) -> CacheResult<()> {
        // Skip caching for non-cacheable responses
        if !Self::is_cacheable(&response) {
            return Ok(());
        }
        
        // Adjust TTL based on config
        let adjusted_ttl = ttl.clamp(self.config.min_ttl, self.config.max_ttl);
        
        // Create cache key
        let key = CacheKey::new(domain, record_type);
        
        // Create cache entry
        let entry = CacheEntry::new(response, adjusted_ttl);
        
        // Check if we need to make room in the cache
        self.ensure_capacity(entry.size_bytes)?;
        
        // Update memory usage
        self.memory_usage += entry.size_bytes;
        
        // Store the entry
        self.entries.insert(key, entry);
        
        // Update metrics
        increment_counter("dns_cache_insert");
        
        Ok(())
    }
    
    /// Remove an entry from the cache
    pub fn remove(&mut self, domain: &str, record_type: RecordType) -> CacheResult<()> {
        let key = CacheKey::new(domain, record_type);
        
        if let Some(entry) = self.entries.remove(&key) {
            // Update memory usage
            self.memory_usage = self.memory_usage.saturating_sub(entry.size_bytes);
            Ok(())
        } else {
            Err(CacheError::EntryNotFound)
        }
    }
    
    /// Clear the entire cache
    pub fn clear(&mut self) {
        self.entries.clear();
        self.memory_usage = 0;
        info!("DNS cache cleared");
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        
        stats.insert("entries".into(), self.entries.len() as u64);
        stats.insert("memory_bytes".into(), self.memory_usage as u64);
        stats.insert("hits".into(), self.hit_count);
        stats.insert("misses".into(), self.miss_count);
        stats.insert("evictions".into(), self.eviction_count);
        stats.insert("uptime_seconds".into(), self.created_at.elapsed().as_secs());
        
        // Calculate hit ratio
        let total_requests = self.hit_count + self.miss_count;
        let hit_ratio = if total_requests > 0 {
            (self.hit_count as f64 / total_requests as f64 * 100.0) as u64
        } else {
            0
        };
        stats.insert("hit_ratio_percent".into(), hit_ratio);
        
        stats
    }
    
    /// Check if a response is cacheable
    fn is_cacheable(response: &Message) -> bool {
        use trust_dns_proto::op::ResponseCode;
        
        // Basic cacheability checks
        match response.response_code() {
            // Always cache positive responses
            ResponseCode::NoError => {
                // But only if they have answers (unless specifically allowing empty responses)
                !response.answers().is_empty()
            },
            
            // Cache negative responses if enabled
            ResponseCode::NXDomain => true,
            
            // Don't cache error responses
            _ => false,
        }
    }
    
    /// Make room in the cache if needed
    fn ensure_capacity(&mut self, required_size: usize) -> CacheResult<()> {
        // Check if adding this would exceed memory limit
        if self.memory_usage + required_size > self.config.max_memory_bytes {
            // Need to evict entries
            self.evict_entries(required_size)
        } else if self.entries.len() >= self.config.max_entries {
            // Need to evict just one entry to make room
            self.evict_entries(0)
        } else {
            // No eviction needed
            Ok(())
        }
    }
    
    /// Evict cache entries to make room
    fn evict_entries(&mut self, required_size: usize) -> CacheResult<()> {
        // First, remove expired entries
        self.remove_expired();
        
        // If that wasn't enough, evict based on LRU or another policy
        if self.memory_usage + required_size > self.config.max_memory_bytes || 
           self.entries.len() >= self.config.max_entries {
            
            // Collect entries with their keys for evaluation
            let mut entries: Vec<_> = self.entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            
            // Sort by access count (least accessed first) and then by age (oldest first)
            entries.sort_by(|a, b| {
                a.1.access_count.cmp(&b.1.access_count)
                    .then_with(|| b.1.created_at.cmp(&a.1.created_at))
            });
            
            // Determine how many entries to remove
            let mut bytes_to_free = required_size;
            let mut freed_bytes = 0;
            let mut evicted = 0;
            
            for (key, entry) in entries {
                // Stop if we've freed enough space
                if (self.memory_usage - freed_bytes + required_size <= self.config.max_memory_bytes) &&
                   (self.entries.len() - evicted < self.config.max_entries) {
                    break;
                }
                
                // Remove this entry
                if self.entries.remove(&key).is_some() {
                    freed_bytes += entry.size_bytes;
                    evicted += 1;
                    self.eviction_count += 1;
                }
            }
            
            // Update memory usage
            self.memory_usage -= freed_bytes;
            
            debug!("Evicted {} cache entries, freed {} bytes", evicted, freed_bytes);
            increment_counter("dns_cache_evictions");
        }
        
        Ok(())
    }
    
    /// Remove all expired entries from the cache
    fn remove_expired(&mut self) {
        let mut removed = 0;
        let mut freed_bytes = 0;
        
        // Collect keys of expired entries
        let expired_keys: Vec<_> = self.entries
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();
        
        // Remove the expired entries
        for key in expired_keys {
            if let Some(entry) = self.entries.remove(&key) {
                freed_bytes += entry.size_bytes;
                removed += 1;
            }
        }
        
        // Update memory usage
        self.memory_usage -= freed_bytes;
        
        if removed > 0 {
            debug!("Removed {} expired cache entries, freed {} bytes", removed, freed_bytes);
        }
    }
    
    /// Clean up the cache (remove expired entries and enforce limits)
    pub fn cleanup(&mut self) {
        // Time the cleanup operation
        let start = Instant::now();
        
        // Remove expired entries
        self.remove_expired();
        
        // Enforce memory and size limits if needed
        if self.memory_usage > self.config.max_memory_bytes || 
           self.entries.len() > self.config.max_entries {
            if let Err(e) = self.evict_entries(0) {
                error!("Error during cache cleanup: {}", e);
            }
        }
        
        // Update last cleanup time
        self.last_cleanup = Instant::now();
        
        debug!("Cache cleanup completed in {:?}", start.elapsed());
    }
    
    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_proto::op::{Header, Message, MessageType, ResponseCode};
    use trust_dns_proto::rr::{DNSClass, Name, Record, RecordType};
    use std::str::FromStr;
    use std::thread::sleep;
    
    fn create_test_response(id: u16, domain: &str, record_type: RecordType, ttl: u32) -> Message {
        let mut response = Message::new();
        let name = Name::from_str(domain).unwrap();
        
        let mut header = Header::new();
        header.set_id(id);
        header.set_message_type(MessageType::Response);
        header.set_recursion_desired(true);
        header.set_recursion_available(true);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);
        
        response.add_query(trust_dns_proto::op::Query::query(name.clone(), record_type));
        
        // Add a dummy answer record
        let mut record = Record::new();
        record.set_name(name);
        record.set_record_type(record_type);
        record.set_ttl(ttl);
        record.set_dns_class(DNSClass::IN);
        
        response.add_answer(record);
        response
    }
    
    fn create_negative_response(id: u16, domain: &str, record_type: RecordType) -> Message {
        let mut response = Message::new();
        let name = Name::from_str(domain).unwrap();
        
        let mut header = Header::new();
        header.set_id(id);
        header.set_message_type(MessageType::Response);
        header.set_recursion_desired(true);
        header.set_recursion_available(true);
        header.set_response_code(ResponseCode::NXDomain);
        response.set_header(header);
        
        response.add_query(trust_dns_proto::op::Query::query(name, record_type));
        
        response
    }
    
    #[test]
    fn test_cache_key_normalization() {
        // Test that domain names are normalized properly
        let key1 = CacheKey::new("example.com", RecordType::A);
        let key2 = CacheKey::new("ExAmPlE.CoM", RecordType::A);
        let key3 = CacheKey::new("example.com.", RecordType::A);
        
        assert_eq!(key1, key2);
        assert_eq!(key1, key3);
        
        // Different record types should be different keys
        let key4 = CacheKey::new("example.com", RecordType::AAAA);
        assert_ne!(key1, key4);
    }
    
    #[test]
    fn test_cache_basic_operations() {
        let mut cache = DnsCache::new();
        
        // Insert an entry
        let response = create_test_response(1234, "example.com", RecordType::A, 300);
        let result = cache.insert("example.com", RecordType::A, response.clone(), 300);
        assert!(result.is_ok());
        
        // Get the entry
        let retrieved = cache.get("example.com", RecordType::A);
        assert!(retrieved.is_some());
        
        // Different record type should be a miss
        let miss = cache.get("example.com", RecordType::AAAA);
        assert!(miss.is_none());
        
        // Different domain should be a miss
        let miss2 = cache.get("example.org", RecordType::A);
        assert!(miss2.is_none());
        
        // Remove the entry
        let remove_result = cache.remove("example.com", RecordType::A);
        assert!(remove_result.is_ok());
        
        // Should be a miss after removal
        let miss3 = cache.get("example.com", RecordType::A);
        assert!(miss3.is_none());
    }
    
    #[test]
    fn test_cache_expiration() {
        let mut cache = DnsCache::with_config(DnsCacheConfig {
            min_ttl: 1, // 1 second min TTL for testing
            max_ttl: 3600,
            ..DnsCacheConfig::default()
        });
        
        // Insert an entry with a 1 second TTL
        let response = create_test_response(1234, "example.com", RecordType::A, 1);
        let result = cache.insert("example.com", RecordType::A, response.clone(), 1);
        assert!(result.is_ok());
        
        // Should be a hit immediately
        let hit = cache.get("example.com", RecordType::A);
        assert!(hit.is_some());
        
        // Wait for expiration
        sleep(Duration::from_secs(2));
        
        // Should be a miss after expiration
        let miss = cache.get("example.com", RecordType::A);
        assert!(miss.is_none());
        
        // Cleanup should remove the expired entry
        cache.cleanup();
        assert_eq!(cache.len(), 0);
    }
    
    #[test]
    fn test_cache_ttl_adjustments() {
        let mut cache = DnsCache::with_config(DnsCacheConfig {
            min_ttl: 10,
            max_ttl: 20,
            ..DnsCacheConfig::default()
        });
        
        // Test min TTL enforcement
        let response1 = create_test_response(1234, "min-test.com", RecordType::A, 5);
        cache.insert("min-test.com", RecordType::A, response1, 5).unwrap();
        
        // Test max TTL enforcement
        let response2 = create_test_response(1235, "max-test.com", RecordType::A, 30);
        cache.insert("max-test.com", RecordType::A, response2, 30).unwrap();
        
        // Inspect the entries directly to verify TTL adjustments
        let min_key = CacheKey::new("min-test.com", RecordType::A);
        let max_key = CacheKey::new("max-test.com", RecordType::A);
        
        assert_eq!(cache.entries.get(&min_key).unwrap().ttl, 10); // Should be adjusted up to min
        assert_eq!(cache.entries.get(&max_key).unwrap().ttl, 20); // Should be adjusted down to max
    }
    
    #[test]
    fn test_cache_eviction() {
        // Create a cache with small limits for testing
        let mut cache = DnsCache::with_config(DnsCacheConfig {
            max_entries: 2,
            max_memory_bytes: 10000,
            ..DnsCacheConfig::default()
        });
        
        // Insert entries until eviction occurs
        let response1 = create_test_response(1, "test1.com", RecordType::A, 300);
        let response2 = create_test_response(2, "test2.com", RecordType::A, 300);
        let response3 = create_test_response(3, "test3.com", RecordType::A, 300);
        
        cache.insert("test1.com", RecordType::A, response1, 300).unwrap();
        cache.insert("test2.com", RecordType::A, response2, 300).unwrap();
        
        // This should trigger eviction due to max_entries limit
        cache.insert("test3.com", RecordType::A, response3, 300).unwrap();
        
        // Cache should still have 2 entries (one was evicted)
        assert_eq!(cache.len(), 2);
        
        // test1.com should have been evicted (LRU policy)
        assert!(cache.get("test1.com", RecordType::A).is_none());
        
        // The other two should still be there
        assert!(cache.get("test2.com", RecordType::A).is_some());
        assert!(cache.get("test3.com", RecordType::A).is_some());
    }
    
    #[test]
    fn test_cache_negative_responses() {
        let mut cache = DnsCache::with_config(DnsCacheConfig {
            enable_negative_caching: true,
            negative_ttl: 60,
            ..DnsCacheConfig::default()
        });
        
        // Create and insert a negative (NXDOMAIN) response
        let negative = create_negative_response(1234, "nonexistent.com", RecordType::A);
        cache.insert("nonexistent.com", RecordType::A, negative.clone(), 60).unwrap();
        
        // Should be able to retrieve it
        let retrieved = cache.get("nonexistent.com", RecordType::A);
        assert!(retrieved.is_some());
        
        // And it should be an NXDOMAIN response
        assert_eq!(retrieved.unwrap().response_code(), ResponseCode::NXDomain);
    }
    
    #[test]
    fn test_cache_ttl_update() {
        let mut cache = DnsCache::new();
        
        // Insert with a 10 second TTL
        let response = create_test_response(1234, "ttl-test.com", RecordType::A, 10);
        cache.insert("ttl-test.com", RecordType::A, response, 10).unwrap();
        
        // Wait 5 seconds
        sleep(Duration::from_secs(5));
        
        // Get the entry, TTL should be reduced
        let retrieved = cache.get("ttl-test.com", RecordType::A).unwrap();
        
        // Check that the TTL in the retrieved response is <= 5
        assert!(retrieved.answers()[0].ttl() <= 5);
    }
    
    #[test]
    fn test_cache_statistics() {
        let mut cache = DnsCache::new();
        
        // Generate some activity
        let response = create_test_response(1234, "stats-test.com", RecordType::A, 300);
        cache.insert("stats-test.com", RecordType::A, response.clone(), 300).unwrap();
        
        cache.get("stats-test.com", RecordType::A);
        cache.get("stats-test.com", RecordType::A);
        cache.get("nonexistent.com", RecordType::A);
        
        // Get stats
        let stats = cache.stats();
        
        // Verify statistics
        assert_eq!(stats.get("entries").unwrap(), &1);
        assert!(stats.get("memory_bytes").unwrap() > &0);
        assert_eq!(stats.get("evictions").unwrap(), &0);
    }
}