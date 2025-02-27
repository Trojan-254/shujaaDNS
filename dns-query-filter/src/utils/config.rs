use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Failed to parse config: {0}")]
    ParseError(#[from] serde_json::Error),
    
    #[error("Invalid configuration: {0}")]
    ValidationError(String),
    
    #[error("Missing required configuration key: {0}")]
    MissingKey(String),
}

/// Result type for configuration operations
pub type ConfigResult<T> = Result<T, ConfigError>;

/// DNS proxy configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Port to listen on for DNS requests
    #[serde(default = "default_dns_port")]
    pub port: u16,
    
    /// Address to bind to
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    
    /// Upstream DNS servers
    pub upstream_servers: Vec<String>,
    
    /// Timeout for upstream DNS requests in milliseconds
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout_ms: u64,
    
    /// Rate limit window in seconds
    #[serde(default = "default_rate_limit_window")]
    pub rate_limit_window_secs: u64,
    
    /// Maximum number of requests per window
    #[serde(default = "default_max_requests")]
    pub rate_limit_max_requests: u32,
    
    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
    
    /// Maximum number of cached entries
    #[serde(default = "default_max_cache_entries")]
    pub max_cache_entries: usize,
    
    /// Whether to enable EDNS support
    #[serde(default = "default_edns_enabled")]
    pub edns_enabled: bool,
    
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
    
    /// Whether to enable metrics
    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,
    
    /// Metrics HTTP port
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

// Default values
fn default_dns_port() -> u16 { 53 }
fn default_bind_address() -> String { "0.0.0.0".to_string() }
fn default_upstream_timeout() -> u64 { 1000 }
fn default_rate_limit_window() -> u64 { 60 }
fn default_max_requests() -> u32 { 100 }
fn default_cache_ttl() -> u64 { 300 }
fn default_max_cache_entries() -> usize { 10000 }
fn default_edns_enabled() -> bool { true }
fn default_log_level() -> String { "info".to_string() }
fn default_metrics_enabled() -> bool { false }
fn default_metrics_port() -> u16 { 9100 }

impl DnsConfig {
    /// Create a new configuration with default values
    pub fn default() -> Self {
        Self {
            port: default_dns_port(),
            bind_address: default_bind_address(),
            upstream_servers: vec![
                "8.8.8.8:53".to_string(),
                "1.1.1.1:53".to_string(),
            ],
            upstream_timeout_ms: default_upstream_timeout(),
            rate_limit_window_secs: default_rate_limit_window(),
            rate_limit_max_requests: default_max_requests(),
            cache_ttl_secs: default_cache_ttl(),
            max_cache_entries: default_max_cache_entries(),
            edns_enabled: default_edns_enabled(),
            log_level: default_log_level(),
            metrics_enabled: default_metrics_enabled(),
            metrics_port: default_metrics_port(),
        }
    }
    
    /// Load configuration from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> ConfigResult<Self> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        let config: Self = serde_json::from_str(&contents)?;
        config.validate()?;
        
        Ok(config)
    }
    
    /// Validate configuration
    pub fn validate(&self) -> ConfigResult<()> {
        // Ensure we have at least one upstream server
        if self.upstream_servers.is_empty() {
            return Err(ConfigError::ValidationError(
                "At least one upstream DNS server must be configured".to_string()
            ));
        }
        
        // Validate upstream server addresses
        for server in &self.upstream_servers {
            if server.parse::<SocketAddr>().is_err() {
                return Err(ConfigError::ValidationError(
                    format!("Invalid upstream server address: {}", server)
                ));
            }
        }
        
        // Validate rate limiting
        if self.rate_limit_window_secs == 0 {
            return Err(ConfigError::ValidationError(
                "Rate limit window must be greater than zero".to_string()
            ));
        }
        
        // Validate cache settings
        if self.max_cache_entries == 0 {
            return Err(ConfigError::ValidationError(
                "Maximum cache entries must be greater than zero".to_string()
            ));
        }
        
        // Validate log level
        match self.log_level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => {
                return Err(ConfigError::ValidationError(
                    format!("Invalid log level: {}", self.log_level)
                ));
            }
        }
        
        Ok(())
    }
    
    /// Get the socket address to bind to for DNS service
    pub fn get_bind_addr(&self) -> ConfigResult<SocketAddr> {
        let addr = format!("{}:{}", self.bind_address, self.port);
        addr.parse::<SocketAddr>()
            .map_err(|e| ConfigError::ValidationError(
                format!("Invalid bind address: {} ({})", addr, e)
            ))
    }
    
    /// Get a list of upstream DNS server socket addresses
    pub fn get_upstream_addrs(&self) -> ConfigResult<Vec<SocketAddr>> {
        let mut addrs = Vec::with_capacity(self.upstream_servers.len());
        
        for server in &self.upstream_servers {
            let addr = server.parse::<SocketAddr>()
                .map_err(|e| ConfigError::ValidationError(
                    format!("Invalid upstream server address: {} ({})", server, e)
                ))?;
            addrs.push(addr);
        }
        
        Ok(addrs)
    }
}

/// Application configuration container
pub struct ConfigManager {
    dns_config: RwLock<DnsConfig>,
    config_path: Option<String>,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new(config_path: Option<&str>) -> ConfigResult<Arc<Self>> {
        let dns_config = if let Some(path) = config_path {
            DnsConfig::from_file(path)?
        } else {
            DnsConfig::default()
        };
        
        Ok(Arc::new(Self {
            dns_config: RwLock::new(dns_config),
            config_path: config_path.map(|s| s.to_string()),
        }))
    }
    
    /// Get a read-only reference to the DNS configuration
    pub async fn get_dns_config(&self) -> DnsConfig {
        self.dns_config.read().await.clone()
    }
    
    /// Reload configuration from file
    pub async fn reload(&self) -> ConfigResult<()> {
        if let Some(path) = &self.config_path {
            let new_config = DnsConfig::from_file(path)?;
            
            // Update configuration atomically
            let mut config = self.dns_config.write().await;
            *config = new_config;
            
            Ok(())
        } else {
            Err(ConfigError::ValidationError(
                "No configuration file path specified".to_string()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::runtime::Runtime;
    
    #[test]
    fn test_default_config() {
        let config = DnsConfig::default();
        assert_eq!(config.port, 53);
        assert_eq!(config.bind_address, "0.0.0.0");
        assert!(!config.upstream_servers.is_empty());
        assert_eq!(config.rate_limit_window_secs, 60);
        assert_eq!(config.rate_limit_max_requests, 100);
    }
    
    #[test]
    fn test_config_validation() {
        // Valid config
        let valid_config = DnsConfig::default();
        assert!(valid_config.validate().is_ok());
        
        // Invalid config - no upstream servers
        let mut invalid_config = DnsConfig::default();
        invalid_config.upstream_servers = vec![];
        assert!(invalid_config.validate().is_err());
        
        // Invalid config - invalid upstream address
        let mut invalid_config = DnsConfig::default();
        invalid_config.upstream_servers = vec!["not_an_address".to_string()];
        assert!(invalid_config.validate().is_err());
        
        // Invalid config - zero rate limit window
        let mut invalid_config = DnsConfig::default();
        invalid_config.rate_limit_window_secs = 0;
        assert!(invalid_config.validate().is_err());
        
        // Invalid config - invalid log level
        let mut invalid_config = DnsConfig::default();
        invalid_config.log_level = "not_a_level".to_string();
        assert!(invalid_config.validate().is_err());
    }
    
    #[test]
    fn test_load_from_file() {
        let config_json = r#"{
            "port": 5353,
            "bind_address": "127.0.0.1",
            "upstream_servers": ["8.8.8.8:53", "1.1.1.1:53"],
            "upstream_timeout_ms": 2000,
            "rate_limit_window_secs": 120,
            "rate_limit_max_requests": 200,
            "log_level": "debug"
        }"#;
        
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_json.as_bytes()).unwrap();
        
        let config = DnsConfig::from_file(temp_file.path()).unwrap();
        assert_eq!(config.port, 5353);
        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.upstream_servers.len(), 2);
        assert_eq!(config.upstream_timeout_ms, 2000);
        assert_eq!(config.rate_limit_window_secs, 120);
        assert_eq!(config.rate_limit_max_requests, 200);
        assert_eq!(config.log_level, "debug");
    }
    
    #[test]
    fn test_config_manager() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            let manager = ConfigManager::new(None).unwrap();
            let config = manager.get_dns_config().await;
            assert_eq!(config.port, 53);
        });
    }
    
    #[test]
    fn test_socket_address_conversion() {
        let config = DnsConfig::default();
        let bind_addr = config.get_bind_addr().unwrap();
        assert_eq!(bind_addr.port(), 53);
        
        let upstream_addrs = config.get_upstream_addrs().unwrap();
        assert!(!upstream_addrs.is_empty());
    }
}