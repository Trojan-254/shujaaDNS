use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::db::operations::{DbError, DbOperations};
use crate::models::group::UserGroup;
use crate::utils::logging::{debug, error, info, warn};
use crate::utils::metrics::increment_counter;

/// Error types for client mapping operations
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] DbError),
    
    #[error("Client IP not found in mapping table")]
    ClientNotFound,
    
    #[error("Client mapping has expired")]
    MappingExpired,
    
    #[error("Group not found: {0}")]
    GroupNotFound(String),
    
    #[error("Invalid MAC address format: {0}")]
    InvalidMacAddress(String),
    
    #[error("Invalid client identifier: {0}")]
    InvalidIdentifier(String),
}

/// Result type for client operations
pub type ClientResult<T> = Result<T, ClientError>;

/// Client identification methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientIdentifier {
    /// Identify by IP address
    IpAddress(IpAddr),
    
    /// Identify by MAC address
    MacAddress(String),
    
    /// Identify by hostname
    Hostname(String),
    
    /// Identify by custom identifier (e.g., client certificate CN)
    CustomId(String),
    
    /// Identify by IP subnet (CIDR notation)
    Subnet(String, u8), // (Network address, prefix length)
}

impl ClientIdentifier {
    /// Parse a client identifier from string representation
    pub fn from_string(s: &str) -> Result<Self, ClientError> {
        // Try as IP address first
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(ClientIdentifier::IpAddress(ip));
        }
        
        // Check for MAC address format (XX:XX:XX:XX:XX:XX)
        let mac_regex = regex::Regex::new(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$").unwrap();
        if mac_regex.is_match(s) {
            return Ok(ClientIdentifier::MacAddress(s.to_uppercase()));
        }
        
        // Check for subnet format (192.168.1.0/24)
        let subnet_regex = regex::Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$").unwrap();
        if let Some(caps) = subnet_regex.captures(s) {
            if let (Ok(ip), Ok(prefix)) = (caps[1].parse::<IpAddr>(), caps[2].parse::<u8>()) {
                if (ip.is_ipv4() && prefix <= 32) || (ip.is_ipv6() && prefix <= 128) {
                    return Ok(ClientIdentifier::Subnet(caps[1].to_string(), prefix));
                }
            }
        }
        
        // If it looks like a hostname (contains letters and no special chars other than -)
        let hostname_regex = regex::Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$").unwrap();
        if hostname_regex.is_match(s) {
            return Ok(ClientIdentifier::Hostname(s.to_lowercase()));
        }
        
        // Otherwise, treat as custom identifier
        Ok(ClientIdentifier::CustomId(s.to_string()))
    }
    
    /// Check if this identifier matches a given IP address
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        match self {
            ClientIdentifier::IpAddress(self_ip) => self_ip == ip,
            ClientIdentifier::Subnet(network, prefix) => {
                // Check if IP is in subnet
                match (ip, network.parse::<IpAddr>()) {
                    (IpAddr::V4(ip_v4), Ok(IpAddr::V4(network_v4))) => {
                        let ip_bits = u32::from_be_bytes(ip_v4.octets());
                        let network_bits = u32::from_be_bytes(network_v4.octets());
                        let mask = if *prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                        (ip_bits & mask) == (network_bits & mask)
                    },
                    (IpAddr::V6(ip_v6), Ok(IpAddr::V6(network_v6))) => {
                        let ip_bits = u128::from_be_bytes(ip_v6.octets());
                        let network_bits = u128::from_be_bytes(network_v6.octets());
                        let mask = if *prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                        (ip_bits & mask) == (network_bits & mask)
                    },
                    _ => false,
                }
            },
            _ => false, // Other types need additional information to match IP
        }
    }
}

/// Database-stored client mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMapping {
    /// Client identifier (IP, MAC, etc.)
    pub identifier: ClientIdentifier,
    
    /// User group ID this client belongs to
    pub group_id: String,
    
    /// Optional friendly name for this client
    pub friendly_name: Option<String>,
    
    /// When this mapping expires (unix timestamp)
    pub expires: u64,
    
    /// Additional metadata as JSON
    pub metadata: serde_json::Value,
}

/// Runtime client information derived from request
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// IP address of the client
    pub ip_addr: IpAddr,
    
    /// Port the client is connecting from
    pub port: u16,
    
    /// MAC address if available
    pub mac_address: Option<String>,
    
    /// Hostname if available
    pub hostname: Option<String>,
    
    /// User group the client belongs to
    pub group_id: Option<String>,
    
    /// Friendly name for the client
    pub friendly_name: Option<String>,
}

impl ClientInfo {
    /// Create a new ClientInfo from a socket address
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self {
            ip_addr: addr.ip(),
            port: addr.port(),
            mac_address: None,
            hostname: None,
            group_id: None,
            friendly_name: None,
        }
    }
    
    /// Create a new ClientInfo with all fields
    #[allow(dead_code)]
    pub fn new(
        ip_addr: IpAddr,
        port: u16,
        mac_address: Option<String>,
        hostname: Option<String>,
        group_id: Option<String>,
        friendly_name: Option<String>,
    ) -> Self {
        Self {
            ip_addr,
            port,
            mac_address,
            hostname,
            group_id,
            friendly_name,
        }
    }
}

/// In-memory cache for client-to-group mappings with periodic DB sync
pub struct ClientMappingManager {
    /// Reference to database operations
    db: Arc<dyn DbOperations>,
    
    /// In-memory cache of client mappings
    /// Maps client identifier string to mapping
    cache: HashMap<String, ClientMapping>,
    
    /// MAC address to IP mapping (for identification)
    mac_to_ip: HashMap<String, IpAddr>,
    
    /// Hostname to IP mapping (for identification)
    hostname_to_ip: HashMap<String, IpAddr>,
    
    /// Default group ID for unknown clients
    default_group_id: String,
    
    /// Time to wait before refreshing from database
    cache_ttl: Duration,
    
    /// When the cache was last refreshed
    last_refresh: SystemTime,
}

impl ClientMappingManager {
    /// Create a new client mapping manager
    pub async fn new(
        db: Arc<dyn DbOperations>,
        default_group_id: String,
        cache_ttl: Duration,
    ) -> ClientResult<Self> {
        let mut manager = Self {
            db,
            cache: HashMap::new(),
            mac_to_ip: HashMap::new(),
            hostname_to_ip: HashMap::new(),
            default_group_id,
            cache_ttl,
            last_refresh: SystemTime::now(),
        };
        
        // Initial load from database
        manager.refresh_cache().await?;
        
        Ok(manager)
    }
    
    /// Refresh the client mapping cache from the database
    pub async fn refresh_cache(&mut self) -> ClientResult<()> {
        debug!("Refreshing client mapping cache from database");
        
        // Get all mappings from database
        let mappings = self.db.get_all_client_mappings().await?;
        
        // Clear existing cache
        self.cache.clear();
        self.mac_to_ip.clear();
        self.hostname_to_ip.clear();
        
        // Process all mappings
        for mapping in mappings {
            // Skip expired mappings
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();
                
            if mapping.expires < now {
                continue;
            }
            
            // Add to cache based on identifier type
            match &mapping.identifier {
                ClientIdentifier::IpAddress(ip) => {
                    self.cache.insert(ip.to_string(), mapping.clone());
                },
                ClientIdentifier::MacAddress(mac) => {
                    self.cache.insert(mac.clone(), mapping.clone());
                    
                    // If we have an IP address in metadata, create mapping
                    if let Some(ip_str) = mapping.metadata.get("last_ip")
                        .and_then(|v| v.as_str()) {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            self.mac_to_ip.insert(mac.clone(), ip);
                        }
                    }
                },
                ClientIdentifier::Hostname(hostname) => {
                    self.cache.insert(hostname.clone(), mapping.clone());
                    
                    // If we have an IP address in metadata, create mapping
                    if let Some(ip_str) = mapping.metadata.get("last_ip")
                        .and_then(|v| v.as_str()) {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            self.hostname_to_ip.insert(hostname.clone(), ip);
                        }
                    }
                },
                ClientIdentifier::CustomId(id) => {
                    self.cache.insert(id.clone(), mapping);
                },
                ClientIdentifier::Subnet(network, prefix) => {
                    self.cache.insert(format!("{}/{}", network, prefix), mapping);
                },
            }
        }
        
        self.last_refresh = SystemTime::now();
        info!("Client mapping cache refreshed, {} entries loaded", self.cache.len());
        
        Ok(())
    }
    
    /// Get the group ID for a client based on its information
    pub async fn get_client_group(&mut self, client: &ClientInfo) -> String {
        // Check if cache needs refreshing
        let elapsed = SystemTime::now()
            .duration_since(self.last_refresh)
            .unwrap_or(Duration::from_secs(0));
            
        if elapsed > self.cache_ttl {
            if let Err(e) = self.refresh_cache().await {
                error!("Failed to refresh client mapping cache: {}", e);
            }
        }
        
        // Try to find by IP address first (most common)
        if let Some(mapping) = self.cache.get(&client.ip_addr.to_string()) {
            debug!("Client {} mapped to group {} by IP", client.ip_addr, mapping.group_id);
            return mapping.group_id.clone();
        }
        
        // Try to find by MAC address if available
        if let Some(mac) = &client.mac_address {
            if let Some(mapping) = self.cache.get(mac) {
                debug!("Client {} mapped to group {} by MAC", client.ip_addr, mapping.group_id);
                
                // Update MAC-to-IP mapping for future lookups
                self.mac_to_ip.insert(mac.clone(), client.ip_addr);
                
                // Update mapping in database asynchronously
                let mac_clone = mac.clone();
                let ip = client.ip_addr;
                let db = self.db.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::update_client_ip(db, &ClientIdentifier::MacAddress(mac_clone), ip).await {
                        error!("Failed to update client IP mapping: {}", e);
                    }
                });
                
                return mapping.group_id.clone();
            }
        }
        
        // Try to find by hostname if available
        if let Some(hostname) = &client.hostname {
            if let Some(mapping) = self.cache.get(hostname) {
                debug!("Client {} mapped to group {} by hostname", client.ip_addr, mapping.group_id);
                
                // Update hostname-to-IP mapping for future lookups
                self.hostname_to_ip.insert(hostname.clone(), client.ip_addr);
                
                // Update mapping in database asynchronously
                let hostname_clone = hostname.clone();
                let ip = client.ip_addr;
                let db = self.db.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::update_client_ip(db, &ClientIdentifier::Hostname(hostname_clone), ip).await {
                        error!("Failed to update client IP mapping: {}", e);
                    }
                });
                
                return mapping.group_id.clone();
            }
        }
        
        // Try subnet matches (we need to check all subnet entries)
        for (key, mapping) in &self.cache {
            if let Ok(identifier) = ClientIdentifier::from_string(key) {
                if identifier.matches_ip(&client.ip_addr) {
                    debug!("Client {} mapped to group {} by subnet match", client.ip_addr, mapping.group_id);
                    return mapping.group_id.clone();
                }
            }
        }
        
        // If no mapping found, use default group
        debug!("Client {} not found in mapping, using default group {}", 
               client.ip_addr, self.default_group_id);
        increment_counter("unknown_clients");
        
        self.default_group_id.clone()
    }
    
    /// Add or update a client mapping
    pub async fn add_client_mapping(
        &mut self,
        identifier: ClientIdentifier,
        group_id: String,
        friendly_name: Option<String>,
        expires_in: Duration,
        metadata: serde_json::Value,
    ) -> ClientResult<()> {
        // Verify the group exists
        if !self.db.group_exists(&group_id).await? {
            return Err(ClientError::GroupNotFound(group_id));
        }
        
        // Calculate expiration time
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .checked_add(expires_in)
            .unwrap_or(Duration::from_secs(u64::MAX))
            .as_secs();
        
        // Create mapping
        let mapping = ClientMapping {
            identifier: identifier.clone(),
            group_id,
            friendly_name,
            expires,
            metadata,
        };
        
        // Store in database
        self.db.add_client_mapping(&mapping).await?;
        
        // Update cache
        let cache_key = match &identifier {
            ClientIdentifier::IpAddress(ip) => ip.to_string(),
            ClientIdentifier::MacAddress(mac) => mac.clone(),
            ClientIdentifier::Hostname(hostname) => hostname.clone(),
            ClientIdentifier::CustomId(id) => id.clone(),
            ClientIdentifier::Subnet(network, prefix) => format!("{}/{}", network, prefix),
        };
        
        self.cache.insert(cache_key, mapping.clone());
        
        info!("Added client mapping for {:?} to group {}", identifier, mapping.group_id);
        Ok(())
    }
    
    /// Remove a client mapping
    pub async fn remove_client_mapping(&mut self, identifier: &ClientIdentifier) -> ClientResult<()> {
        // Remove from database
        self.db.remove_client_mapping(identifier).await?;
        
        // Remove from cache
        let cache_key = match identifier {
            ClientIdentifier::IpAddress(ip) => ip.to_string(),
            ClientIdentifier::MacAddress(mac) => mac.clone(),
            ClientIdentifier::Hostname(hostname) => hostname.clone(),
            ClientIdentifier::CustomId(id) => id.clone(),
            ClientIdentifier::Subnet(network, prefix) => format!("{}/{}", network, prefix),
        };
        
        self.cache.remove(&cache_key);
        
        // Also clean up related mappings
        match identifier {
            ClientIdentifier::MacAddress(mac) => {
                self.mac_to_ip.remove(mac);
            },
            ClientIdentifier::Hostname(hostname) => {
                self.hostname_to_ip.remove(hostname);
            },
            _ => {},
        }
        
        info!("Removed client mapping for {:?}", identifier);
        Ok(())
    }
    
    /// Update the IP address for a client in the database
    async fn update_client_ip(
        db: Arc<dyn DbOperations>,
        identifier: &ClientIdentifier,
        ip: IpAddr,
    ) -> ClientResult<()> {
        // Get existing mapping
        let mut mapping = db.get_client_mapping(identifier).await?;
        
        // Update the last IP in metadata
        let metadata = match &mut mapping.metadata {
            serde_json::Value::Object(map) => {
                map.insert("last_ip".to_string(), serde_json::Value::String(ip.to_string()));
                map.insert("last_seen".to_string(), serde_json::Value::Number(
                    serde_json::Number::from(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::from_secs(0))
                            .as_secs()
                    )
                ));
                serde_json::Value::Object(map.clone())
            },
            _ => {
                let mut map = serde_json::Map::new();
                map.insert("last_ip".to_string(), serde_json::Value::String(ip.to_string()));
                map.insert("last_seen".to_string(), serde_json::Value::Number(
                    serde_json::Number::from(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::from_secs(0))
                            .as_secs()
                    )
                ));
                serde_json::Value::Object(map)
            }
        };
        
        mapping.metadata = metadata;
        
        // Update in database
        db.update_client_mapping(&mapping).await?;
        
        Ok(())
    }
    
    /// Get additional client information from DHCP leases or other sources
    pub async fn enrich_client_info(&self, client: &mut ClientInfo) -> ClientResult<()> {
        // If we already have group_id, we're done
        if client.group_id.is_some() {
            return Ok(());
        }
        
        // Try to get MAC address from ARP table if not already present
        if client.mac_address.is_none() {
            if let Some(mac) = self.get_mac_from_ip(&client.ip_addr).await {
                client.mac_address = Some(mac);
            }
        }
        
        // Try to get hostname from reverse DNS if not already present
        if client.hostname.is_none() {
            if let Some(hostname) = self.get_hostname_from_ip(&client.ip_addr).await {
                client.hostname = Some(hostname);
            }
        }
        
        Ok(())
    }
    
    /// Look up a MAC address from an IP using the ARP table
    async fn get_mac_from_ip(&self, ip: &IpAddr) -> Option<String> {
        // This would normally call out to system commands or an API
        // For now, just check our known mappings
        for (mac, mapped_ip) in &self.mac_to_ip {
            if mapped_ip == ip {
                return Some(mac.clone());
            }
        }
        
        None
    }
    
    /// Look up a hostname from an IP using reverse DNS
    async fn get_hostname_from_ip(&self, ip: &IpAddr) -> Option<String> {
        // This would normally do a reverse DNS lookup
        // For now, just check our known mappings
        for (hostname, mapped_ip) in &self.hostname_to_ip {
            if mapped_ip == ip {
                return Some(hostname.clone());
            }
        }
        
        None
    }
    
    /// Start background task to periodically clean expired mappings
    pub fn start_cleanup_task(manager: Arc<RwLock<Self>>, interval: Duration) {
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            loop {
                timer.tick().await;
                
                if let Ok(mut lock) = manager.write().await {
                    if let Err(e) = lock.cleanup_expired_mappings().await {
                        error!("Failed to clean up expired mappings: {}", e);
                    }
                }
            }
        });
    }
    
    /// Clean up expired mappings
    async fn cleanup_expired_mappings(&mut self) -> ClientResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
            
        // Get expired mappings from database and remove them
        let expired = self.db.get_expired_client_mappings(now).await?;
        
        for mapping in expired {
            // Remove from cache
            let cache_key = match &mapping.identifier {
                ClientIdentifier::IpAddress(ip) => ip.to_string(),
                ClientIdentifier::MacAddress(mac) => mac.clone(),
                ClientIdentifier::Hostname(hostname) => hostname.clone(),
                ClientIdentifier::CustomId(id) => id.clone(),
                ClientIdentifier::Subnet(network, prefix) => format!("{}/{}", network, prefix),
            };
            
            self.cache.remove(&cache_key);
            
            // Remove from database
            self.db.remove_client_mapping(&mapping.identifier).await?;
        }
        
        Ok(())
    }
}

// Helpers for struct implementations
use std::collections::HashMap;