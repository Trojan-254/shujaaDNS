use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::net::UdpSocket as TokioUdpSocket;
use thiserror::Error;
use trust_dns_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::{DNSClass, Name, Record, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::HashMap;

use crate::dns::cache::DnsCache;
use crate::filter::engine::FilterEngine;
use crate::models::client::ClientInfo;
use crate::utils::metrics::{increment_counter, record_timing};
use crate::utils::logging::{error, info, warn, debug};
use crate::utils::config::DnsConfig;

/// Possible errors that can occur during DNS proxy operations
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("DNS protocol error: {0}")]
    ProtocolError(#[from] trust_dns_proto::error::ProtoError),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Timeout waiting for upstream DNS server")]
    UpstreamTimeout,
    
    #[error("Invalid request format")]
    InvalidRequest,
    
    #[error("Security violation: {0}")]
    SecurityViolation(String),
    
    #[error("Rate limit exceeded for client {0}")]
    RateLimitExceeded(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for DNS proxy operations
type ProxyResult<T> = Result<T, ProxyError>;

/// Structure to hold rate limiting information for clients
struct RateLimiter {
    // Maps client IP to (last request time, request count)
    clients: HashMap<SocketAddr, (Instant, u32)>,
    window_size: Duration,
    max_requests: u32,
}

impl RateLimiter {
    pub fn new(window_size: Duration, max_requests: u32) -> Self {
        Self {
            clients: HashMap::new(),
            window_size,
            max_requests,
        }
    }
    
    pub fn check_rate_limit(&mut self, client_addr: SocketAddr) -> bool {
        let now = Instant::now();
        let entry = self.clients.entry(client_addr).or_insert((now, 0));
        
        // Reset counter if window has passed
        if now.duration_since(entry.0) > self.window_size {
            *entry = (now, 1);
            return true;
        }
        
        // Increment counter
        entry.1 += 1;
        
        // Check if limit exceeded
        entry.1 <= self.max_requests
    }
    
    // Clean up old entries periodically
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.clients.retain(|_, (timestamp, _)| {
            now.duration_since(*timestamp) <= self.window_size * 2
        });
    }
}

/// DNS Proxy server implementation
pub struct DnsProxy {
    socket: Arc<TokioUdpSocket>,
    upstream_servers: Vec<SocketAddr>,
    cache: Arc<RwLock<DnsCache>>,
    filter_engine: Arc<RwLock<FilterEngine>>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    config: DnsConfig,
    buffer_size: usize,
}

impl DnsProxy {
    /// Create a new DNS proxy instance
    pub async fn new(
        bind_addr: SocketAddr,
        upstream_servers: Vec<SocketAddr>,
        filter_engine: Arc<RwLock<FilterEngine>>,
        cache: Arc<RwLock<DnsCache>>,
        config: DnsConfig,
    ) -> ProxyResult<Self> {
        // Validate configuration
        if upstream_servers.is_empty() {
            return Err(ProxyError::ConfigError("No upstream DNS servers configured".into()));
        }
        
        // Create and configure UDP socket
        let socket = TokioUdpSocket::bind(bind_addr).await?;
        
        // Configure rate limiter based on config
        let rate_limiter = Arc::new(RwLock::new(RateLimiter::new(
            Duration::from_secs(config.rate_limit_window_secs),
            config.rate_limit_max_requests,
        )));
        
        // Determine optimal buffer size based on system
        let buffer_size = if cfg!(target_os = "linux") {
            // Linux can handle larger buffers efficiently
            8192
        } else {
            // Default for other platforms
            4096
        };
        
        Ok(Self {
            socket: Arc::new(socket),
            upstream_servers,
            cache,
            filter_engine,
            rate_limiter,
            config,
            buffer_size,
        })
    }
    
    /// Start the DNS proxy server
    pub async fn run(&self) -> ProxyResult<()> {
        info!("Starting DNS proxy server on {}", self.socket.local_addr()?);
        
        // Spawn a task to periodically clean up rate limiter
        let rate_limiter_cleanup = self.rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Ok(mut limiter) = rate_limiter_cleanup.write().await {
                    limiter.cleanup();
                }
            }
        });
        
        // Spawn a task to periodically clean up cache
        let cache_cleanup = self.cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                if let Ok(mut cache) = cache_cleanup.write().await {
                    cache.cleanup();
                }
            }
        });
        
        // Main request handling loop
        let mut recv_buffer = vec![0u8; self.buffer_size];
        
        loop {
            // Use select to handle shutdown signals
            match self.socket.recv_from(&mut recv_buffer).await {
                Ok((size, client_addr)) => {
                    // Clone required data for async task
                    let socket = self.socket.clone();
                    let upstream_servers = self.upstream_servers.clone();
                    let cache = self.cache.clone();
                    let filter_engine = self.filter_engine.clone();
                    let rate_limiter = self.rate_limiter.clone();
                    let config = self.config.clone();
                    let request_data = recv_buffer[..size].to_vec();
                    
                    // Process request in a separate task
                    tokio::spawn(async move {
                        let start_time = Instant::now();
                        
                        // Handle the request and send response
                        match Self::handle_request(
                            &socket,
                            &request_data,
                            client_addr,
                            &upstream_servers,
                            &cache,
                            &filter_engine,
                            &rate_limiter,
                            &config,
                        ).await {
                            Ok(_) => {
                                record_timing("dns_request_time", start_time.elapsed());
                                debug!("Request from {} processed successfully", client_addr);
                            }
                            Err(e) => {
                                error!("Error processing request from {}: {}", client_addr, e);
                                increment_counter("dns_errors");
                                
                                // Try to send an error response
                                if let Err(send_err) = Self::send_error_response(&socket, client_addr, &request_data, e).await {
                                    error!("Failed to send error response: {}", send_err);
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Error receiving data: {}", e);
                    
                    // Differentiate between transient and fatal errors
                    if e.kind() == std::io::ErrorKind::WouldBlock || 
                       e.kind() == std::io::ErrorKind::TimedOut {
                        // For transient errors, just continue
                        continue;
                    } else {
                        // For other errors, break and return
                        return Err(e.into());
                    }
                }
            }
        }
    }
    
    /// Handle a DNS request
    async fn handle_request(
        socket: &TokioUdpSocket,
        request_data: &[u8],
        client_addr: SocketAddr,
        upstream_servers: &[SocketAddr],
        cache: &Arc<RwLock<DnsCache>>,
        filter_engine: &Arc<RwLock<FilterEngine>>,
        rate_limiter: &Arc<RwLock<RateLimiter>>,
        config: &DnsConfig,
    ) -> ProxyResult<()> {
        // Check rate limit first
        {
            let mut limiter = rate_limiter.write().await;
            if !limiter.check_rate_limit(client_addr) {
                increment_counter("rate_limit_exceeded");
                return Err(ProxyError::RateLimitExceeded(client_addr.to_string()));
            }
        }
        
        // Parse the DNS request
        let request = match Message::from_vec(request_data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Invalid DNS request from {}: {}", client_addr, e);
                return Err(ProxyError::ProtocolError(e));
            }
        };
        
        // Security checks
        Self::security_check(&request, client_addr)?;
        
        // Get client info for filtering decisions
        let client_info = ClientInfo::from_addr(client_addr);
        
        // Check if we have any questions to process
        if request.queries().is_empty() {
            return Err(ProxyError::InvalidRequest);
        }
        
        // Process each query in the request
        let question = &request.queries()[0];
        let query_name = question.name().to_ascii();
        
        // Try to get domain from cache
        let cached_response = {
            let cache_reader = cache.read().await;
            cache_reader.get(&query_name, question.query_type())
        };
        
        if let Some(cached_resp) = cached_response {
            let mut response = cached_resp.clone();
            response.set_id(request.id());
            
            // Send the cached response
            let response_data = response.to_vec()?;
            socket.send_to(&response_data, client_addr).await?;
            increment_counter("cache_hits");
            
            return Ok(());
        }
        
        // Apply filtering rules
        let filter_result = {
            let filter = filter_engine.read().await;
            filter.check_domain(&query_name, &client_info).await
        };
        
        if !filter_result.is_allowed {
            // Create blocked response
            let response = Self::create_blocked_response(&request, &filter_result.reason);
            let response_data = response.to_vec()?;
            socket.send_to(&response_data, client_addr).await?;
            increment_counter("filtered_domains");
            
            info!("Blocked domain {} for client {} (reason: {})", 
                  query_name, client_addr, filter_result.reason);
            
            return Ok(());
        }
        
        // Forward to upstream DNS servers
        let response = Self::forward_to_upstream(
            request_data, 
            upstream_servers, 
            config.upstream_timeout_ms,
        ).await?;
        
        // Cache the response if it's cacheable
        if Self::is_cacheable(&response) {
            let ttl = Self::get_min_ttl(&response);
            let mut cache_writer = cache.write().await;
            cache_writer.insert(&query_name, question.query_type(), response.clone(), ttl);
        }
        
        // Send response back to client
        let response_data = response.to_vec()?;
        socket.send_to(&response_data, client_addr).await?;
        increment_counter("successful_responses");
        
        Ok(())
    }
    
    /// Forward the request to upstream DNS servers
    async fn forward_to_upstream(
        request_data: &[u8], 
        upstream_servers: &[SocketAddr], 
        timeout_ms: u64,
    ) -> ProxyResult<Message> {
        // Create a new UDP socket for forwarding
        let upstream_socket = UdpSocket::bind("0.0.0.0:0")?;
        upstream_socket.set_nonblocking(true)?;
        
        // Try each upstream server until we get a response
        for &server in upstream_servers {
            // Send the request to the upstream server
            match upstream_socket.send_to(request_data, server) {
                Ok(_) => {
                    // Set up a timeout for receiving the response
                    let timeout = Duration::from_millis(timeout_ms);
                    
                    // Receive the response with timeout
                    let mut buf = vec![0u8; 4096];
                    match tokio::time::timeout(timeout, async {
                        let async_socket = TokioUdpSocket::from_std(upstream_socket)?;
                        async_socket.recv(&mut buf).await
                    }).await {
                        Ok(Ok(size)) => {
                            // Parse the response
                            match Message::from_vec(&buf[..size]) {
                                Ok(response) => return Ok(response),
                                Err(e) => {
                                    warn!("Invalid response from upstream server {}: {}", server, e);
                                    continue; // Try next server
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            warn!("Error receiving from upstream server {}: {}", server, e);
                            continue; // Try next server
                        }
                        Err(_) => {
                            warn!("Timeout waiting for response from upstream server {}", server);
                            continue; // Try next server
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to send to upstream server {}: {}", server, e);
                    continue; // Try next server
                }
            }
        }
        
        // If we get here, all upstream servers failed
        error!("All upstream DNS servers failed to respond");
        Err(ProxyError::UpstreamTimeout)
    }
    
    /// Perform security checks on the DNS request
    fn security_check(request: &Message, client_addr: SocketAddr) -> ProxyResult<()> {
        // Check for valid DNS message type
        if request.message_type() != MessageType::Query {
            return Err(ProxyError::SecurityViolation("Only DNS queries are allowed".into()));
        }
        
        // Check opcode (only standard queries allowed)
        if request.op_code() != OpCode::Query {
            return Err(ProxyError::SecurityViolation(format!(
                "Unsupported OpCode: {:?}", request.op_code()
            )));
        }
        
        // Check that recursion is desired (we only support recursive queries)
        if !request.recursion_desired() {
            return Err(ProxyError::SecurityViolation("Only recursive queries are supported".into()));
        }
        
        // Limit query count per message (to prevent DOS)
        if request.queries().len() > 1 {
            return Err(ProxyError::SecurityViolation("Only one query per message is supported".into()));
        }
        
        // Check for DNS tunneling (excessively long domain names)
        for query in request.queries() {
            let domain = query.name().to_ascii();
            if domain.len() > 253 || domain.split('.').any(|label| label.len() > 63) {
                warn!("Possible DNS tunneling attempt from {}: domain too long", client_addr);
                return Err(ProxyError::SecurityViolation("Domain name too long".into()));
            }
            
            // Check for suspicious characters in domain name (potential exfiltration)
            let suspicious_chars = domain.chars().any(|c| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
            if suspicious_chars {
                warn!("Suspicious domain name from {}: {}", client_addr, domain);
                // We don't fail here, just log it, as some legitimate domains may have unusual characters
            }
        }
        
        Ok(())
    }
    
    /// Create a response for blocked domains
    fn create_blocked_response(request: &Message, reason: &str) -> Message {
        let mut response = Message::new();
        
        // Copy the ID from the request
        response.set_id(request.id());
        
        // Set response flags
        let mut header = Header::new();
        header.set_message_type(MessageType::Response);
        header.set_op_code(OpCode::Query);
        header.set_response_code(ResponseCode::NXDomain); // Non-existent domain
        header.set_recursion_desired(true);
        header.set_recursion_available(true);
        header.set_authoritative(false);
        response.set_header(header);
        
        // Copy the query
        for query in request.queries() {
            response.add_query(query.clone());
        }
        
        // Add a TXT record explaining why it was blocked (if debug is enabled)
        if cfg!(debug_assertions) {
            let mut txt_record = Record::new();
            txt_record.set_name(request.queries()[0].name().clone());
            txt_record.set_record_type(RecordType::TXT);
            txt_record.set_dns_class(DNSClass::IN);
            txt_record.set_ttl(300); // 5 minutes TTL
            
            // Set TXT data with the reason
            let txt_data = format!("Domain blocked: {}", reason);
            // Note: actual TXT record data setting omitted for brevity
            
            response.add_additional(txt_record);
        }
        
        response
    }
    
    /// Send an error response to the client
    async fn send_error_response(
        socket: &TokioUdpSocket,
        client_addr: SocketAddr,
        request_data: &[u8],
        error: ProxyError,
    ) -> ProxyResult<()> {
        // Parse the original request to get the ID
        let request = match Message::from_vec(request_data) {
            Ok(req) => req,
            Err(_) => {
                // If we can't parse the request, we can't send a proper response
                return Err(ProxyError::InvalidRequest);
            }
        };
        
        // Create a server failure response
        let mut response = Message::new();
        response.set_id(request.id());
        
        let mut header = Header::new();
        header.set_message_type(MessageType::Response);
        header.set_op_code(request.op_code());
        
        // Set appropriate response code based on error type
        let response_code = match &error {
            ProxyError::InvalidRequest => ResponseCode::FormErr,
            ProxyError::SecurityViolation(_) => ResponseCode::Refused,
            ProxyError::RateLimitExceeded(_) => ResponseCode::Refused,
            _ => ResponseCode::ServFail,
        };
        
        header.set_response_code(response_code);
        header.set_recursion_desired(request.recursion_desired());
        header.set_recursion_available(true);
        response.set_header(header);
        
        // Copy the queries from the request
        for query in request.queries() {
            response.add_query(query.clone());
        }
        
        // Send the error response
        let response_data = response.to_vec()?;
        socket.send_to(&response_data, client_addr).await?;
        
        Ok(())
    }
    
    /// Check if a response is cacheable
    fn is_cacheable(response: &Message) -> bool {
        // Don't cache error responses
        if response.response_code() != ResponseCode::NoError {
            return false;
        }
        
        // Don't cache empty responses
        if response.answers().is_empty() {
            return false;
        }
        
        // Check if all TTLs are > 0
        response.answers().iter().all(|record| record.ttl() > 0)
    }
    
    /// Get the minimum TTL from a response
    fn get_min_ttl(response: &Message) -> u32 {
        response.answers()
            .iter()
            .map(|record| record.ttl())
            .min()
            .unwrap_or(300) // Default 5 minutes if no records
    }
}

