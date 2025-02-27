/// This is the main proxy implementation that handles DNS Queries

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;


/// Possible errors that can occur during DNS Proxy operations
#[derive(Error, Debug)]
pub enum ProxyError {
   #[error("DNS Protocol Error: {0}")]
   ProtocolError(#[from] trust_dns_proto::error::ProtoError),

   #[error("I/O error: {0}")]
   IoError(#[from] std::io::Error),

   #[error("Timeout waiting for upstream DNS Server")]
   UpstreamTimeout,

   #[error("Invalid request format")]
   InvalidRequest,

   #[error("Rate limit exceeded for client")]
   RateLimitExceeded(String),

   #[error("Security violation error: {0}")]
   SecurityViolation(String),

   #[error("Configuration error: {0}")]
   ConfigError(String),
}

/// Result type for DNS Proxy operations
type ProxyResult<T> = Result<T, ProxyError>

/// Structure to hold rate limiting information for clients
struct RateLimiter {
   // Maps client ip to (last request time, resent count)
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

       // Reset counter if window passed
       if now.duration_since(entry.0) > self.window_size {
          *entry = (now, 1);
          return true;
       }

       // Increament counter
       entry.1 += 1;

       // check if limit exceeded
       entry.1 <= self.max_requests
   }

   // Clean old entries periodically
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
   /// Create a new Dns proxy instance
   pub async fn new (
     bind_addr: SocketAddr,
     upstream_servers: Vec<SocketAddr>,
     filter_engine: Arc<RwLock<FilterEngine>>,
     cache: Arc<RwLock<DnsCache>>,
     config: DnsConfig,
   ) -> ProxyResult<Self> {
     // Validate configuration
     if upstream_servers.is_empty() {
         return Err(ProxyError::ConfigError("No upstream DNS Servers configured".into()));
     }

     // create and configure UDP Socket
     let socket = TokioUdpSocket::bind(bind_addr).await?;

     // Configure our rate limiter based on config
     let rate_limiter = Arc::new(RwLock::new(RateLimiter::new(
         Duration::from_secs(config.rate_limit_window_secs),
         config.rate_limit_max_requests,
     )));

     // Determine the optimal buffer size based on the system
     let buffer_size = if cfg!(target_os == "linux") {
         8192
     } else {
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

   /// Start the DNS Proxy server
   pub async fn run (&self) -> ProxyResult<()> {
      info!("Starting DNS proxy server on {}", self.socket.local_addr()?);

      // Spawn a task periodically to clean up rate limiter
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

     // spawn a task periodically to clean up cache
     let cache_cleanup = self.cache.clone();
     tokio:spawn(async move {
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
        // use select to handle shutdown signals
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

                   // Handle request and send response
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
) -> ProxyResult<()> {}
