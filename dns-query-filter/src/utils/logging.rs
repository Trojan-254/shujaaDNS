use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use thiserror::Error;
use chrono::Local;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;

/// Logging errors
#[derive(Error, Debug)]
pub enum LogError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Invalid log level: {0}")]
    InvalidLogLevel(String),
    
    #[error("Logger initialization error: {0}")]
    InitError(String),
}

/// Result type for logging operations
type LogResult<T> = Result<T, LogError>;

/// Logging levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "TRACE"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

impl LogLevel {
    /// Parse log level from string
    pub fn from_str(s: &str) -> LogResult<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" | "err" => Ok(LogLevel::Error),
            _ => Err(LogError::InvalidLogLevel(s.to_string())),
        }
    }
}

/// Logger implementation
struct Logger {
    /// Current log level
    level: LogLevel,
    
    /// Optional file for logging
    file: Option<Arc<Mutex<File>>>,
    
    /// Whether to log to stdout
    stdout: bool,
    
    /// Whether to include timestamps
    timestamps: bool,
}

impl Logger {
    /// Create a new logger
    async fn new(level: LogLevel, log_file: Option<&str>, stdout: bool, timestamps: bool) -> LogResult<Self> {
        let file = if let Some(path) = log_file {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
                
            Some(Arc::new(Mutex::new(file)))
        } else {
            None
        };
        
        Ok(Self {
            level,
            file,
            stdout,
            timestamps,
        })
    }
    
    /// Log a message
    async fn log(&self, level: LogLevel, message: &str, module: &str) -> LogResult<()> {
        // Skip if log level is lower than the configured level
        if level < self.level {
            return Ok(());
        }
        
        // Format the log message
        let timestamp = if self.timestamps {
            let now = Local::now();
            format!("{} ", now.format("%Y-%m-%d %H:%M:%S%.3f"))
        } else {
            String::new()
        };
        
        let formatted = format!(
            "{}[{}] [{}] {}\n",
            timestamp,
            level,
            module,
            message
        );
        
        // Write to file if configured
        if let Some(file) = &self.file {
            let mut file_guard = file.lock().await;
            file_guard.write_all(formatted.as_bytes()).await?;
        }
        
        // Write to stdout if configured
        if self.stdout {
            // Use println to avoid async complexity for stdout
            // This is fine for logging as it's not performance-critical
            print!("{}", formatted);
        }
        
        Ok(())
    }
}

// Global logger
static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static INIT: Once = Once::new();
static mut LOGGER: Option<Arc<Mutex<Logger>>> = None;

/// Initialize the logger
pub async fn init(level: LogLevel, log_file: Option<&str>, stdout: bool, timestamps: bool) -> LogResult<()> {
    if LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    let logger = Logger::new(level, log_file, stdout, timestamps).await?;
    
    // This is safe because we're using Once to ensure single initialization
    unsafe {
        INIT.call_once(|| {
            LOGGER = Some(Arc::new(Mutex::new(logger)));
            LOGGER_INITIALIZED.store(true, Ordering::SeqCst);
        });
    }
    
    Ok(())
}

/// Initialize the logger from config string
pub async fn init_from_config(level_str: &str, log_file: Option<&str>) -> LogResult<()> {
    let level = LogLevel::from_str(level_str)?;
    init(level, log_file, true, true).await
}

/// Set the current log level
pub async fn set_level(level: LogLevel) -> LogResult<()> {
    if !LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        return Err(LogError::InitError("Logger not initialized".to_string()));
    }
    
    unsafe {
        if let Some(logger) = &LOGGER {
            let mut guard = logger.lock().await;
            guard.level = level;
        }
    }
    
    Ok(())
}

/// Internal log function
async fn log_internal(level: LogLevel, message: &str, module: &str) -> LogResult<()> {
    if !LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        // If logger is not initialized, just print to stdout as fallback
        let now = Local::now();
        println!("{} [{}] [{}] {}", 
            now.format("%Y-%m-%d %H:%M:%S%.3f"),
            level,
            module,
            message
        );
        return Ok(());
    }
    
    unsafe {
        if let Some(logger) = &LOGGER {
            let guard = logger.lock().await;
            guard.log(level, message, module).await?;
        }
    }
    
    Ok(())
}

/// Get module name from file path
fn get_module_name(file: &str) -> &str {
    file.split('/')
        .last()
        .unwrap_or(file)
        .split('\\')
        .last()
        .unwrap_or(file)
        .split('.')
        .next()
        .unwrap_or(file)
}

/// Log at trace level
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        let _ = $crate::utils::logging::log_internal(
            $crate::utils::logging::LogLevel::Trace,
            &message,
            module
        );
    }
}

/// Log at debug level
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        let _ = $crate::utils::logging::log_internal(
            $crate::utils::logging::LogLevel::Debug,
            &message,
            module
        );
    }
}

/// Log at info level
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        let _ = $crate::utils::logging::log_internal(
            $crate::utils::logging::LogLevel::Info,
            &message,
            module
        );
    }
}

/// Log at warn level
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        let _ = $crate::utils::logging::log_internal(
            $crate::utils::logging::LogLevel::Warn,
            &message,
            module
        );
    }
}

/// Log at error level
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        let module = $crate::utils::logging::get_module_name(file!());
        let message = format!($($arg)*);
        let _ = $crate::utils::logging::log_internal(
            $crate::utils::logging::LogLevel::Error,
            &message,
            module
        );
    }
}

// Re-export these functions for macro usage
pub use get_module_name;
pub use log_internal;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;
    use tempfile::NamedTempFile;
    use std::fs;
    
    #[test]
    fn test_log_level_parse() {
        assert_eq!(LogLevel::from_str("trace").unwrap(), LogLevel::Trace);
        assert_eq!(LogLevel::from_str("debug").unwrap(), LogLevel::Debug);
        assert_eq!(LogLevel::from_str("info").unwrap(), LogLevel::Info);
        assert_eq!(LogLevel::from_str("warn").unwrap(), LogLevel::Warn);
        assert_eq!(LogLevel::from_str("warning").unwrap(), LogLevel::Warn);
        assert_eq!(LogLevel::from_str("error").unwrap(), LogLevel::Error);
        assert_eq!(LogLevel::from_str("err").unwrap(), LogLevel::Error);
        
        assert!(LogLevel::from_str("invalid").is_err());
    }
    
    #[test]
    fn test_module_name_extraction() {
        assert_eq!(get_module_name("src/utils/logging.rs"), "logging");
        assert_eq!(get_module_name("logging.rs"), "logging");
        assert_eq!(get_module_name("src\\utils\\logging.rs"), "logging");
    }
    
    #[test]
    fn test_logger_file_output() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            // Create a temporary file for logging
            let temp_file = NamedTempFile::new().unwrap();
            let file_path = temp_file.path().to_str().unwrap();
            
            // Initialize logger
            init(LogLevel::Debug, Some(file_path), false, true).await.unwrap();
            
            // Log some messages
            log_internal(LogLevel::Info, "Test info message", "test_module").await.unwrap();
            log_internal(LogLevel::Error, "Test error message", "test_module").await.unwrap();
            
            // Check file contents
            let contents = fs::read_to_string(file_path).unwrap();
            assert!(contents.contains("[INFO] [test_module] Test info message"));
            assert!(contents.contains("[ERROR] [test_module] Test error message"));
        });
    }
    
    #[test]
    fn test_log_level_filtering() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            // Create a temporary file for logging
            let temp_file = NamedTempFile::new().unwrap();
            let file_path = temp_file.path().to_str().unwrap();
            
            // Initialize logger with INFO level
            init(LogLevel::Info, Some(file_path), false, true).await.unwrap();
            
            // Log some messages
            log_internal(LogLevel::Debug, "Should not appear", "test_module").await.unwrap();
            log_internal(LogLevel::Info, "Should appear", "test_module").await.unwrap();
            
            // Check file contents
            let contents = fs::read_to_string(file_path).unwrap();
            assert!(!contents.contains("Should not appear"));
            assert!(contents.contains("Should appear"));
        });
    }
}