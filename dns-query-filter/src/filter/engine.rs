use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::db::operations::{DbError, DbOperations};
use crate::filter::rules::{Rule, RuleAction, TimeRestriction};
use crate::filter::categories::CategoryManager;
use crate::models::client::{ClientInfo, ClientMappingManager};
use crate::utils::logging::{debug, error, info, warn};
use crate::utils::metrics::increment_counter;

/// Error types for filter operations
#[derive(Error, Debug)]
pub enum FilterError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] DbError),
    
    #[error("Rule not found: {0}")]
    RuleNotFound(u32),
    
    #[error("Category not found: {0}")]
    CategoryNotFound(String),
    
    #[error("Invalid time format: {0}")]
    InvalidTimeFormat(String),
}

/// Result type for filter operations
pub type FilterResult<T> = Result<T, FilterError>;

/// Filter check result
#[derive(Debug, Clone)]
pub struct FilterCheckResult {
    /// Whether the domain is allowed
    pub is_allowed: bool,
    
    /// Reason for blocking (if blocked)
    pub reason: String,
    
    /// Category the domain belongs to (if known)
    pub category: Option<String>,
    
    /// Group ID that determined this outcome
    pub group_id: String,
    
    /// Rule ID that determined this outcome
    pub rule_id: Option<u32>,
}

/// Filter engine that applies rules to DNS queries
pub struct FilterEngine {
    /// Database access
    db: Arc<dyn DbOperations>,
    
    /// Client mapping manager
    client_manager: Arc<RwLock<ClientMappingManager>>,
    
    /// Category manager
    category_manager: Arc<RwLock<CategoryManager>>,
    
    /// In-memory cache of rules by group
    /// Maps group_id -> list of rules
    rules_cache: HashMap<String, Vec<Rule>>,
    
    /// When rules were last refreshed
    rules_last_refresh: SystemTime,
    
    /// How long to cache rules before refreshing
    rules_cache_ttl: Duration,
}

impl FilterEngine {
    /// Create a new filter engine
    pub async fn new(
        db: Arc<dyn DbOperations>,
        client_manager: Arc<RwLock<ClientMappingManager>>,
        category_manager: Arc<RwLock<CategoryManager>>,
        rules_cache_ttl: Duration,
    ) -> FilterResult<Self> {
        let mut engine = Self {
            db,
            client_manager,
            category_manager,
            rules_cache: HashMap::new(),
            rules_last_refresh: SystemTime::now(),
            rules_cache_ttl,
        };
        
        // Initial load of rules
        engine.refresh_rules().await?;
        
        Ok(engine)
    }
    
    /// Refresh rules from the database
    pub async fn refresh_rules(&mut self) -> FilterResult<()> {
        debug!("Refreshing filter rules from database");
        
        // Get all rules from database
        let rules = self.db.get_all_rules().await?;
        
        // Group rules by group_id
        let mut rules_by_group: HashMap<String, Vec<Rule>> = HashMap::new();
        
        for rule in rules {
            rules_by_group
                .entry(rule.group_id.clone())
                .or_insert_with(Vec::new)
                .push(rule);
        }
        
        // Sort rules within each group by priority
        for rules in rules_by_group.values_mut() {
            rules.sort_by(|a, b| a.priority.cmp(&b.priority));
        }
        
        // Update cache
        self.rules_cache = rules_by_group;
        self.rules_last_refresh = SystemTime::now();
        
        info!("Filter rules refreshed, rules for {} groups loaded", self.rules_cache.len());
        
        Ok(())
    }
    
    /// Check if we need to refresh rules
    async fn ensure_rules_fresh(&mut self) -> FilterResult<()> {
        let elapsed = SystemTime::now()
            .duration_since(self.rules_last_refresh)
            .unwrap_or(Duration::from_secs(0));
            
        if elapsed > self.rules_cache_ttl {
            self.refresh_rules().await?;
        }
        
        Ok(())
    }
    
    /// Check if a domain should be filtered for a client
    pub async fn check_domain(&self, domain: &str, client: &ClientInfo) -> FilterCheckResult {
        // Make a mutable clone of the client info so we can enrich it
        let mut client_info = client.clone();
        
        // Try to get additional client info (MAC, hostname)
        if let Err(e) = {
            let client_manager = self.client_manager.read().await;
            client_manager.enrich_client_info(&mut client_info)
        }.await {
            debug!("Failed to enrich client info: {}", e);
        }
        
        // Get the client's group ID
        let group_id = if let Some(id) = &client_info.group_id {
            id.clone()
        } else {
            let mut client_manager = self.client_manager.write().await;
            client_manager.get_client_group(&client_info).await
        };
        
        // Look up domain category
        let domain_category = {
            let category_manager = self.category_manager.read().await;
            category_manager.get_domain_category(domain).await
        };
        
        // Get rules for this group
        let rules = match self.rules_cache.get(&group_id) {
            Some(rules) => rules,
            None => {
                // If no rules for this group, default to allow
                return FilterCheckResult {
                    is_allowed: true,
                    reason: "No rules defined for group".into(),
                    category: domain_category.clone(),
                    group_id,
                    rule_id: None,
                };
            }
        };
        
        // Current time for time-based restrictions
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        
        // Apply rules in priority order
        for rule in rules {
            // Skip disabled rules
            if !rule.enabled {
                continue;
            }
            
            // Check time restrictions
            if !Self::check_time_restriction(&rule.time_restrictions, now) {
                continue;
            }
            
            // Skip rules for other categories if we know the category
            if let Some(category) = &domain_category {
                if !rule.categories.is_empty() && !rule.categories.contains(category) {
                    continue;
                }
            }
            
            // Check exact domain matches
            if rule.exact_domains.contains(&domain.to_string()) {
                return self.create_result(rule, domain_category, group_id);
            }
            
            // Check domain pattern matches
            for pattern in &rule.domain_patterns {
                if Self::domain_matches_pattern(domain, pattern) {
                    return self.create_result(rule, domain_category, group_id);
                }
            }
            
            // If rule applies to all domains and we have no pattern/exact matches
            if rule.domain_patterns.is_empty() && rule.exact_domains.is_empty() {
                // If rule applies to categories and we have a category match
                if let Some(category) =