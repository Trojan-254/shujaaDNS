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
            
            // If rule applies to categories and we have a category match
            if let Some(category) = &domain_category {
                if rule.categories.contains(category) {
                    return self.create_result(rule, domain_category, group_id);
                }
            }
            
            // If this is a general rule (no domains or categories specified)
            if rule.exact_domains.is_empty() && rule.domain_patterns.is_empty() && rule.categories.is_empty() {
                return self.create_result(rule, domain_category, group_id);
            }
        }
        
        // If no rules matched, default to allow
        FilterCheckResult {
            is_allowed: true,
            reason: "No matching rules".into(),
            category: domain_category,
            group_id,
            rule_id: None,
        }
    }
    
    /// Create a result from a rule match
    fn create_result(&self, rule: &Rule, category: Option<String>, group_id: String) -> FilterCheckResult {
        // Determine if it's allowed based on the rule action
        let is_allowed = rule.action == RuleAction::Allow;
        
        // Increment metrics counter based on action
        if is_allowed {
            increment_counter("filter_allowed");
        } else {
            increment_counter("filter_blocked");
        }
        
        FilterCheckResult {
            is_allowed,
            reason: rule.description.clone(),
            category,
            group_id,
            rule_id: Some(rule.id),
        }
    }
    
    /// Check if a domain matches a pattern
    /// 
    /// Supports simple wildcard patterns:
    /// - *.example.com: matches any subdomain of example.com
    /// - example.*: matches example with any TLD
    /// - *example*: matches any domain containing "example"
    fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
        // Convert domain and pattern to lowercase for case-insensitive matching
        let domain_lower = domain.to_lowercase();
        let pattern_lower = pattern.to_lowercase();
        
        // Handle different wildcard positions
        if pattern_lower.starts_with("*.") {
            // *.example.com pattern - match any subdomain
            let suffix = &pattern_lower[2..]; // Remove the "*."
            domain_lower.ends_with(suffix) && domain_lower.len() > suffix.len() &&
                domain_lower.chars().nth(domain_lower.len() - suffix.len() - 1) == Some('.')
        } else if pattern_lower.ends_with(".*") {
            // domain.* pattern - match any TLD
            let prefix = &pattern_lower[..pattern_lower.len() - 2]; // Remove the ".*"
            domain_lower.starts_with(prefix) && domain_lower.len() > prefix.len() &&
                domain_lower.chars().nth(prefix.len()) == Some('.')
        } else if pattern_lower.starts_with('*') && pattern_lower.ends_with('*') && pattern_lower.len() > 2 {
            // *contains* pattern - match if domain contains the middle part
            let middle = &pattern_lower[1..pattern_lower.len() - 1];
            domain_lower.contains(middle)
        } else if pattern_lower.starts_with('*') {
            // *suffix pattern - match if domain ends with the suffix
            let suffix = &pattern_lower[1..];
            domain_lower.ends_with(suffix)
        } else if pattern_lower.ends_with('*') {
            // prefix* pattern - match if domain starts with the prefix
            let prefix = &pattern_lower[..pattern_lower.len() - 1];
            domain_lower.starts_with(prefix)
        } else {
            // Exact match (no wildcards)
            domain_lower == pattern_lower
        }
    }
    
    /// Check if the current time satisfies time restrictions
    fn check_time_restriction(restrictions: &[TimeRestriction], current_time: u64) -> bool {
        // If no time restrictions, allow at any time
        if restrictions.is_empty() {
            return true;
        }
        
        // Check each time restriction
        for restriction in restrictions {
            // Get current day of week (0 = Sunday, 6 = Saturday)
            let current_day = chrono::Utc::now().weekday().num_days_from_sunday() as u8;
            
            // Check if current day is included
            if !restriction.days.contains(&current_day) {
                continue;
            }
            
            // Convert current_time to seconds since midnight in local time
            let now = chrono::Utc::now().naive_local();
            let seconds_since_midnight = 
                now.hour() as u64 * 3600 + now.minute() as u64 * 60 + now.second() as u64;
            
            // Check if current time is within the allowed range
            if seconds_since_midnight >= restriction.start_time && 
               seconds_since_midnight <= restriction.end_time {
                return true;
            }
        }
        
        // No matching time restriction found
        false
    }
    
    /// Add a new rule to the filter
    pub async fn add_rule(&mut self, rule: Rule) -> FilterResult<u32> {
        // Ensure rule has a valid ID
        let rule_id = self.db.add_rule(&rule).await?;
        
        // Force refresh of rules
        self.refresh_rules().await?;
        
        Ok(rule_id)
    }
    
    /// Update an existing rule
    pub async fn update_rule(&mut self, rule: Rule) -> FilterResult<()> {
        // Check if rule exists
        if !self.db.rule_exists(rule.id).await? {
            return Err(FilterError::RuleNotFound(rule.id));
        }
        
        // Update the rule
        self.db.update_rule(&rule).await?;
        
        // Refresh rules
        self.refresh_rules().await?;
        
        Ok(())
    }
    
    /// Delete a rule
    pub async fn delete_rule(&mut self, rule_id: u32) -> FilterResult<()> {
        // Check if rule exists
        if !self.db.rule_exists(rule_id).await? {
            return Err(FilterError::RuleNotFound(rule_id));
        }
        
        // Delete the rule
        self.db.delete_rule(rule_id).await?;
        
        // Refresh rules
        self.refresh_rules().await?;
        
        Ok(())
    }
    
    /// Get all rules for a specific group
    pub async fn get_rules_for_group(&self, group_id: &str) -> Vec<Rule> {
        match self.rules_cache.get(group_id) {
            Some(rules) => rules.clone(),
            None => Vec::new(),
        }
    }
    
    /// Get a specific rule by ID
    pub async fn get_rule(&self, rule_id: u32) -> FilterResult<Rule> {
        // Look through all cached rules
        for rules in self.rules_cache.values() {
            if let Some(rule) = rules.iter().find(|r| r.id == rule_id) {
                return Ok(rule.clone());
            }
        }
        
        // If not found in cache, try the database
        match self.db.get_rule(rule_id).await {
            Ok(rule) => Ok(rule),
            Err(_) => Err(FilterError::RuleNotFound(rule_id)),
        }
    }
    
    /// Search domains against all filter rules (used for bulk checking)
    pub async fn bulk_check_domains(&self, domains: &[String], client: &ClientInfo) -> HashMap<String, FilterCheckResult> {
        let mut results = HashMap::new();
        
        for domain in domains {
            results.insert(
                domain.clone(),
                self.check_domain(domain, client).await,
            );
        }
        
        results
    }
    
    /// Clean cached resources that are no longer needed
    pub async fn cleanup(&mut self) {
        // Check if we need to refresh rules
        let _ = self.ensure_rules_fresh().await;
        
        // Clean up other managers
        {
            let mut category_manager = self.category_manager.write().await;
            category_manager.cleanup().await;
        }
        
        {
            let mut client_manager = self.client_manager.write().await;
            client_manager.cleanup().await;
        }
    }
}