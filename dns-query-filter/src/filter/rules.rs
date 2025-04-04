use std::collections::HashSet;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};

/// Rule action - whether to allow or block traffic
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    /// Allow traffic
    Allow,
    
    /// Block traffic
    Block,
}

/// Time restriction for when a rule is active
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestriction {
    /// ID in the database
    pub id: Option<u32>,
    
    /// Days of the week when this restriction applies (0 = Sunday, 6 = Saturday)
    pub days: Vec<u8>,
    
    /// Start time in seconds from midnight
    pub start_time: u64,
    
    /// End time in seconds from midnight
    pub end_time: u64,
    
    /// When this restriction was created
    pub created_at: SystemTime,
}

/// Filter rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule ID (unique)
    pub id: u32,
    
    /// Group this rule applies to
    pub group_id: String,
    
    /// Rule priority (lower numbers are processed first)
    pub priority: u32,
    
    /// Action (allow/block)
    pub action: RuleAction,
    
    /// Whether this rule is enabled
    pub enabled: bool,
    
    /// Description of the rule
    pub description: String,
    
    /// Exact domains this rule applies to
    pub exact_domains: HashSet<String>,
    
    /// Domain patterns this rule applies to (wildcards)
    pub domain_patterns: HashSet<String>,
    
    /// Categories this rule applies to
    pub categories: HashSet<String>,
    
    /// Time restrictions for when this rule is active
    pub time_restrictions: Vec<TimeRestriction>,
    
    /// When this rule was created
    pub created_at: SystemTime,
    
    /// When this rule was last updated
    pub updated_at: SystemTime,
}

impl Rule {
    /// Create a new rule
    pub fn new(
        id: u32,
        group_id: String,
        priority: u32,
        action: RuleAction,
        description: String,
    ) -> Self {
        let now = SystemTime::now();
        
        Self {
            id,
            group_id,
            priority,
            action,
            enabled: true,
            description,
            exact_domains: HashSet::new(),
            domain_patterns: HashSet::new(),
            categories: HashSet::new(),
            time_restrictions: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
    
    /// Check if a domain matches this rule
    pub fn matches_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        
        // Check exact domains
        if self.exact_domains.contains(&domain_lower) {
            return true;
        }
        
        // Check domain patterns
        for pattern in &self.domain_patterns {
            if Self::domain_matches_pattern(&domain_lower, pattern) {
                return true;
            }
        }
        
        false
    }
    
    /// Check if a domain matches a pattern
    /// 
    /// Supports wildcard patterns:
    /// - *.example.com: matches any subdomain of example.com
    /// - example.*: matches example with any TLD
    /// - *example*: matches any domain containing "example"
    fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
        // Handle different wildcard positions
        if pattern.starts_with("*.") {
            // *.example.com pattern - match any subdomain
            let suffix = &pattern[2..]; // Remove the "*."
            domain.ends_with(suffix) && domain.len() > suffix.len() &&
                domain.chars().nth(domain.len() - suffix.len() - 1) == Some('.')
        } else if pattern.ends_with(".*") {
            // domain.* pattern - match any TLD
            let prefix = &pattern[..pattern.len() - 2]; // Remove the ".*"
            domain.starts_with(prefix) && domain.len() > prefix.len() &&
                domain.chars().nth(prefix.len()) == Some('.')
        } else if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
            // *contains* pattern - match if domain contains the middle part
            let middle = &pattern[1..pattern.len() - 1];
            domain.contains(middle)
        } else if pattern.starts_with('*') {
            // *suffix pattern - match if domain ends with the suffix
            let suffix = &pattern[1..];
            domain.ends_with(suffix)
        } else if pattern.ends_with('*') {
            // prefix* pattern - match if domain starts with the prefix
            let prefix = &pattern[..pattern.len() - 1];
            domain.starts_with(prefix)
        } else {
            // Exact match (no wildcards)
            domain == pattern
        }
    }
    
    /// Add an exact domain to this rule
    pub fn add_exact_domain(&mut self, domain: &str) {
        self.exact_domains.insert(domain.to_lowercase());
        self.updated_at = SystemTime::now();
    }
    
    /// Remove an exact domain from this rule
    pub fn remove_exact_domain(&mut self, domain: &str) {
        self.exact_domains.remove(&domain.to_lowercase());
        self.updated_at = SystemTime::now();
    }
    
    /// Add a domain pattern to this rule
    pub fn add_domain_pattern(&mut self, pattern: &str) {
        self.domain_patterns.insert(pattern.to_lowercase());
        self.updated_at = SystemTime::now();
    }
    
    /// Remove a domain pattern from this rule
    pub fn remove_domain_pattern(&mut self, pattern: &str) {
        self.domain_patterns.remove(&pattern.to_lowercase());
        self.updated_at = SystemTime::now();
    }
    
    /// Add a category to this rule
    pub fn add_category(&mut self, category: &str) {
        self.categories.insert(category.to_string());
        self.updated_at = SystemTime::now();
    }
    
    /// Remove a category from this rule
    pub fn remove_category(&mut self, category: &str) {
        self.categories.remove(category);
        self.updated_at = SystemTime::now();
    }
    
    /// Add a time restriction to this rule
    pub fn add_time_restriction(&mut self, restriction: TimeRestriction) {
        self.time_restrictions.push(restriction);
        self.updated_at = SystemTime::now();
    }
    
    /// Remove a time restriction from this rule
    pub fn remove_time_restriction(&mut self, restriction_id: u32) {
        self.time_restrictions.retain(|r| {
            if let Some(id) = r.id {
                id != restriction_id
            } else {
                true
            }
        });
        self.updated_at = SystemTime::now();
    }
    
    /// Set the rule's enabled status
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.updated_at = SystemTime::now();
    }
    
    /// Set the rule's priority
    pub fn set_priority(&mut self, priority: u32) {
        self.priority = priority;
        self.updated_at = SystemTime::now();
    }
    
    /// Set the rule's action
    pub fn set_action(&mut self, action: RuleAction) {
        self.action = action;
        self.updated_at = SystemTime::now();
    }
    
    /// Set the rule's description
    pub fn set_description(&mut self, description: String) {
        self.description = description;
        self.updated_at = SystemTime::now();
    }
}

/// Builder for creating rules
pub struct RuleBuilder {
    id: u32,
    group_id: String,
    priority: u32,
    action: RuleAction,
    enabled: bool,
    description: String,
    exact_domains: HashSet<String>,
    domain_patterns: HashSet<String>,
    categories: HashSet<String>,
    time_restrictions: Vec<TimeRestriction>,
}

impl RuleBuilder {
    /// Create a new rule builder
    pub fn new(id: u32, group_id: String) -> Self {
        Self {
            id,
            group_id,
            priority: 100, // Default priority
            action: RuleAction::Block, // Default action
            enabled: true,
            description: String::new(),
            exact_domains: HashSet::new(),
            domain_patterns: HashSet::new(),
            categories: HashSet::new(),
            time_restrictions: Vec::new(),
        }
    }
    
    /// Set the rule priority
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
    
    /// Set the rule action
    pub fn action(mut self, action: RuleAction) -> Self {
        self.action = action;
        self
    }
    
    /// Set whether the rule is enabled
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
    
    /// Set the rule description
    pub fn description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }
    
    /// Add an exact domain
    pub fn add_exact_domain(mut self, domain: &str) -> Self {
        self.exact_domains.insert(domain.to_lowercase());
        self
    }
    
    /// Add multiple exact domains
    pub fn add_exact_domains(mut self, domains: &[&str]) -> Self {
        for domain in domains {
            self.exact_domains.insert(domain.to_lowercase());
        }
        self
    }
    
    /// Add a domain pattern
    pub fn add_domain_pattern(mut self, pattern: &str) -> Self {
        self.domain_patterns.insert(pattern.to_lowercase());
        self
    }
    
    /// Add multiple domain patterns
    pub fn add_domain_patterns(mut self, patterns: &[&str]) -> Self {
        for pattern in patterns {
            self.domain_patterns.insert(pattern.to_lowercase());
        }
        self
    }
    
    /// Add a category
    pub fn add_category(mut self, category: &str) -> Self {
        self.categories.insert(category.to_string());
        self
    }
    
    /// Add multiple categories
    pub fn add_categories(mut self, categories: &[&str]) -> Self {
        for category in categories {
            self.categories.insert(category.to_string());
        }
        self
    }
    
    /// Add a time restriction
    pub fn add_time_restriction(mut self, restriction: TimeRestriction) -> Self {
        self.time_restrictions.push(restriction);
        self
    }
    
    /// Build the rule
    pub fn build(self) -> Rule {
        let now = SystemTime::now();
        
        Rule {
            id: self.id,
            group_id: self.group_id,
            priority: self.priority,
            action: self.action,
            enabled: self.enabled,
            description: self.description,
            exact_domains: self.exact_domains,
            domain_patterns: self.domain_patterns,
            categories: self.categories,
            time_restrictions: self.time_restrictions,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Create a new time restriction
pub fn new_time_restriction(
    days: Vec<u8>,
    start_hour: u8,
    start_minute: u8,
    end_hour: u8,
    end_minute: u8,
) -> TimeRestriction {
    // Convert hours and minutes to seconds since midnight
    let start_time = (start_hour as u64) * 3600 + (start_minute as u64) * 60;
    let end_time = (end_hour as u64) * 3600 + (end_minute as u64) * 60;
    
    TimeRestriction {
        id: None,
        days,
        start_time,
        end_time,
        created_at: SystemTime::now(),
    }
}

/// Create a weekday time restriction (Monday-Friday)
pub fn weekday_restriction(
    start_hour: u8,
    start_minute: u8,
    end_hour: u8,
    end_minute: u8,
) -> TimeRestriction {
    // 1-5 = Monday-Friday
    new_time_restriction(vec![1, 2, 3, 4, 5], start_hour, start_minute, end_hour, end_minute)
}

/// Create a weekend time restriction (Saturday-Sunday)
pub fn weekend_restriction(
    start_hour: u8,
    start_minute: u8,
    end_hour: u8,
    end_minute: u8,
) -> TimeRestriction {
    // 0 = Sunday, 6 = Saturday
    new_time_restriction(vec![0, 6], start_hour, start_minute, end_hour, end_minute)
}

/// Create an everyday time restriction
pub fn everyday_restriction(
    start_hour: u8,
    start_minute: u8,
    end_hour: u8,
    end_minute: u8,
) -> TimeRestriction {
    // 0-6 = Sunday-Saturday
    new_time_restriction(vec![0, 1, 2, 3, 4, 5, 6], start_hour, start_minute, end_hour, end_minute)
}
