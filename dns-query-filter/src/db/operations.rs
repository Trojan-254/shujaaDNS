// src/db/operations.rs

use async_trait::async_trait;
use thiserror::Error;
use tokio_postgres::{Client, Error as PgError};
use std::sync::Arc;

use crate::filter::rules::{Rule, RuleAction, TimeRestriction};

/// Database operation errors
#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    ConnectionError(String),
    
    #[error("Query execution error: {0}")]
    QueryError(#[from] PgError),
    
    #[error("No data found: {0}")]
    NotFound(String),
    
    #[error("Data conversion error: {0}")]
    ConversionError(String),
}

/// Result type for database operations
pub type DbResult<T> = Result<T, DbError>;

/// Database operations interface
#[async_trait]
pub trait DbOperations: Send + Sync {
    /// Get all rules from the database
    async fn get_all_rules(&self) -> DbResult<Vec<Rule>>;
    
    /// Get a specific rule by ID
    async fn get_rule(&self, rule_id: u32) -> DbResult<Rule>;
    
    /// Check if a rule exists
    async fn rule_exists(&self, rule_id: u32) -> DbResult<bool>;
    
    /// Add a new rule to the database
    async fn add_rule(&self, rule: &Rule) -> DbResult<u32>;
    
    /// Update an existing rule
    async fn update_rule(&self, rule: &Rule) -> DbResult<()>;
    
    /// Delete a rule
    async fn delete_rule(&self, rule_id: u32) -> DbResult<()>;
    
    /// Get all categories
    async fn get_all_categories(&self) -> DbResult<Vec<String>>;
    
    /// Get domains in a specific category
    async fn get_domains_in_category(&self, category: &str) -> DbResult<Vec<String>>;
    
    /// Add a domain to a category
    async fn add_domain_to_category(&self, domain: &str, category: &str) -> DbResult<()>;
    
    /// Remove a domain from a category
    async fn remove_domain_from_category(&self, domain: &str, category: &str) -> DbResult<()>;
    
    /// Get the category for a specific domain
    async fn get_domain_category(&self, domain: &str) -> DbResult<Option<String>>;
    
    /// Add a client mapping
    async fn add_client_mapping(&self, ip: &str, mac: Option<&str>, hostname: Option<&str>, group_id: &str) -> DbResult<()>;
    
    /// Get group ID for a client
    async fn get_client_group(&self, ip: &str, mac: Option<&str>, hostname: Option<&str>) -> DbResult<String>;
    
    /// Log a DNS query
    async fn log_query(&self, domain: &str, client_ip: &str, client_mac: Option<&str>, 
                     client_group: &str, allowed: bool, category: Option<&str>, 
                     rule_id: Option<u32>) -> DbResult<()>;
}

/// PostgreSQL implementation of DbOperations
pub struct PostgresDb {
    client: Arc<Client>,
}

impl PostgresDb {
    /// Create a new PostgreSQL database connection
    pub async fn new(connection_string: &str) -> DbResult<Self> {
        let (client, connection) = tokio_postgres::connect(connection_string, tokio_postgres::NoTls)
            .await
            .map_err(|e| DbError::ConnectionError(e.to_string()))?;
            
        // Spawn the connection handler
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Database connection error: {}", e);
            }
        });
        
        Ok(Self {
            client: Arc::new(client),
        })
    }
    
    /// Convert database row to Rule
    async fn row_to_rule(&self, id: i32) -> DbResult<Rule> {
        // Get the base rule info
        let row = self.client.query_one(
            "SELECT id, group_id, priority, action, enabled, description 
             FROM rules WHERE id = $1",
            &[&id],
        ).await?;
        
        let rule_id = row.get::<_, i32>("id") as u32;
        let group_id = row.get::<_, String>("group_id");
        let priority = row.get::<_, i32>("priority") as u32;
        let action_str = row.get::<_, String>("action");
        let action = if action_str == "ALLOW" { RuleAction::Allow } else { RuleAction::Block };
        let enabled = row.get::<_, bool>("enabled");
        let description = row.get::<_, String>("description");
        
        // Get exact domains
        let domains_rows = self.client.query(
            "SELECT domain FROM rule_domains WHERE rule_id = $1",
            &[&id],
        ).await?;
        
        let exact_domains = domains_rows.iter()
            .map(|row| row.get::<_, String>("domain"))
            .collect();
            
        // Get domain patterns
        let patterns_rows = self.client.query(
            "SELECT pattern FROM rule_patterns WHERE rule_id = $1",
            &[&id],
        ).await?;
        
        let domain_patterns = patterns_rows.iter()
            .map(|row| row.get::<_, String>("pattern"))
            .collect();
            
        // Get categories
        let categories_rows = self.client.query(
            "SELECT category_name FROM rule_categories WHERE rule_id = $1",
            &[&id],
        ).await?;
        
        let categories = categories_rows.iter()
            .map(|row| row.get::<_, String>("category_name"))
            .collect();
            
        // Get time restrictions
        let time_rows = self.client.query(
            "SELECT days, start_time, end_time 
             FROM time_restrictions WHERE rule_id = $1",
            &[&id],
        ).await?;
        
        let time_restrictions = time_rows.iter()
            .map(|row| {
                let days_str = row.get::<_, String>("days");
                let days = days_str.chars()
                    .map(|c| c.to_digit(10).unwrap_or(0) as u8)
                    .collect();
                    
                TimeRestriction {
                    days,
                    start_time: row.get::<_, i32>("start_time") as u64,
                    end_time: row.get::<_, i32>("end_time") as u64,
                }
            })
            .collect();
            
        Ok(Rule {
            id: rule_id,
            group_id,
            priority,
            action,
            enabled,
            description,
            exact_domains,
            domain_patterns,
            categories,
            time_restrictions,
        })
    }
}

#[async_trait]
impl DbOperations for PostgresDb {
    async fn get_all_rules(&self) -> DbResult<Vec<Rule>> {
        let rows = self.client.query(
            "SELECT id FROM rules ORDER BY group_id, priority",
            &[],
        ).await?;
        
        let mut rules = Vec::new();
        for row in rows {
            let id = row.get::<_, i32>("id");
            let rule = self.row_to_rule(id).await?;
            rules.push(rule);
        }
        
        Ok(rules)
    }
    
    async fn get_rule(&self, rule_id: u32) -> DbResult<Rule> {
        self.row_to_rule(rule_id as i32).await
    }
    
    async fn rule_exists(&self, rule_id: u32) -> DbResult<bool> {
        let row = self.client.query_one(
            "SELECT EXISTS(SELECT 1 FROM rules WHERE id = $1)",
            &[&(rule_id as i32)],
        ).await?;
        
        Ok(row.get::<_, bool>(0))
    }
    
    async fn add_rule(&self, rule: &Rule) -> DbResult<u32> {
        // Start a transaction
        let tx = self.client.transaction().await?;
        
        // Insert the base rule
        let row = tx.query_one(
            "INSERT INTO rules (group_id, priority, action, enabled, description) 
             VALUES ($1, $2, $3, $4, $5) 
             RETURNING id",
            &[
                &rule.group_id,
                &(rule.priority as i32),
                &(if rule.action == RuleAction::Allow { "ALLOW" } else { "BLOCK" }),
                &rule.enabled,
                &rule.description,
            ],
        ).await?;
        
        let rule_id = row.get::<_, i32>("id");
        
        // Insert exact domains
        for domain in &rule.exact_domains {
            tx.execute(
                "INSERT INTO rule_domains (rule_id, domain) VALUES ($1, $2)",
                &[&rule_id, &domain],
            ).await?;
        }
        
        // Insert domain patterns
        for pattern in &rule.domain_patterns {
            tx.execute(
                "INSERT INTO rule_patterns (rule_id, pattern) VALUES ($1, $2)",
                &[&rule_id, &pattern],
            ).await?;
        }
        
        // Insert categories
        for category in &rule.categories {
            tx.execute(
                "INSERT INTO rule_categories (rule_id, category_name) VALUES ($1, $2)",
                &[&rule_id, &category],
            ).await?;
        }
        
        // Insert time restrictions
        for restriction in &rule.time_restrictions {
            // Convert days to string representation
            let days_str: String = restriction.days.iter()
                .map(|d| d.to_string())
                .collect();
                
            tx.execute(
                "INSERT INTO time_restrictions (rule_id, days, start_time, end_time) 
                 VALUES ($1, $2, $3, $4)",
                &[
                    &rule_id,
                    &days_str,
                    &(restriction.start_time as i32),
                    &(restriction.end_time as i32),
                ],
            ).await?;
        }
        
        // Commit the transaction
        tx.commit().await?;
        
        Ok(rule_id as u32)
    }
    
    async fn update_rule(&self, rule: &Rule) -> DbResult<()> {
        // Start a transaction
        let tx = self.client.transaction().await?;
        let rule_id = rule.id as i32;
        
        // Update the base rule
        tx.execute(
            "UPDATE rules SET 
                group_id = $1,
                priority = $2,
                action = $3,
                enabled = $4,
                description = $5,
                updated_at = CURRENT_TIMESTAMP
             WHERE id = $6",
            &[
                &rule.group_id,
                &(rule.priority as i32),
                &(if rule.action == RuleAction::Allow { "ALLOW" } else { "BLOCK" }),
                &rule.enabled,
                &rule.description,
                &rule_id,
            ],
        ).await?;
        
        // Delete existing domains, patterns, categories, and time restrictions
        tx.execute("DELETE FROM rule_domains WHERE rule_id = $1", &[&rule_id]).await?;
        tx.execute("DELETE FROM rule_patterns WHERE rule_id = $1", &[&rule_id]).await?;
        tx.execute("DELETE FROM rule_categories WHERE rule_id = $1", &[&rule_id]).await?;
        tx.execute("DELETE FROM time_restrictions WHERE rule_id = $1", &[&rule_id]).await?;
        
        // Insert exact domains
        for domain in &rule.exact_domains {
            tx.execute(
                "INSERT INTO rule_domains (rule_id, domain) VALUES ($1, $2)",
                &[&rule_id, &domain],
            ).await?;
        }
        
        // Insert domain patterns
        for pattern in &rule.domain_patterns {
            tx.execute(
                "INSERT INTO rule_patterns (rule_id, pattern) VALUES ($1, $2)",
                &[&rule_id, &pattern],
            ).await?;
        }
        
        // Insert categories
        for category in &rule.categories {
            tx.execute(
                "INSERT INTO rule_categories (rule_id, category_name) VALUES ($1, $2)",
                &[&rule_id, &category],
            ).await?;
        }
        
        // Insert time restrictions
        for restriction in &rule.time_restrictions {
            // Convert days to string representation
            let days_str: String = restriction.days.iter()
                .map(|d| d.to_string())
                .collect();
                
            tx.execute(
                "INSERT INTO time_restrictions (rule_id, days, start_time, end_time) 
                 VALUES ($1, $2, $3, $4)",
                &[
                    &rule_id,
                    &days_str,
                    &(restriction.start_time as i32),
                    &(restriction.end_time as i32),
                ],
            ).await?;
        }
        
        // Commit the transaction
        tx.commit().await?;
        
        Ok(())
    }
    
    async fn delete_rule(&self, rule_id: u32) -> DbResult<()> {
        // Due to foreign key constraints with CASCADE, we only need to delete the rule
        self.client.execute(
            "DELETE FROM rules WHERE id = $1",
            &[&(rule_id as i32)],
        ).await?;
        
        Ok(())
    }
    
    async fn get_all_categories(&self) -> DbResult<Vec<String>> {
        let rows = self.client.query(
            "SELECT name FROM categories ORDER BY name",
            &[],
        ).await?;
        
        let categories = rows.iter()
            .map(|row| row.get::<_, String>("name"))
            .collect();
            
        Ok(categories)
    }
    
    async fn get_domains_in_category(&self, category: &str) -> DbResult<Vec<String>> {
        let rows = self.client.query(
            "SELECT domain FROM domain_categories WHERE category_name = $1 ORDER BY domain",
            &[&category],
        ).await?;
        
        let domains = rows.iter()
            .map(|row| row.get::<_, String>("domain"))
            .collect();
            
        Ok(domains)
    }
    
    async fn add_domain_to_category(&self, domain: &str, category: &str) -> DbResult<()> {
        // First check if the category exists
        let category_exists = self.client.query_one(
            "SELECT EXISTS(SELECT 1 FROM categories WHERE name = $1)",
            &[&category],
        ).await?.get::<_, bool>(0);
        
        if !category_exists {
            return Err(DbError::NotFound(format!("Category '{}' does not exist", category)));
        }
        
        // Insert or update the domain category mapping
        self.client.execute(
            "INSERT INTO domain_categories (domain, category_name) 
             VALUES ($1, $2)
             ON CONFLICT (domain, category_name) DO NOTHING",
            &[&domain, &category],
        ).await?;
        
        Ok(())
    }
    
    async fn remove_domain_from_category(&self, domain: &str, category: &str) -> DbResult<()> {
        self.client.execute(
            "DELETE FROM domain_categories WHERE domain = $1 AND category_name = $2",
            &[&domain, &category],
        ).await?;
        
        Ok(())
    }
    
    async fn get_domain_category(&self, domain: &str) -> DbResult<Option<String>> {
        // Try exact domain match first
        let result = self.client.query_opt(
            "SELECT category_name FROM domain_categories WHERE domain = $1 LIMIT 1",
            &[&domain],
        ).await?;
        
        if let Some(row) = result {
            return Ok(Some(row.get::<_, String>("category_name")));
        }
        
        // Try to match domain against pattern rules (this is more complex in SQL)
        // For simplicity, we'll return None here - in practice, you might want to 
        // implement pattern matching in application code

        Ok(None)
    }
    
    async fn add_client_mapping(&self, ip: &str, mac: Option<&str>, hostname: Option<&str>, group_id: &str) -> DbResult<()> {
        // First check if the group exists
        let group_exists = self.client.query_one(
            "SELECT EXISTS(SELECT 1 FROM client_groups WHERE id = $1)",
            &[&group_id],
        ).await?.get::<_, bool>(0);
        
        if !group_exists {
            return Err(DbError::NotFound(format!("Group '{}' does not exist", group_id)));
        }
        
        // Check if mapping exists
        let existing = self.client.query_opt(
            "SELECT id FROM client_mappings 
             WHERE ip_address = $1 
             OR ($2::VARCHAR IS NOT NULL AND mac_address = $2)
             OR ($3::VARCHAR IS NOT NULL AND hostname = $3)",
            &[&ip, &mac, &hostname],
        ).await?;
        
        if let Some(row) = existing {
            // Update existing mapping
            let id = row.get::<_, i32>("id");
            self.client.execute(
                "UPDATE client_mappings SET 
                    group_id = $1,
                    ip_address = $2,
                    mac_address = $3,
                    hostname = $4,
                    active = TRUE,
                    last_seen = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                 WHERE id = $5",
                &[&group_id, &ip, &mac, &hostname, &id],
            ).await?;
        } else {
            // Insert new mapping
            self.client.execute(
                "INSERT INTO client_mappings 
                 (group_id, ip_address, mac_address, hostname, active) 
                 VALUES ($1, $2, $3, $4, TRUE)",
                &[&group_id, &ip, &mac, &hostname],
            ).await?;
        }
        
        Ok(())
    }
    
    async fn get_client_group(&self, ip: &str, mac: Option<&str>, hostname: Option<&str>) -> DbResult<String> {
        // Try to find matching client mapping
        let result = self.client.query_opt(
            "SELECT group_id FROM client_mappings 
             WHERE active = TRUE AND (
                ip_address = $1 
                OR ($2::VARCHAR IS NOT NULL AND mac_address = $2)
                OR ($3::VARCHAR IS NOT NULL AND hostname = $3)
             )
             ORDER BY last_seen DESC
             LIMIT 1",
            &[&ip, &mac, &hostname],
        ).await?;
        
        if let Some(row) = result {
            // Update last_seen
            let group_id = row.get::<_, String>("group_id");
            
            // No need to await this - fire and forget
            let client = self.client.clone();
            let ip_owned = ip.to_string();
            tokio::spawn(async move {
                let _ = client.execute(
                    "UPDATE client_mappings SET last_seen = CURRENT_TIMESTAMP 
                     WHERE ip_address = $1",
                    &[&ip_owned],
                ).await;
            });
            
            return Ok(group_id);
        }
        
        // If no mapping found, get the default group
        let default_row = self.client.query_opt(
            "SELECT id FROM client_groups WHERE default_group = TRUE LIMIT 1",
            &[],
        ).await?;
        
        if let Some(row) = default_row {
            let default_group = row.get::<_, String>("id");
            
            // Create a mapping for this client to the default group
            // No need to await this - fire and forget
            let client = self.client.clone();
            let ip_owned = ip.to_string();
            let mac_owned = mac.map(|s| s.to_string());
            let hostname_owned = hostname.map(|s| s.to_string());
            let group_id = default_group.clone();
            
            tokio::spawn(async move {
                let _ = client.execute(
                    "INSERT INTO client_mappings 
                     (group_id, ip_address, mac_address, hostname, active) 
                     VALUES ($1, $2, $3, $4, TRUE)",
                    &[&group_id, &ip_owned, &mac_owned, &hostname_owned],
                ).await;
            });
            
            return Ok(default_group);
        }
        
        // If no default group, error out
        Err(DbError::NotFound("No default client group configured".into()))
    }
    
    async fn log_query(&self, domain: &str, client_ip: &str, client_mac: Option<&str>, 
                     client_group: &str, allowed: bool, category: Option<&str>, 
                     rule_id: Option<u32>) -> DbResult<()> {
        // Insert query log
        self.client.execute(
            "INSERT INTO query_log 
             (domain, client_ip, client_mac, client_group, allowed, category, rule_id) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &domain, 
                &client_ip, 
                &client_mac, 
                &client_group, 
                &allowed, 
                &category, 
                &rule_id.map(|id| id as i32),
            ],
        ).await?;
        
        Ok(())
    }
}