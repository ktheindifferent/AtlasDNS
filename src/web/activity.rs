//! Activity Logging Module
//!
//! Tracks user actions and system events for audit trails and dashboard display.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type of activity being logged
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityType {
    Login,
    Logout,
    ZoneCreated,
    ZoneModified,
    ZoneDeleted,
    RecordAdded,
    RecordModified,
    RecordDeleted,
    UserCreated,
    UserModified,
    UserDeleted,
    CacheCleared,
    ConfigChanged,
    ApiRequest,
    SecurityEvent,
}

/// Activity log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user: String,
    pub user_id: Option<String>,
    pub activity_type: ActivityType,
    pub action: String,
    pub resource: String,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
}

impl ActivityEntry {
    /// Create a new activity entry
    pub fn new(
        user: String,
        user_id: Option<String>,
        activity_type: ActivityType,
        action: String,
        resource: String,
        success: bool,
    ) -> Self {
        ActivityEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user,
            user_id,
            activity_type,
            action,
            resource,
            details: None,
            ip_address: None,
            user_agent: None,
            success,
            error_message: None,
        }
    }
    
    /// Add additional details to the entry
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }
    
    /// Add IP address to the entry
    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }
    
    /// Add user agent to the entry
    pub fn with_user_agent(mut self, agent: String) -> Self {
        self.user_agent = Some(agent);
        self
    }
    
    /// Add error message for failed activities
    pub fn with_error(mut self, error: String) -> Self {
        self.error_message = Some(error);
        self.success = false;
        self
    }
    
    /// Format the activity for display
    pub fn format_display(&self) -> String {
        if self.success {
            format!("{} {}", self.action, self.resource)
        } else {
            format!("{} {} (failed)", self.action, self.resource)
        }
    }
    
    /// Get a human-readable time ago string
    pub fn time_ago(&self) -> String {
        let now = Utc::now();
        let duration = now - self.timestamp;
        
        if duration.num_seconds() < 60 {
            "just now".to_string()
        } else if duration.num_minutes() < 60 {
            format!("{} minute{} ago", 
                duration.num_minutes(),
                if duration.num_minutes() == 1 { "" } else { "s" })
        } else if duration.num_hours() < 24 {
            format!("{} hour{} ago",
                duration.num_hours(),
                if duration.num_hours() == 1 { "" } else { "s" })
        } else {
            format!("{} day{} ago",
                duration.num_days(),
                if duration.num_days() == 1 { "" } else { "s" })
        }
    }
}

/// Activity logger that maintains a rolling log of activities
pub struct ActivityLogger {
    entries: Arc<RwLock<VecDeque<ActivityEntry>>>,
    max_entries: usize,
}

impl ActivityLogger {
    /// Create a new activity logger with a maximum number of entries
    pub fn new(max_entries: usize) -> Self {
        ActivityLogger {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_entries))),
            max_entries,
        }
    }
    
    /// Log a new activity
    pub fn log(&self, entry: ActivityEntry) {
        if let Ok(mut entries) = self.entries.write() {
            // Add the new entry
            entries.push_front(entry);
            
            // Remove old entries if we exceed the limit
            while entries.len() > self.max_entries {
                entries.pop_back();
            }
        }
    }
    
    /// Log a simple activity
    pub fn log_simple(
        &self,
        user: String,
        action: String,
        resource: String,
        success: bool,
    ) {
        let entry = ActivityEntry::new(
            user,
            None,
            ActivityType::ApiRequest,
            action,
            resource,
            success,
        );
        self.log(entry);
    }
    
    /// Log a login activity
    pub fn log_login(&self, username: String, user_id: String, ip: Option<String>, success: bool) {
        let mut entry = ActivityEntry::new(
            username.clone(),
            Some(user_id),
            ActivityType::Login,
            if success { "logged in".to_string() } else { "failed login".to_string() },
            "session".to_string(),
            success,
        );
        
        if let Some(ip_addr) = ip {
            entry = entry.with_ip(ip_addr);
        }
        
        self.log(entry);
    }
    
    /// Log a zone operation
    pub fn log_zone_operation(
        &self,
        user: String,
        user_id: Option<String>,
        operation: &str,
        zone: String,
        success: bool,
    ) {
        let activity_type = match operation {
            "create" => ActivityType::ZoneCreated,
            "modify" | "update" => ActivityType::ZoneModified,
            "delete" => ActivityType::ZoneDeleted,
            _ => ActivityType::ApiRequest,
        };
        
        let entry = ActivityEntry::new(
            user,
            user_id,
            activity_type,
            format!("{} zone", operation),
            zone,
            success,
        );
        
        self.log(entry);
    }
    
    /// Get recent activities
    pub fn get_recent(&self, count: usize) -> Vec<ActivityEntry> {
        if let Ok(entries) = self.entries.read() {
            entries.iter().take(count).cloned().collect()
        } else {
            Vec::new()
        }
    }
    
    /// Get all activities
    pub fn get_all(&self) -> Vec<ActivityEntry> {
        if let Ok(entries) = self.entries.read() {
            entries.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }
    
    /// Get activities filtered by user
    pub fn get_by_user(&self, user_id: &str) -> Vec<ActivityEntry> {
        if let Ok(entries) = self.entries.read() {
            entries
                .iter()
                .filter(|e| e.user_id.as_deref() == Some(user_id))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Get activities filtered by type
    pub fn get_by_type(&self, activity_type: ActivityType) -> Vec<ActivityEntry> {
        if let Ok(entries) = self.entries.read() {
            entries
                .iter()
                .filter(|e| std::mem::discriminant(&e.activity_type) == std::mem::discriminant(&activity_type))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Get activity statistics
    pub fn get_stats(&self) -> ActivityStats {
        if let Ok(entries) = self.entries.read() {
            let total = entries.len();
            let successful = entries.iter().filter(|e| e.success).count();
            let failed = total - successful;
            
            let mut by_type = std::collections::HashMap::new();
            for entry in entries.iter() {
                let type_name = format!("{:?}", entry.activity_type);
                *by_type.entry(type_name).or_insert(0) += 1;
            }
            
            ActivityStats {
                total_activities: total,
                successful_activities: successful,
                failed_activities: failed,
                activities_by_type: by_type,
            }
        } else {
            ActivityStats::default()
        }
    }
    
    /// Clear all activities
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }
}

/// Activity statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActivityStats {
    pub total_activities: usize,
    pub successful_activities: usize,
    pub failed_activities: usize,
    pub activities_by_type: std::collections::HashMap<String, usize>,
}

impl Default for ActivityLogger {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_activity_logger() {
        let logger = ActivityLogger::new(5);
        
        // Log some activities
        for i in 0..10 {
            logger.log_simple(
                format!("user{}", i),
                "test action".to_string(),
                format!("resource{}", i),
                i % 2 == 0,
            );
        }
        
        // Check that only 5 most recent are kept
        let recent = logger.get_recent(10);
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0].user, "user9");
        
        // Test stats
        let stats = logger.get_stats();
        assert_eq!(stats.total_activities, 5);
    }
    
    #[test]
    fn test_activity_entry_time_ago() {
        let entry = ActivityEntry::new(
            "test".to_string(),
            None,
            ActivityType::Login,
            "login".to_string(),
            "session".to_string(),
            true,
        );
        
        assert_eq!(entry.time_ago(), "just now");
    }
}