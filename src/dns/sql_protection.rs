//! SQL Injection Protection Framework
//!
//! Provides comprehensive protection against SQL injection attacks through:
//! - Input validation and sanitization
//! - Safe query construction with parameter binding
//! - Monitoring and logging of suspicious queries
//! - Automatic escaping and type validation

use std::fmt;
use serde::{Deserialize, Serialize};
use regex::Regex;
use log::{warn, error, debug};

/// SQL injection protection error types
#[derive(Debug, Clone)]
pub enum SqlProtectionError {
    /// Input contains potentially dangerous SQL keywords
    DangerousKeywords(String),
    /// Input contains suspicious characters
    SuspiciousCharacters(String),
    /// Input exceeds maximum length
    InputTooLong(usize),
    /// Invalid parameter type
    InvalidType(String),
    /// Query structure validation failed
    InvalidQuery(String),
}

impl fmt::Display for SqlProtectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SqlProtectionError::DangerousKeywords(input) => {
                write!(f, "Input contains dangerous SQL keywords: {}", input)
            }
            SqlProtectionError::SuspiciousCharacters(input) => {
                write!(f, "Input contains suspicious characters: {}", input)
            }
            SqlProtectionError::InputTooLong(len) => {
                write!(f, "Input too long: {} characters", len)
            }
            SqlProtectionError::InvalidType(typ) => {
                write!(f, "Invalid parameter type: {}", typ)
            }
            SqlProtectionError::InvalidQuery(query) => {
                write!(f, "Invalid query structure: {}", query)
            }
        }
    }
}

impl std::error::Error for SqlProtectionError {}

/// Configuration for SQL protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlProtectionConfig {
    /// Maximum allowed length for string inputs
    pub max_input_length: usize,
    /// Enable strict keyword filtering
    pub strict_filtering: bool,
    /// Log suspicious queries
    pub log_suspicious: bool,
    /// Block queries with suspicious patterns
    pub block_suspicious: bool,
    /// Allowed SQL keywords for whitelisting
    pub allowed_keywords: Vec<String>,
}

impl Default for SqlProtectionConfig {
    fn default() -> Self {
        Self {
            max_input_length: 1000,
            strict_filtering: true,
            log_suspicious: true,
            block_suspicious: true,
            allowed_keywords: vec![
                "SELECT".to_string(),
                "INSERT".to_string(),
                "UPDATE".to_string(),
                "DELETE".to_string(),
                "WHERE".to_string(),
                "ORDER BY".to_string(),
                "GROUP BY".to_string(),
                "HAVING".to_string(),
                "LIMIT".to_string(),
            ],
        }
    }
}

/// Safe parameter types for SQL queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafeParameter {
    Text(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Null,
}

impl SafeParameter {
    /// Validate and sanitize a text parameter
    pub fn sanitized_text(input: &str, config: &SqlProtectionConfig) -> Result<Self, SqlProtectionError> {
        // Check length
        if input.len() > config.max_input_length {
            return Err(SqlProtectionError::InputTooLong(input.len()));
        }

        // Validate against dangerous patterns
        let sanitized = SqlInputValidator::sanitize_text(input, config)?;
        Ok(SafeParameter::Text(sanitized))
    }

    /// Create a safe integer parameter
    pub fn integer(value: i64) -> Self {
        SafeParameter::Integer(value)
    }

    /// Create a safe float parameter
    pub fn float(value: f64) -> Self {
        SafeParameter::Float(value)
    }

    /// Create a safe boolean parameter
    pub fn boolean(value: bool) -> Self {
        SafeParameter::Boolean(value)
    }
}

/// SQL input validator with injection protection
pub struct SqlInputValidator {
    config: SqlProtectionConfig,
    dangerous_patterns: Vec<Regex>,
    suspicious_chars: Regex,
}

impl SqlInputValidator {
    /// Create a new validator with the given configuration
    pub fn new(config: SqlProtectionConfig) -> Self {
        let dangerous_patterns = vec![
            // SQL injection patterns
            Regex::new(r"(?i)\bUNION\s+SELECT\b").unwrap(),
            Regex::new(r"(?i)\bDROP\s+(?:TABLE|DATABASE)\b").unwrap(),
            Regex::new(r"(?i)\bALTER\s+TABLE\b").unwrap(),
            Regex::new(r"(?i)\b(?:EXEC|EXECUTE)\b").unwrap(),
            Regex::new(r"(?i)\bSCRIPT\b").unwrap(),
            Regex::new(r"(?i)\bxp_\w+").unwrap(),
            Regex::new(r"(?i)\bsp_\w+").unwrap(),
            // Common injection techniques
            Regex::new(r"'(?:\s*or\s*|\s*and\s*).+?(?:'|$)").unwrap(),
            Regex::new(r"(?i)\b(?:1\s*=\s*1|0\s*=\s*0)\b").unwrap(),
            Regex::new(r"(?i)(?:--|#|/\*)").unwrap(),
            // Hex/binary injection attempts
            Regex::new(r"\b0x[0-9a-f]+\b").unwrap(),
            // WAITFOR/DELAY attacks
            Regex::new(r"(?i)\b(?:WAITFOR\s+DELAY|SLEEP\s*\()").unwrap(),
        ];

        let suspicious_chars = Regex::new(r"[;<>'\x22\\]").unwrap();

        Self {
            config,
            dangerous_patterns,
            suspicious_chars,
        }
    }

    /// Validate and sanitize text input
    pub fn sanitize_text(input: &str, config: &SqlProtectionConfig) -> Result<String, SqlProtectionError> {
        // Check for dangerous patterns
        for pattern in &[
            r"(?i)\bUNION\s+SELECT\b",
            r"(?i)\bDROP\s+(?:TABLE|DATABASE)\b",
            r"(?i)\bALTER\s+TABLE\b",
            r"(?i)\b(?:EXEC|EXECUTE)\b",
            r"(?i)\bxp_\w+",
            r"(?i)\bsp_\w+",
            r"'(?:\s*or\s*|\s*and\s*).+?(?:'|$)",
            r"(?i)\b(?:1\s*=\s*1|0\s*=\s*0)\b",
            r"(?i)(?:--|#|/\*)",
            r"\b0x[0-9a-f]+\b",
            r"(?i)\b(?:WAITFOR\s+DELAY|SLEEP\s*\()",
        ] {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(input) {
                    if config.log_suspicious {
                        warn!("SQL injection attempt detected in input: {}", input);
                    }
                    if config.block_suspicious {
                        return Err(SqlProtectionError::DangerousKeywords(input.to_string()));
                    }
                }
            }
        }

        // Check for suspicious characters
        if let Ok(suspicious_regex) = Regex::new(r"[;<>'\x22\\]") {
            if suspicious_regex.is_match(input) && config.strict_filtering {
                if config.log_suspicious {
                    warn!("Suspicious characters detected in input: {}", input);
                }
                if config.block_suspicious {
                    return Err(SqlProtectionError::SuspiciousCharacters(input.to_string()));
                }
            }
        }

        // Sanitize by removing/escaping dangerous characters
        let sanitized = input
            .replace("'", "''")  // Escape single quotes
            .replace("\\", "\\\\") // Escape backslashes
            .trim()
            .to_string();

        debug!("Input sanitized: '{}' -> '{}'", input, sanitized);
        Ok(sanitized)
    }

    /// Validate a complete query structure
    pub fn validate_query(&self, query: &str) -> Result<(), SqlProtectionError> {
        if query.len() > self.config.max_input_length * 10 {
            return Err(SqlProtectionError::InputTooLong(query.len()));
        }

        // Check for dangerous patterns in the query itself
        for pattern in &self.dangerous_patterns {
            if pattern.is_match(query) {
                if self.config.log_suspicious {
                    warn!("Dangerous pattern detected in query: {}", query);
                }
                if self.config.block_suspicious {
                    return Err(SqlProtectionError::InvalidQuery(query.to_string()));
                }
            }
        }

        Ok(())
    }

    /// Log a query execution for monitoring
    pub fn log_query_execution(&self, query: &str, params: &[SafeParameter]) {
        if self.config.log_suspicious {
            debug!("Executing SQL query: {} with {} parameters", query, params.len());
        }
    }
}

/// Safe query builder with automatic parameter binding
pub struct SafeQueryBuilder {
    validator: SqlInputValidator,
    query_parts: Vec<String>,
    parameters: Vec<SafeParameter>,
}

impl SafeQueryBuilder {
    /// Create a new safe query builder
    pub fn new(config: SqlProtectionConfig) -> Self {
        Self {
            validator: SqlInputValidator::new(config),
            query_parts: Vec::new(),
            parameters: Vec::new(),
        }
    }

    /// Add a query part with parameter binding
    pub fn add_part(&mut self, query_part: &str) -> &mut Self {
        self.validator.validate_query(query_part).unwrap_or_else(|e| {
            error!("Query validation failed: {}", e);
        });
        self.query_parts.push(query_part.to_string());
        self
    }

    /// Add a safe parameter
    pub fn add_parameter(&mut self, param: SafeParameter) -> &mut Self {
        self.parameters.push(param);
        self
    }

    /// Add a text parameter with sanitization
    pub fn add_text_param(&mut self, text: &str) -> Result<&mut Self, SqlProtectionError> {
        let safe_param = SafeParameter::sanitized_text(text, &self.validator.config)?;
        self.parameters.push(safe_param);
        Ok(self)
    }

    /// Build the final query
    pub fn build(&self) -> (String, Vec<SafeParameter>) {
        let query = self.query_parts.join(" ");
        self.validator.log_query_execution(&query, &self.parameters);
        (query, self.parameters.clone())
    }
}

/// Statistics for SQL protection monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlProtectionStats {
    /// Total queries processed
    pub queries_processed: u64,
    /// Queries blocked due to injection attempts
    pub queries_blocked: u64,
    /// Suspicious patterns detected
    pub suspicious_patterns: u64,
    /// Parameters sanitized
    pub parameters_sanitized: u64,
}

impl Default for SqlProtectionStats {
    fn default() -> Self {
        Self {
            queries_processed: 0,
            queries_blocked: 0,
            suspicious_patterns: 0,
            parameters_sanitized: 0,
        }
    }
}

/// SQL Protection Manager for coordinating protection mechanisms
pub struct SqlProtectionManager {
    validator: SqlInputValidator,
    stats: SqlProtectionStats,
}

impl SqlProtectionManager {
    /// Create a new protection manager
    pub fn new(config: SqlProtectionConfig) -> Self {
        Self {
            validator: SqlInputValidator::new(config),
            stats: SqlProtectionStats::default(),
        }
    }

    /// Process and validate a query with parameters
    pub fn validate_query_with_params(
        &mut self,
        query: &str,
        params: &[&str],
    ) -> Result<(String, Vec<SafeParameter>), SqlProtectionError> {
        self.stats.queries_processed += 1;

        // Validate the query structure
        self.validator.validate_query(query)?;

        // Sanitize parameters
        let mut safe_params = Vec::new();
        for param in params {
            match SafeParameter::sanitized_text(param, &self.validator.config) {
                Ok(safe_param) => {
                    self.stats.parameters_sanitized += 1;
                    safe_params.push(safe_param);
                }
                Err(e) => {
                    self.stats.queries_blocked += 1;
                    self.stats.suspicious_patterns += 1;
                    return Err(e);
                }
            }
        }

        Ok((query.to_string(), safe_params))
    }

    /// Get protection statistics
    pub fn get_stats(&self) -> &SqlProtectionStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = SqlProtectionStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_keyword_detection() {
        let config = SqlProtectionConfig::default();
        let result = SqlInputValidator::sanitize_text("'; DROP TABLE users; --", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_union_injection_detection() {
        let config = SqlProtectionConfig::default();
        let result = SqlInputValidator::sanitize_text("admin' UNION SELECT * FROM passwords", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_normal_input_passes() {
        let config = SqlProtectionConfig::default();
        let result = SqlInputValidator::sanitize_text("normal_username", &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "normal_username");
    }

    #[test]
    fn test_single_quote_escaping() {
        let mut config = SqlProtectionConfig::default();
        config.block_suspicious = false; // Allow processing
        let result = SqlInputValidator::sanitize_text("O'Reilly", &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "O''Reilly");
    }

    #[test]
    fn test_query_builder() {
        let config = SqlProtectionConfig::default();
        let mut builder = SafeQueryBuilder::new(config);
        
        builder
            .add_part("SELECT * FROM users WHERE name = ?")
            .add_text_param("john_doe")
            .unwrap();

        let (query, params) = builder.build();
        assert_eq!(query, "SELECT * FROM users WHERE name = ?");
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn test_protection_manager() {
        let config = SqlProtectionConfig::default();
        let mut manager = SqlProtectionManager::new(config);

        let result = manager.validate_query_with_params(
            "SELECT * FROM users WHERE id = ?",
            &["123"],
        );

        assert!(result.is_ok());
        assert_eq!(manager.get_stats().queries_processed, 1);
        assert_eq!(manager.get_stats().queries_blocked, 0);
    }

    #[test]
    fn test_injection_blocking() {
        let config = SqlProtectionConfig::default();
        let mut manager = SqlProtectionManager::new(config);

        let result = manager.validate_query_with_params(
            "SELECT * FROM users WHERE id = ?",
            &["1'; DROP TABLE users; --"],
        );

        assert!(result.is_err());
        assert_eq!(manager.get_stats().queries_processed, 1);
        assert_eq!(manager.get_stats().queries_blocked, 1);
    }
}