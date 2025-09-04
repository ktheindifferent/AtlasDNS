/// Input validation module for web endpoints
/// 
/// Provides comprehensive input validation and sanitization for all web handlers
/// to prevent injection attacks, ensure data integrity, and enforce business rules.

use regex::Regex;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use lazy_static::lazy_static;

lazy_static! {
    /// Valid DNS label pattern (RFC 1035)
    static ref DNS_LABEL_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$").expect("Failed to compile DNS label regex");
    
    /// Valid email pattern (basic RFC 5322)  
    static ref EMAIL_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").expect("Failed to compile email regex");
    
    /// Valid username pattern
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_\-]{3,32}$").expect("Failed to compile username regex");
    
    /// Valid hexadecimal token pattern
    static ref TOKEN_REGEX: Regex = Regex::new(r"^[a-f0-9]{32,128}$").expect("Failed to compile token regex");
    
    /// Reserved domain names
    static ref RESERVED_DOMAINS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("localhost");
        set.insert("localdomain");
        set.insert("local");
        set.insert("invalid");
        set.insert("test");
        set.insert("example");
        set.insert("example.com");
        set.insert("example.net");
        set.insert("example.org");
        set
    };
}

/// DNS validation constants
const MAX_DNS_LABEL_LENGTH: usize = 63;
const MAX_DNS_NAME_LENGTH: usize = 253;
const MIN_TTL: u32 = 0;
const MAX_TTL: u32 = 2147483647; // RFC 2181 maximum TTL
const DEFAULT_TTL: u32 = 3600;

/// User input validation constants
const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_PASSWORD_LENGTH: usize = 128;
const MAX_USERNAME_LENGTH: usize = 32;
const MIN_USERNAME_LENGTH: usize = 3;
const MAX_EMAIL_LENGTH: usize = 254;

/// Request size limits
const MAX_JSON_SIZE: usize = 1_048_576; // 1MB
const MAX_BULK_OPERATIONS: usize = 100;
const MAX_RECORDS_PER_ZONE: usize = 10000;

#[derive(Debug)]
pub enum ValidationError {
    InvalidDnsName(String),
    InvalidDnsLabel(String),
    InvalidRecordType(String),
    InvalidIpAddress(String),
    InvalidEmail(String),
    InvalidUsername(String),
    InvalidPassword(String),
    InvalidTtl(u32),
    InvalidToken(String),
    InvalidJson(String),
    RequestTooLarge(usize),
    TooManyOperations(usize),
    ReservedDomain(String),
    InvalidCharacters(String),
    LengthViolation { field: String, min: usize, max: usize, actual: usize },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ValidationError::InvalidDnsName(name) => write!(f, "Invalid DNS name: {}", name),
            ValidationError::InvalidDnsLabel(label) => write!(f, "Invalid DNS label: {}", label),
            ValidationError::InvalidRecordType(rtype) => write!(f, "Invalid record type: {}", rtype),
            ValidationError::InvalidIpAddress(ip) => write!(f, "Invalid IP address: {}", ip),
            ValidationError::InvalidEmail(email) => write!(f, "Invalid email address: {}", email),
            ValidationError::InvalidUsername(user) => write!(f, "Invalid username: {}", user),
            ValidationError::InvalidPassword(msg) => write!(f, "Invalid password: {}", msg),
            ValidationError::InvalidTtl(ttl) => write!(f, "Invalid TTL value: {}", ttl),
            ValidationError::InvalidToken(msg) => write!(f, "Invalid token: {}", msg),
            ValidationError::InvalidJson(msg) => write!(f, "Invalid JSON: {}", msg),
            ValidationError::RequestTooLarge(size) => write!(f, "Request too large: {} bytes", size),
            ValidationError::TooManyOperations(count) => write!(f, "Too many operations: {}", count),
            ValidationError::ReservedDomain(domain) => write!(f, "Reserved domain name: {}", domain),
            ValidationError::InvalidCharacters(field) => write!(f, "Invalid characters in: {}", field),
            ValidationError::LengthViolation { field, min, max, actual } => 
                write!(f, "Field '{}' length {} not in range {}-{}", field, actual, min, max),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate a DNS domain name according to RFC 1035
pub fn validate_dns_name(name: &str) -> Result<String, ValidationError> {
    // Remove trailing dot if present
    let name = if name.ends_with('.') {
        &name[..name.len() - 1]
    } else {
        name
    };
    
    // Check total length
    if name.is_empty() || name.len() > MAX_DNS_NAME_LENGTH {
        return Err(ValidationError::InvalidDnsName(format!(
            "DNS name must be 1-{} characters", MAX_DNS_NAME_LENGTH
        )));
    }
    
    // Check for reserved domains
    if RESERVED_DOMAINS.contains(name) {
        return Err(ValidationError::ReservedDomain(name.to_string()));
    }
    
    // Split into labels and validate each
    let labels: Vec<&str> = name.split('.').collect();
    if labels.is_empty() || labels.len() > 127 {
        return Err(ValidationError::InvalidDnsName(
            "DNS name must have 1-127 labels".to_string()
        ));
    }
    
    for label in &labels {
        validate_dns_label(label)?;
    }
    
    // Normalize to lowercase
    Ok(name.to_lowercase())
}

/// Validate a single DNS label
pub fn validate_dns_label(label: &str) -> Result<(), ValidationError> {
    if label.is_empty() || label.len() > MAX_DNS_LABEL_LENGTH {
        return Err(ValidationError::InvalidDnsLabel(format!(
            "Label must be 1-{} characters", MAX_DNS_LABEL_LENGTH
        )));
    }
    
    if !DNS_LABEL_REGEX.is_match(label) {
        return Err(ValidationError::InvalidDnsLabel(
            "Label contains invalid characters or format".to_string()
        ));
    }
    
    Ok(())
}

/// Validate DNS record type
pub fn validate_record_type(record_type: &str) -> Result<String, ValidationError> {
    let valid_types = vec![
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", 
        "SOA", "SRV", "CAA", "DNSKEY", "DS", "NSEC", "NSEC3",
        "RRSIG", "SPF", "TLSA"
    ];
    
    let record_type = record_type.to_uppercase();
    if !valid_types.contains(&record_type.as_str()) {
        return Err(ValidationError::InvalidRecordType(record_type));
    }
    
    Ok(record_type)
}

/// Validate IP address (v4 or v6)
pub fn validate_ip_address(ip_str: &str) -> Result<IpAddr, ValidationError> {
    ip_str.parse::<IpAddr>()
        .map_err(|_| ValidationError::InvalidIpAddress(ip_str.to_string()))
}

/// Validate IPv4 address
pub fn validate_ipv4_address(ip_str: &str) -> Result<Ipv4Addr, ValidationError> {
    ip_str.parse::<Ipv4Addr>()
        .map_err(|_| ValidationError::InvalidIpAddress(format!("Invalid IPv4: {}", ip_str)))
}

/// Validate IPv6 address
pub fn validate_ipv6_address(ip_str: &str) -> Result<Ipv6Addr, ValidationError> {
    ip_str.parse::<Ipv6Addr>()
        .map_err(|_| ValidationError::InvalidIpAddress(format!("Invalid IPv6: {}", ip_str)))
}

/// Validate TTL value
pub fn validate_ttl(ttl: u32) -> Result<u32, ValidationError> {
    if ttl > MAX_TTL {
        return Err(ValidationError::InvalidTtl(ttl));
    }
    Ok(ttl)
}

/// Validate email address
pub fn validate_email(email: &str) -> Result<String, ValidationError> {
    if email.len() > MAX_EMAIL_LENGTH {
        return Err(ValidationError::InvalidEmail(
            format!("Email exceeds maximum length of {}", MAX_EMAIL_LENGTH)
        ));
    }
    
    if !EMAIL_REGEX.is_match(email) {
        return Err(ValidationError::InvalidEmail(
            "Invalid email format".to_string()
        ));
    }
    
    // Normalize to lowercase
    Ok(email.to_lowercase())
}

/// Validate username
pub fn validate_username(username: &str) -> Result<String, ValidationError> {
    if username.len() < MIN_USERNAME_LENGTH || username.len() > MAX_USERNAME_LENGTH {
        return Err(ValidationError::LengthViolation {
            field: "username".to_string(),
            min: MIN_USERNAME_LENGTH,
            max: MAX_USERNAME_LENGTH,
            actual: username.len(),
        });
    }
    
    if !USERNAME_REGEX.is_match(username) {
        return Err(ValidationError::InvalidUsername(
            "Username can only contain alphanumeric, underscore and hyphen".to_string()
        ));
    }
    
    // Prevent reserved usernames
    let reserved = vec!["admin", "root", "administrator", "system", "guest"];
    if reserved.contains(&username.to_lowercase().as_str()) {
        return Err(ValidationError::InvalidUsername(
            "Username is reserved".to_string()
        ));
    }
    
    Ok(username.to_string())
}

/// Validate password strength
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(ValidationError::InvalidPassword(
            format!("Password must be at least {} characters", MIN_PASSWORD_LENGTH)
        ));
    }
    
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ValidationError::InvalidPassword(
            format!("Password exceeds maximum length of {}", MAX_PASSWORD_LENGTH)
        ));
    }
    
    // Check for complexity requirements
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    let complexity_score = vec![has_uppercase, has_lowercase, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    
    if complexity_score < 3 {
        return Err(ValidationError::InvalidPassword(
            "Password must contain at least 3 of: uppercase, lowercase, digit, special character".to_string()
        ));
    }
    
    // Check for common weak passwords
    let weak_passwords = vec!["password", "12345678", "qwerty", "admin"];
    if weak_passwords.contains(&password.to_lowercase().as_str()) {
        return Err(ValidationError::InvalidPassword(
            "Password is too common".to_string()
        ));
    }
    
    Ok(())
}

/// Validate session token
pub fn validate_token(token: &str) -> Result<String, ValidationError> {
    if token.len() < 32 || token.len() > 128 {
        return Err(ValidationError::InvalidToken(
            "Token must be 32-128 characters".to_string()
        ));
    }
    
    if !TOKEN_REGEX.is_match(token) {
        return Err(ValidationError::InvalidToken(
            "Token contains invalid characters".to_string()
        ));
    }
    
    Ok(token.to_string())
}

/// Validate JSON size
pub fn validate_json_size(size: usize) -> Result<(), ValidationError> {
    if size > MAX_JSON_SIZE {
        return Err(ValidationError::RequestTooLarge(size));
    }
    Ok(())
}

/// Validate bulk operation count
pub fn validate_bulk_count(count: usize) -> Result<(), ValidationError> {
    if count > MAX_BULK_OPERATIONS {
        return Err(ValidationError::TooManyOperations(count));
    }
    Ok(())
}

/// Sanitize string for safe output (prevent XSS)
pub fn sanitize_html(input: &str) -> String {
    input
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")
        .replace("/", "&#x2F;")
}

/// Sanitize string for logging (prevent log injection)
pub fn sanitize_log(input: &str) -> String {
    input
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .collect()
}

/// Validate MX priority
pub fn validate_mx_priority(priority: u16) -> Result<u16, ValidationError> {
    // MX priority is a 16-bit value, all values are technically valid
    // but we can add business logic constraints
    if priority > 65535 {
        return Err(ValidationError::InvalidRecordType(
            format!("MX priority {} exceeds maximum", priority)
        ));
    }
    Ok(priority)
}

/// Validate TXT record data
pub fn validate_txt_record(data: &str) -> Result<String, ValidationError> {
    // TXT records can be up to 255 characters per string
    // Multiple strings can be concatenated
    if data.len() > 4096 {
        return Err(ValidationError::InvalidRecordType(
            "TXT record data exceeds maximum length".to_string()
        ));
    }
    
    // Prevent null bytes and control characters
    if data.chars().any(|c| c == '\0' || (c.is_control() && c != '\t' && c != '\n')) {
        return Err(ValidationError::InvalidCharacters(
            "TXT record contains invalid control characters".to_string()
        ));
    }
    
    Ok(data.to_string())
}

/// Validate CNAME target
pub fn validate_cname_target(target: &str) -> Result<String, ValidationError> {
    // CNAME target must be a valid domain name
    validate_dns_name(target)
}

/// Validate SRV record components
pub fn validate_srv_record(priority: u16, weight: u16, port: u16, target: &str) 
    -> Result<(u16, u16, u16, String), ValidationError> {
    
    if port == 0 {
        return Err(ValidationError::InvalidRecordType(
            "SRV port cannot be 0".to_string()
        ));
    }
    
    let validated_target = validate_dns_name(target)?;
    Ok((priority, weight, port, validated_target))
}

/// Validate CAA record
pub fn validate_caa_record(flags: u8, tag: &str, value: &str) 
    -> Result<(u8, String, String), ValidationError> {
    
    let valid_tags = vec!["issue", "issuewild", "iodef"];
    if !valid_tags.contains(&tag) {
        return Err(ValidationError::InvalidRecordType(
            format!("Invalid CAA tag: {}", tag)
        ));
    }
    
    // Validate value based on tag
    match tag {
        "issue" | "issuewild" => {
            // Should be a domain name or ";"
            if value != ";" && validate_dns_name(value).is_err() {
                return Err(ValidationError::InvalidRecordType(
                    "CAA issue value must be a domain or semicolon".to_string()
                ));
            }
        }
        "iodef" => {
            // Should be a URL
            if !value.starts_with("mailto:") && !value.starts_with("http://") && !value.starts_with("https://") {
                return Err(ValidationError::InvalidRecordType(
                    "CAA iodef must be a URL".to_string()
                ));
            }
        }
        _ => {}
    }
    
    Ok((flags, tag.to_string(), value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_dns_name() {
        // Valid cases
        assert!(validate_dns_name("example.com").is_ok());
        assert!(validate_dns_name("sub.example.com").is_ok());
        assert!(validate_dns_name("test-123.example.co.uk").is_ok());
        assert!(validate_dns_name("example.com.").is_ok()); // trailing dot
        
        // Invalid cases
        assert!(validate_dns_name("").is_err());
        assert!(validate_dns_name("-example.com").is_err());
        assert!(validate_dns_name("example..com").is_err());
        assert!(validate_dns_name("localhost").is_err()); // reserved
        assert!(validate_dns_name(&"a".repeat(64)).is_err()); // label too long
        assert!(validate_dns_name(&format!("{}.com", "a".repeat(64))).is_err());
    }
    
    #[test]
    fn test_validate_email() {
        // Valid cases
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user+tag@example.co.uk").is_ok());
        assert!(validate_email("user.name@sub.example.com").is_ok());
        
        // Invalid cases
        assert!(validate_email("").is_err());
        assert!(validate_email("user").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@.com").is_err());
    }
    
    #[test]
    fn test_validate_password() {
        // Valid cases
        assert!(validate_password("SecureP@ss123").is_ok());
        assert!(validate_password("C0mpl3x!Pass").is_ok());
        
        // Invalid cases
        assert!(validate_password("short").is_err()); // too short
        assert!(validate_password("12345678").is_err()); // weak
        assert!(validate_password("password").is_err()); // common
        assert!(validate_password("alllowercase").is_err()); // no complexity
    }
    
    #[test]
    fn test_validate_ip_address() {
        // Valid IPv4
        assert!(validate_ipv4_address("192.168.1.1").is_ok());
        assert!(validate_ipv4_address("8.8.8.8").is_ok());
        
        // Valid IPv6
        assert!(validate_ipv6_address("::1").is_ok());
        assert!(validate_ipv6_address("2001:db8::1").is_ok());
        
        // Invalid
        assert!(validate_ipv4_address("256.256.256.256").is_err());
        assert!(validate_ipv4_address("192.168.1").is_err());
        assert!(validate_ipv6_address("gggg::1").is_err());
    }
    
    #[test]
    fn test_sanitize_html() {
        assert_eq!(sanitize_html("<script>alert('xss')</script>"), 
                   "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;");
        assert_eq!(sanitize_html("normal text"), "normal text");
    }
    
    #[test]
    fn test_validate_ttl() {
        assert!(validate_ttl(3600).is_ok());
        assert!(validate_ttl(0).is_ok());
        assert!(validate_ttl(MAX_TTL).is_ok());
        assert!(validate_ttl(MAX_TTL + 1).is_err());
    }
}