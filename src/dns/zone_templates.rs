//! Zone Templates
//!
//! Predefined DNS zone templates for rapid deployment and consistent configuration
//! across multiple zones with customizable variables and inheritance support.
//!
//! # Features
//!
//! * **Predefined Templates** - Common zone configurations ready to use
//! * **Variable Substitution** - Dynamic values with template variables
//! * **Template Inheritance** - Build on existing templates
//! * **Validation Rules** - Ensure zones meet requirements
//! * **Industry Standards** - Best practices for different use cases
//! * **Custom Templates** - Create organization-specific templates
//! * **Version Control** - Track template changes over time

use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use regex::Regex;

/// Zone template configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTemplateConfig {
    /// Enable templates
    pub enabled: bool,
    /// Template directory
    pub template_dir: String,
    /// Allow custom templates
    pub allow_custom: bool,
    /// Validate on apply
    pub validate_on_apply: bool,
    /// Default TTL
    pub default_ttl: u32,
    /// Maximum variables
    pub max_variables: usize,
    /// Cache templates
    pub cache_templates: bool,
}

impl Default for ZoneTemplateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            template_dir: "/etc/atlas-dns/templates".to_string(),
            allow_custom: true,
            validate_on_apply: true,
            default_ttl: 3600,
            max_variables: 100,
            cache_templates: true,
        }
    }
}

/// Zone template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTemplate {
    /// Template ID
    pub id: String,
    /// Template name
    pub name: String,
    /// Description
    pub description: String,
    /// Category
    pub category: TemplateCategory,
    /// Parent template (for inheritance)
    pub parent: Option<String>,
    /// Variables
    pub variables: Vec<TemplateVariable>,
    /// Records
    pub records: Vec<TemplateRecord>,
    /// Validation rules
    pub validation_rules: Vec<ValidationRule>,
    /// Metadata
    pub metadata: TemplateMetadata,
    /// Tags
    pub tags: Vec<String>,
}

/// Template category
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TemplateCategory {
    /// Basic web hosting
    BasicWeb,
    /// E-commerce site
    Ecommerce,
    /// Email service
    Email,
    /// CDN configuration
    CDN,
    /// API service
    API,
    /// Corporate domain
    Corporate,
    /// Personal blog
    Blog,
    /// SaaS application
    SaaS,
    /// Gaming server
    Gaming,
    /// Custom template
    Custom,
}

/// Template variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariable {
    /// Variable name
    pub name: String,
    /// Description
    pub description: String,
    /// Variable type
    pub var_type: VariableType,
    /// Default value
    pub default_value: Option<String>,
    /// Required flag
    pub required: bool,
    /// Validation pattern
    pub pattern: Option<String>,
    /// Allowed values
    pub allowed_values: Option<Vec<String>>,
}

/// Variable type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableType {
    String,
    IpAddress,
    IpV4Address,
    IpV6Address,
    Domain,
    Email,
    Number,
    Boolean,
    List,
}

/// Template record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRecord {
    /// Record name (can contain variables)
    pub name: String,
    /// Record type
    pub record_type: String,
    /// TTL (can be variable)
    pub ttl: String,
    /// Record value (can contain variables)
    pub value: String,
    /// Priority (for MX, SRV)
    pub priority: Option<String>,
    /// Weight (for SRV)
    pub weight: Option<String>,
    /// Port (for SRV)
    pub port: Option<String>,
    /// Conditional
    pub conditional: Option<RecordCondition>,
}

/// Record condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordCondition {
    /// Variable to check
    pub variable: String,
    /// Operator
    pub operator: ConditionOperator,
    /// Value to compare
    pub value: String,
}

/// Condition operator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    Exists,
    NotExists,
}

/// Validation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    /// Rule name
    pub name: String,
    /// Rule type
    pub rule_type: ValidationRuleType,
    /// Parameters
    pub parameters: HashMap<String, String>,
    /// Error message
    pub error_message: String,
}

/// Validation rule type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationRuleType {
    /// Minimum number of records
    MinimumRecords,
    /// Maximum number of records
    MaximumRecords,
    /// Required record types
    RequiredRecordTypes,
    /// Unique names
    UniqueNames,
    /// Valid SPF
    ValidSPF,
    /// Valid DMARC
    ValidDMARC,
    /// Valid DKIM
    ValidDKIM,
    /// Custom regex
    CustomRegex,
}

/// Template metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMetadata {
    /// Author
    pub author: String,
    /// Version
    pub version: String,
    /// Created date
    pub created: u64,
    /// Modified date
    pub modified: u64,
    /// License
    pub license: Option<String>,
    /// Documentation URL
    pub documentation_url: Option<String>,
}

/// Template instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInstance {
    /// Instance ID
    pub id: String,
    /// Template ID
    pub template_id: String,
    /// Zone name
    pub zone_name: String,
    /// Variable values
    pub variables: HashMap<String, String>,
    /// Applied at
    pub applied_at: u64,
    /// Applied by
    pub applied_by: String,
    /// Status
    pub status: InstanceStatus,
}

/// Instance status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InstanceStatus {
    Pending,
    Applied,
    Failed,
    RolledBack,
}

/// Built-in templates
#[derive(Debug)]
pub struct BuiltInTemplates;

impl BuiltInTemplates {
    /// Basic web hosting template
    pub fn basic_web() -> ZoneTemplate {
        ZoneTemplate {
            id: "basic-web".to_string(),
            name: "Basic Web Hosting".to_string(),
            description: "Standard configuration for web hosting".to_string(),
            category: TemplateCategory::BasicWeb,
            parent: None,
            variables: vec![
                TemplateVariable {
                    name: "web_ip".to_string(),
                    description: "Web server IP address".to_string(),
                    var_type: VariableType::IpV4Address,
                    default_value: None,
                    required: true,
                    pattern: None,
                    allowed_values: None,
                },
                TemplateVariable {
                    name: "mail_server".to_string(),
                    description: "Mail server hostname".to_string(),
                    var_type: VariableType::Domain,
                    default_value: Some("mail.{{zone}}".to_string()),
                    required: false,
                    pattern: None,
                    allowed_values: None,
                },
            ],
            records: vec![
                TemplateRecord {
                    name: "@".to_string(),
                    record_type: "A".to_string(),
                    ttl: "3600".to_string(),
                    value: "{{web_ip}}".to_string(),
                    priority: None,
                    weight: None,
                    port: None,
                    conditional: None,
                },
                TemplateRecord {
                    name: "www".to_string(),
                    record_type: "CNAME".to_string(),
                    ttl: "3600".to_string(),
                    value: "@".to_string(),
                    priority: None,
                    weight: None,
                    port: None,
                    conditional: None,
                },
                TemplateRecord {
                    name: "@".to_string(),
                    record_type: "MX".to_string(),
                    ttl: "3600".to_string(),
                    value: "{{mail_server}}".to_string(),
                    priority: Some("10".to_string()),
                    weight: None,
                    port: None,
                    conditional: None,
                },
            ],
            validation_rules: vec![
                ValidationRule {
                    name: "minimum_records".to_string(),
                    rule_type: ValidationRuleType::MinimumRecords,
                    parameters: [("count".to_string(), "3".to_string())].iter().cloned().collect(),
                    error_message: "Zone must have at least 3 records".to_string(),
                },
            ],
            metadata: TemplateMetadata {
                author: "Atlas DNS Team".to_string(),
                version: "1.0.0".to_string(),
                created: Self::current_timestamp(),
                modified: Self::current_timestamp(),
                license: Some("MIT".to_string()),
                documentation_url: None,
            },
            tags: vec!["web".to_string(), "basic".to_string()],
        }
    }

    /// E-commerce template
    pub fn ecommerce() -> ZoneTemplate {
        ZoneTemplate {
            id: "ecommerce".to_string(),
            name: "E-commerce Site".to_string(),
            description: "Configuration for e-commerce websites with CDN".to_string(),
            category: TemplateCategory::Ecommerce,
            parent: Some("basic-web".to_string()),
            variables: vec![
                TemplateVariable {
                    name: "cdn_endpoint".to_string(),
                    description: "CDN endpoint URL".to_string(),
                    var_type: VariableType::Domain,
                    default_value: None,
                    required: true,
                    pattern: None,
                    allowed_values: None,
                },
                TemplateVariable {
                    name: "api_endpoint".to_string(),
                    description: "API server endpoint".to_string(),
                    var_type: VariableType::Domain,
                    default_value: None,
                    required: true,
                    pattern: None,
                    allowed_values: None,
                },
            ],
            records: vec![
                TemplateRecord {
                    name: "cdn".to_string(),
                    record_type: "CNAME".to_string(),
                    ttl: "300".to_string(),
                    value: "{{cdn_endpoint}}".to_string(),
                    priority: None,
                    weight: None,
                    port: None,
                    conditional: None,
                },
                TemplateRecord {
                    name: "api".to_string(),
                    record_type: "CNAME".to_string(),
                    ttl: "300".to_string(),
                    value: "{{api_endpoint}}".to_string(),
                    priority: None,
                    weight: None,
                    port: None,
                    conditional: None,
                },
                TemplateRecord {
                    name: "@".to_string(),
                    record_type: "TXT".to_string(),
                    ttl: "3600".to_string(),
                    value: "v=spf1 include:_spf.google.com ~all".to_string(),
                    priority: None,
                    weight: None,
                    port: None,
                    conditional: None,
                },
            ],
            validation_rules: vec![
                ValidationRule {
                    name: "required_types".to_string(),
                    rule_type: ValidationRuleType::RequiredRecordTypes,
                    parameters: [("types".to_string(), "A,CNAME,MX,TXT".to_string())].iter().cloned().collect(),
                    error_message: "E-commerce zone must have A, CNAME, MX, and TXT records".to_string(),
                },
            ],
            metadata: TemplateMetadata {
                author: "Atlas DNS Team".to_string(),
                version: "1.0.0".to_string(),
                created: Self::current_timestamp(),
                modified: Self::current_timestamp(),
                license: Some("MIT".to_string()),
                documentation_url: None,
            },
            tags: vec!["ecommerce".to_string(), "cdn".to_string(), "api".to_string()],
        }
    }

    /// Email service template
    pub fn email_service() -> ZoneTemplate {
        ZoneTemplate {
            id: "email-service".to_string(),
            name: "Email Service".to_string(),
            description: "Complete email service configuration with SPF, DKIM, DMARC".to_string(),
            category: TemplateCategory::Email,
            parent: None,
            variables: vec![
                TemplateVariable {
                    name: "mail_servers".to_string(),
                    description: "Mail server IPs (comma-separated)".to_string(),
                    var_type: VariableType::List,
                    default_value: None,
                    required: true,
                    pattern: None,
                    allowed_values: None,
                },
                TemplateVariable {
                    name: "dkim_selector".to_string(),
                    description: "DKIM selector".to_string(),
                    var_type: VariableType::String,
                    default_value: Some("default".to_string()),
                    required: true,
                    pattern: Some("^[a-z0-9]+$".to_string()),
                    allowed_values: None,
                },
                TemplateVariable {
                    name: "dkim_key".to_string(),
                    description: "DKIM public key".to_string(),
                    var_type: VariableType::String,
                    default_value: None,
                    required: true,
                    pattern: None,
                    allowed_values: None,
                },
            ],
            records: vec![
                TemplateRecord {
                    name: "@".to_string(),
                    record_type: "MX".to_string(),
                    ttl: "3600".to_string(),
                    value: "mail.{{zone}}".to_string(),
                    priority: Some("10".to_string()),
                    weight: None,
                    port: None,
                    conditional: None,
                },
                TemplateRecord {
                    name: "@".to_string(),
                    record_type: "TXT".to_string(),
                    ttl: "3600".to_string(),
                    value: "v=spf1 ip4:{{mail_servers}} -all".to_string(),
                    priority: None,
                    weight: None,
                    port: None,
                    conditional: None,
                },
                TemplateRecord {
                    name: "_dmarc".to_string(),
                    record_type: "TXT".to_string(),
                    ttl: "3600".to_string(),
                    value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@{{zone}}".to_string(),
                    priority: None,
                    weight: None,
                    port: None,
                    conditional: None,
                },
                TemplateRecord {
                    name: "{{dkim_selector}}._domainkey".to_string(),
                    record_type: "TXT".to_string(),
                    ttl: "3600".to_string(),
                    value: "v=DKIM1; k=rsa; p={{dkim_key}}".to_string(),
                    priority: None,
                    weight: None,
                    port: None,
                    conditional: None,
                },
            ],
            validation_rules: vec![
                ValidationRule {
                    name: "valid_spf".to_string(),
                    rule_type: ValidationRuleType::ValidSPF,
                    parameters: HashMap::new(),
                    error_message: "Invalid SPF record".to_string(),
                },
                ValidationRule {
                    name: "valid_dmarc".to_string(),
                    rule_type: ValidationRuleType::ValidDMARC,
                    parameters: HashMap::new(),
                    error_message: "Invalid DMARC record".to_string(),
                },
            ],
            metadata: TemplateMetadata {
                author: "Atlas DNS Team".to_string(),
                version: "1.0.0".to_string(),
                created: Self::current_timestamp(),
                modified: Self::current_timestamp(),
                license: Some("MIT".to_string()),
                documentation_url: None,
            },
            tags: vec!["email".to_string(), "spf".to_string(), "dkim".to_string(), "dmarc".to_string()],
        }
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Template statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TemplateStats {
    /// Total templates
    pub total_templates: usize,
    /// Custom templates
    pub custom_templates: usize,
    /// Total instances
    pub total_instances: u64,
    /// Successful applications
    pub successful_applications: u64,
    /// Failed applications
    pub failed_applications: u64,
    /// Most used template
    pub most_used_template: Option<String>,
}

/// Zone templates handler
pub struct ZoneTemplatesHandler {
    /// Configuration
    config: Arc<RwLock<ZoneTemplateConfig>>,
    /// Templates
    templates: Arc<RwLock<HashMap<String, ZoneTemplate>>>,
    /// Template instances
    instances: Arc<RwLock<Vec<TemplateInstance>>>,
    /// Statistics
    stats: Arc<RwLock<TemplateStats>>,
    /// Variable cache
    variable_cache: Arc<RwLock<HashMap<String, HashMap<String, String>>>>,
}

impl ZoneTemplatesHandler {
    /// Create new zone templates handler
    pub fn new(config: ZoneTemplateConfig) -> Self {
        let handler = Self {
            config: Arc::new(RwLock::new(config)),
            templates: Arc::new(RwLock::new(HashMap::new())),
            instances: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(TemplateStats::default())),
            variable_cache: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Load built-in templates
        handler.load_builtin_templates();
        
        handler
    }

    /// Load built-in templates
    fn load_builtin_templates(&self) {
        let templates = vec![
            BuiltInTemplates::basic_web(),
            BuiltInTemplates::ecommerce(),
            BuiltInTemplates::email_service(),
        ];
        
        let mut template_map = self.templates.write();
        for template in templates {
            template_map.insert(template.id.clone(), template);
        }
        
        self.stats.write().total_templates = template_map.len();
    }

    /// Register template
    pub fn register_template(&self, template: ZoneTemplate) -> Result<(), String> {
        let config = self.config.read();
        
        if !config.allow_custom && template.category == TemplateCategory::Custom {
            return Err("Custom templates are not allowed".to_string());
        }
        
        // Validate template
        self.validate_template(&template)?;
        
        // Check for parent
        if let Some(parent_id) = &template.parent {
            if !self.templates.read().contains_key(parent_id) {
                return Err(format!("Parent template {} not found", parent_id));
            }
        }
        
        self.templates.write().insert(template.id.clone(), template);
        self.update_stats();
        
        Ok(())
    }

    /// Apply template
    pub fn apply_template(
        &self,
        template_id: &str,
        zone_name: &str,
        variables: HashMap<String, String>,
        user: &str,
    ) -> Result<Vec<TemplateRecord>, String> {
        let templates = self.templates.read();
        
        let template = templates.get(template_id)
            .ok_or_else(|| format!("Template {} not found", template_id))?;
        
        // Validate variables
        self.validate_variables(template, &variables)?;
        
        // Merge with parent variables if applicable
        let merged_variables = self.merge_parent_variables(template, variables)?;
        
        // Expand template
        let records = self.expand_template(template, zone_name, &merged_variables)?;
        
        // Validate result if configured
        if self.config.read().validate_on_apply {
            self.validate_zone_records(&records, template)?;
        }
        
        // Create instance
        let instance = TemplateInstance {
            id: Self::generate_id(),
            template_id: template_id.to_string(),
            zone_name: zone_name.to_string(),
            variables: merged_variables.clone(),
            applied_at: Self::current_timestamp(),
            applied_by: user.to_string(),
            status: InstanceStatus::Applied,
        };
        
        self.instances.write().push(instance);
        self.stats.write().successful_applications += 1;
        
        Ok(records)
    }

    /// Validate template
    fn validate_template(&self, template: &ZoneTemplate) -> Result<(), String> {
        // Check variable count
        if template.variables.len() > self.config.read().max_variables {
            return Err(format!("Template has too many variables (max: {})", 
                self.config.read().max_variables));
        }
        
        // Validate variable patterns
        for variable in &template.variables {
            if let Some(pattern) = &variable.pattern {
                Regex::new(pattern)
                    .map_err(|e| format!("Invalid pattern for variable {}: {}", variable.name, e))?;
            }
        }
        
        // Check for duplicate variable names
        let mut seen = HashSet::new();
        for variable in &template.variables {
            if !seen.insert(&variable.name) {
                return Err(format!("Duplicate variable name: {}", variable.name));
            }
        }
        
        Ok(())
    }

    /// Validate variables
    fn validate_variables(
        &self,
        template: &ZoneTemplate,
        variables: &HashMap<String, String>,
    ) -> Result<(), String> {
        for template_var in &template.variables {
            if template_var.required {
                if !variables.contains_key(&template_var.name) && template_var.default_value.is_none() {
                    return Err(format!("Required variable {} not provided", template_var.name));
                }
            }
            
            if let Some(value) = variables.get(&template_var.name) {
                // Check type
                if !self.validate_variable_type(value, &template_var.var_type) {
                    return Err(format!("Invalid type for variable {}", template_var.name));
                }
                
                // Check pattern
                if let Some(pattern) = &template_var.pattern {
                    let regex = Regex::new(pattern).unwrap();
                    if !regex.is_match(value) {
                        return Err(format!("Variable {} does not match pattern", template_var.name));
                    }
                }
                
                // Check allowed values
                if let Some(allowed) = &template_var.allowed_values {
                    if !allowed.contains(value) {
                        return Err(format!("Variable {} has invalid value", template_var.name));
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Validate variable type
    fn validate_variable_type(&self, value: &str, var_type: &VariableType) -> bool {
        match var_type {
            VariableType::String => true,
            VariableType::IpAddress => {
                value.parse::<std::net::IpAddr>().is_ok()
            }
            VariableType::IpV4Address => {
                value.parse::<std::net::Ipv4Addr>().is_ok()
            }
            VariableType::IpV6Address => {
                value.parse::<std::net::Ipv6Addr>().is_ok()
            }
            VariableType::Domain => {
                // Simple domain validation
                value.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
            }
            VariableType::Email => {
                value.contains('@') && value.contains('.')
            }
            VariableType::Number => {
                value.parse::<i64>().is_ok()
            }
            VariableType::Boolean => {
                value == "true" || value == "false"
            }
            VariableType::List => true,
        }
    }

    /// Merge parent variables
    fn merge_parent_variables(
        &self,
        template: &ZoneTemplate,
        mut variables: HashMap<String, String>,
    ) -> Result<HashMap<String, String>, String> {
        if let Some(parent_id) = &template.parent {
            let templates = self.templates.read();
            if let Some(parent) = templates.get(parent_id) {
                // Add default values from parent
                for parent_var in &parent.variables {
                    if !variables.contains_key(&parent_var.name) {
                        if let Some(default) = &parent_var.default_value {
                            variables.insert(parent_var.name.clone(), default.clone());
                        }
                    }
                }
            }
        }
        
        // Add defaults from current template
        for template_var in &template.variables {
            if !variables.contains_key(&template_var.name) {
                if let Some(default) = &template_var.default_value {
                    variables.insert(template_var.name.clone(), default.clone());
                }
            }
        }
        
        Ok(variables)
    }

    /// Expand template
    fn expand_template(
        &self,
        template: &ZoneTemplate,
        zone_name: &str,
        variables: &HashMap<String, String>,
    ) -> Result<Vec<TemplateRecord>, String> {
        let mut expanded_records = Vec::new();
        
        // Add zone variable
        let mut all_variables = variables.clone();
        all_variables.insert("zone".to_string(), zone_name.to_string());
        
        // Expand parent records if applicable
        if let Some(parent_id) = &template.parent {
            let templates = self.templates.read();
            if let Some(parent) = templates.get(parent_id) {
                let parent_records = self.expand_template(parent, zone_name, &all_variables)?;
                expanded_records.extend(parent_records);
            }
        }
        
        // Expand current template records
        for record in &template.records {
            // Check condition
            if let Some(condition) = &record.conditional {
                if !self.evaluate_condition(condition, &all_variables) {
                    continue;
                }
            }
            
            // Expand variables in record
            let expanded = TemplateRecord {
                name: self.expand_string(&record.name, &all_variables),
                record_type: record.record_type.clone(),
                ttl: self.expand_string(&record.ttl, &all_variables),
                value: self.expand_string(&record.value, &all_variables),
                priority: record.priority.as_ref().map(|p| self.expand_string(p, &all_variables)),
                weight: record.weight.as_ref().map(|w| self.expand_string(w, &all_variables)),
                port: record.port.as_ref().map(|p| self.expand_string(p, &all_variables)),
                conditional: None,
            };
            
            expanded_records.push(expanded);
        }
        
        Ok(expanded_records)
    }

    /// Expand string with variables
    fn expand_string(&self, template: &str, variables: &HashMap<String, String>) -> String {
        let mut result = template.to_string();
        
        for (key, value) in variables {
            let pattern = format!("{{{{{}}}}}", key);
            result = result.replace(&pattern, value);
        }
        
        result
    }

    /// Evaluate condition
    fn evaluate_condition(&self, condition: &RecordCondition, variables: &HashMap<String, String>) -> bool {
        let value = variables.get(&condition.variable);
        
        match condition.operator {
            ConditionOperator::Exists => value.is_some(),
            ConditionOperator::NotExists => value.is_none(),
            ConditionOperator::Equals => {
                value.map_or(false, |v| v == &condition.value)
            }
            ConditionOperator::NotEquals => {
                value.map_or(true, |v| v != &condition.value)
            }
            ConditionOperator::Contains => {
                value.map_or(false, |v| v.contains(&condition.value))
            }
            ConditionOperator::NotContains => {
                value.map_or(true, |v| !v.contains(&condition.value))
            }
        }
    }

    /// Validate zone records
    fn validate_zone_records(
        &self,
        records: &[TemplateRecord],
        template: &ZoneTemplate,
    ) -> Result<(), String> {
        for rule in &template.validation_rules {
            match rule.rule_type {
                ValidationRuleType::MinimumRecords => {
                    let min = rule.parameters.get("count")
                        .and_then(|c| c.parse::<usize>().ok())
                        .unwrap_or(0);
                    if records.len() < min {
                        return Err(rule.error_message.clone());
                    }
                }
                ValidationRuleType::MaximumRecords => {
                    let max = rule.parameters.get("count")
                        .and_then(|c| c.parse::<usize>().ok())
                        .unwrap_or(usize::MAX);
                    if records.len() > max {
                        return Err(rule.error_message.clone());
                    }
                }
                ValidationRuleType::RequiredRecordTypes => {
                    if let Some(types) = rule.parameters.get("types") {
                        let required: HashSet<&str> = types.split(',').collect();
                        let present: HashSet<String> = records.iter()
                            .map(|r| r.record_type.clone())
                            .collect();
                        
                        for req_type in required {
                            if !present.contains(req_type) {
                                return Err(rule.error_message.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }

    /// Get template
    pub fn get_template(&self, template_id: &str) -> Option<ZoneTemplate> {
        self.templates.read().get(template_id).cloned()
    }

    /// List templates
    pub fn list_templates(&self, category: Option<TemplateCategory>) -> Vec<ZoneTemplate> {
        let templates = self.templates.read();
        
        if let Some(cat) = category {
            templates.values()
                .filter(|t| t.category == cat)
                .cloned()
                .collect()
        } else {
            templates.values().cloned().collect()
        }
    }

    /// Get template instances
    pub fn get_instances(&self, zone_name: Option<&str>) -> Vec<TemplateInstance> {
        let instances = self.instances.read();
        
        if let Some(zone) = zone_name {
            instances.iter()
                .filter(|i| i.zone_name == zone)
                .cloned()
                .collect()
        } else {
            instances.clone()
        }
    }

    /// Update statistics
    fn update_stats(&self) {
        let mut stats = self.stats.write();
        let templates = self.templates.read();
        
        stats.total_templates = templates.len();
        stats.custom_templates = templates.values()
            .filter(|t| t.category == TemplateCategory::Custom)
            .count();
        
        // Find most used template
        let mut usage_count: HashMap<String, u64> = HashMap::new();
        for instance in self.instances.read().iter() {
            *usage_count.entry(instance.template_id.clone()).or_insert(0) += 1;
        }
        
        stats.most_used_template = usage_count.into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(template_id, _)| template_id);
    }

    /// Get statistics
    pub fn get_stats(&self) -> TemplateStats {
        self.stats.read().clone()
    }

    /// Generate ID
    fn generate_id() -> String {
        format!("{:x}", Self::current_timestamp())
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

use std::collections::HashSet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_web_template() {
        let config = ZoneTemplateConfig::default();
        let handler = ZoneTemplatesHandler::new(config);
        
        let template = handler.get_template("basic-web").unwrap();
        assert_eq!(template.category, TemplateCategory::BasicWeb);
        assert_eq!(template.variables.len(), 2);
    }

    #[test]
    fn test_apply_template() {
        let config = ZoneTemplateConfig::default();
        let handler = ZoneTemplatesHandler::new(config);
        
        let mut variables = HashMap::new();
        variables.insert("web_ip".to_string(), "192.168.1.1".to_string());
        
        let result = handler.apply_template(
            "basic-web",
            "example.com",
            variables,
            "admin",
        );
        
        assert!(result.is_ok());
        let records = result.unwrap();
        assert!(records.len() >= 3);
    }

    #[test]
    fn test_variable_expansion() {
        let config = ZoneTemplateConfig::default();
        let handler = ZoneTemplatesHandler::new(config);
        
        let mut variables = HashMap::new();
        variables.insert("test".to_string(), "value".to_string());
        
        let expanded = handler.expand_string("{{test}} is {{test}}", &variables);
        assert_eq!(expanded, "value is value");
    }
}