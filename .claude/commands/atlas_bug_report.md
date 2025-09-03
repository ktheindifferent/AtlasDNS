````markdown
# /atlas_bug_report Command - Add New Bug Reports to Atlas DNS Bug Tracking

## Command Purpose
This command enables Claude to automatically analyze user-reported issues, system problems, or discovered bugs and add them to the `bugs.md` file with proper categorization, priority assessment, and structured tracking information for the Atlas DNS system.

## Bug Report Categories & Classification

### 🔴 CRITICAL Security Issues
**Criteria**: Vulnerabilities that could lead to system compromise, data breaches, or service disruption
```markdown
# Template for Critical Security Bug
- [ ] **[Vulnerability Type]**: [Brief description] in [file]:[line]
  - **Impact**: [Security impact assessment]
  - **CVSS Score**: [If applicable] 
  - **Affected Component**: [DNS/Web/API/Auth]
  - **Reproducible**: [Yes/No] via [steps]
  - **Sentry**: [Error frequency if tracked]
```

**Examples**:
- Authentication bypass vulnerabilities
- SQL injection (if database implemented)
- DNS cache poisoning vulnerabilities
- Session hijacking potential
- DNSSEC validation bypass
- DoS attack vectors

### 🟠 HIGH Priority API/DNS Issues
**Criteria**: Functional problems affecting core DNS operations or critical API endpoints
```markdown
# Template for High Priority Bug
- [ ] **[Issue Type]**: [Description] in [component/file]
  - **Symptoms**: [What users experience]
  - **Frequency**: [Always/Intermittent/Rare]
  - **DNS Impact**: [Query types/protocols affected]
  - **API Impact**: [Endpoints affected]
  - **Workaround**: [If available]
```

**Examples**:
- DNS resolution failures
- API endpoint errors (500, parsing issues)
- Authentication failures
- Zone management problems
- Cache corruption
- Protocol implementation bugs (DoH/DoT/DNSSEC)

### 🟡 MEDIUM Priority Performance Issues
**Criteria**: Performance degradation, memory leaks, or efficiency problems
```markdown
# Template for Performance Bug
- [ ] **[Performance Issue]**: [Description] in [component]
  - **Metric Impact**: [Response time/Memory/CPU]
  - **Threshold**: [Current vs Expected performance]
  - **Load Conditions**: [When it occurs]
  - **Resource Usage**: [Memory/CPU/Network impact]
  - **Scalability**: [Impact on high load]
```

**Examples**:
- Memory leaks in long-running operations
- Slow query processing (>10ms target)
- High CPU usage under load
- Inefficient cache algorithms
- Network connection exhaustion
- Thread pool starvation

### 🟢 LOW Priority Code Quality Issues
**Criteria**: Code quality, compilation warnings, or minor usability issues
```markdown
# Template for Code Quality Bug
- [ ] **[Quality Issue]**: [Description] in [file]:[line-range]
  - **Type**: [Warning/Error/Style/Documentation]
  - **Compilation**: [Affects build: Yes/No]
  - **Runtime Impact**: [None/Minimal/Moderate]
  - **Technical Debt**: [Cleanup effort required]
```

**Examples**:
- Compilation warnings
- Unused variables/imports
- Poor error messages
- Missing documentation
- Code duplication
- Inefficient algorithms (non-critical path)

## Bug Report Analysis Workflow

### Phase 1: Issue Assessment and Classification
```bash
# Automated bug analysis checklist

# 1. Determine issue severity
assess_bug_severity() {
    echo "=== Bug Severity Assessment ==="
    echo "1. Does this affect security? (Authentication, Authorization, Encryption)"
    echo "2. Does this affect core DNS functionality? (Resolution, Protocols)"
    echo "3. Does this affect performance? (Response time, Resource usage)"
    echo "4. Does this affect code quality? (Warnings, Style, Documentation)"
}

# 2. Check if issue is already tracked
check_existing_bugs() {
    local issue_description="$1"
    echo "=== Checking for Duplicate Issues ==="
    grep -i "$issue_description" bugs.md || echo "No duplicates found"
}

# 3. Reproduce issue if possible
reproduce_issue() {
    echo "=== Issue Reproduction ==="
    echo "Attempting to reproduce on: https://atlas.alpha.opensam.foundation/"
    # [Specific reproduction steps based on issue type]
}

# 4. Gather system context
gather_system_context() {
    echo "=== System Context Collection ==="
    curl -s https://atlas.alpha.opensam.foundation/api/version
    curl -s https://atlas.alpha.opensam.foundation/api/system/metrics | jq '.response_time_ms'
}
```

### Phase 2: Sentry Integration for Bug Analysis
```bash
# Enhanced bug analysis with Sentry error monitoring

analyze_with_sentry() {
    local issue_type="$1"
    echo "=== Sentry Error Analysis ==="
    
    # Check for related errors in last 24 hours
    RELATED_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
        "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=24h&query=tag:component:${issue_type}" | \
        jq -r '.[] | "\(.count)x: \(.title)"')
    
    if [ -n "$RELATED_ERRORS" ]; then
        echo "Related Sentry errors found:"
        echo "$RELATED_ERRORS"
    else
        echo "No related Sentry errors in last 24 hours"
    fi
    
    # Check for high-frequency errors that might be related
    HIGH_FREQ_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
        "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=7d&sort=freq" | \
        jq -r '.[] | select(.count > 50) | "\(.count)x: \(.title)"' | head -5)
    
    if [ -n "$HIGH_FREQ_ERRORS" ]; then
        echo "High-frequency errors (may be related):"
        echo "$HIGH_FREQ_ERRORS"
    fi
}

# Usage: analyze_with_sentry "dns" or "web" or "auth"
```

### Phase 3: Bug Report Generation
```bash
# Generate comprehensive bug report

generate_bug_report() {
    local issue_title="$1"
    local issue_description="$2"
    local severity="$3"
    local component="$4"
    local reproduction_steps="$5"
    
    echo "=== Generating Bug Report ==="
    
    # Determine priority emoji and section
    case $severity in
        "critical"|"security")
            PRIORITY="🔴"
            SECTION="CRITICAL Security Issues"
            ;;
        "high"|"api"|"dns")
            PRIORITY="🟠"
            SECTION="HIGH Priority API/DNS Issues"
            ;;
        "medium"|"performance")
            PRIORITY="🟡"
            SECTION="MEDIUM Priority Performance Issues"
            ;;
        "low"|"quality"|"warning")
            PRIORITY="🟢"
            SECTION="LOW Priority Code Quality Issues"
            ;;
        *)
            PRIORITY="🟡"
            SECTION="MEDIUM Priority Issues"
            ;;
    esac
    
    # Create formatted bug entry
    cat << EOF
### $issue_title
- [ ] **$issue_title**: $issue_description
  - **Component**: $component
  - **Severity**: $severity
  - **Reported**: $(date +%Y-%m-%d)
  - **Reproduction**: $reproduction_steps
  - **Environment**: https://atlas.alpha.opensam.foundation/
  - **Status**: Open
EOF
}
```

## Bug Report Templates by Category

### Security Vulnerability Template
```markdown
### [SECURITY] [Vulnerability Type] in [Component]
- [ ] **[Vulnerability Name]**: [Detailed description] in src/[component]/[file]:[line]
  - **Impact**: [Confidentiality/Integrity/Availability impact]
  - **Attack Vector**: [Local/Network/Physical]
  - **Authentication Required**: [None/Single/Multiple]
  - **User Interaction**: [None/Required]
  - **CVSS v3 Score**: [If calculated]
  - **Affected Versions**: [Version range]
  - **Component**: [DNS Server/Web Interface/API/Authentication]
  - **Reproducible**: [Always/Sometimes/Rare]
  - **POC Available**: [Yes/No] - [Description if yes]
  - **Mitigation**: [Immediate steps to reduce risk]
  - **Sentry Tracking**: [Error ID if available] ([frequency])
  - **Related Issues**: [Links to related bugs/CVEs]
```

### DNS Protocol Bug Template
```markdown
### [DNS] [Protocol/Query Type] Issue in [Component]
- [ ] **[Bug Title]**: [Description] affecting [query types/protocols]
  - **DNS Protocol**: [UDP/TCP/DoH/DoT/DoQ/DNSSEC]
  - **Query Types**: [A/AAAA/CNAME/MX/TXT/NS/SOA/PTR]
  - **Symptoms**: [What happens vs expected behavior]
  - **Frequency**: [Always/Load-dependent/Intermittent]
  - **Client Impact**: [Timeout/Wrong answer/No response/Error]
  - **Server Logs**: [Error patterns if available]
  - **Upstream Impact**: [Does it affect forwarded queries]
  - **Zone Types**: [Authoritative/Recursive/Cache/All]
  - **Reproduction**: [Specific dig/nslookup commands]
  - **Performance Impact**: [Response time degradation]
  - **Workaround**: [Alternative approach if available]
```

### API Endpoint Bug Template
```markdown
### [API] [HTTP Method] [Endpoint] Error
- [ ] **[API Bug Title]**: [Description] in [endpoint]
  - **Endpoint**: [Full URL path and method]
  - **Request Format**: [JSON/Form/Query params]
  - **Response Code**: [Expected vs Actual HTTP status]
  - **Response Body**: [Error message/malformed JSON]
  - **Authentication**: [Required/Optional/Bypass issue]
  - **Request Size**: [Small/Large/Specific size trigger]
  - **Concurrency**: [Single request/Concurrent/Race condition]
  - **Data Validation**: [Input validation failure]
  - **Database Impact**: [If persistence affected]
  - **API Version**: [v1/v2/GraphQL]
  - **Client Type**: [Web UI/CLI/SDK/External]
  - **Error Rate**: [Percentage of requests affected]
```

### Performance Issue Template
```markdown
### [PERF] [Component] Performance Degradation
- [ ] **[Performance Issue]**: [Description] in [component/operation]
  - **Metric**: [Response Time/Memory/CPU/Network/Disk]
  - **Current Value**: [Measured performance]
  - **Expected Value**: [Target/Previous performance]
  - **Degradation**: [Percentage or absolute difference]
  - **Load Conditions**: [Idle/Normal/High/Stress]
  - **Time Pattern**: [Constant/Growing/Periodic/Spike]
  - **Resource Usage**: [Memory leak/CPU spike/Network saturation]
  - **Scaling Behavior**: [Linear/Exponential/Plateau]
  - **Threshold**: [Point where performance becomes unacceptable]
  - **User Impact**: [Timeout/Slow response/Service unavailable]
  - **Monitoring Data**: [Metrics/Graphs if available]
  - **Profiling**: [Hot spots/Bottlenecks identified]
```

### Code Quality Issue Template
```markdown
### [QUALITY] [Type] in [File/Component]
- [ ] **[Quality Issue]**: [Description] in src/[component]/[file]
  - **Issue Type**: [Compilation Warning/Error/Style/Documentation/Technical Debt]
  - **Compiler Message**: [Exact warning/error text]
  - **Line Numbers**: [Specific lines affected]
  - **Scope**: [Single function/Module/Cross-cutting]
  - **Build Impact**: [Prevents build/Warning only/Runtime issue]
  - **Maintenance Impact**: [Code readability/Future development]
  - **Performance Impact**: [None/Minimal/Measurable]
  - **Technical Debt**: [Effort required to fix]
  - **Priority Justification**: [Why low priority vs higher]
  - **Related Issues**: [Other code quality problems]
```

## Integration with Existing Atlas DNS Commands

### Workflow with atlas_bug_fix
```bash
# After reporting a bug with atlas_bug_report:
# 1. High/Critical bugs should be fixed immediately with atlas_bug_fix
# 2. Medium/Low bugs can be scheduled for future sessions
# 3. Security bugs should trigger immediate atlas_bug_fix session

prioritize_bug_fix() {
    local bug_severity="$1"
    case $bug_severity in
        "critical"|"security")
            echo "⚠️  CRITICAL BUG: Run atlas_bug_fix immediately"
            ;;
        "high")
            echo "🟠 HIGH PRIORITY: Schedule atlas_bug_fix within 24 hours"
            ;;
        "medium"|"low")
            echo "📋 TRACKED: Add to next planned atlas_bug_fix session"
            ;;
    esac
}
```

### Workflow with atlas_bug_compress
```bash
# After multiple bug reports:
# 1. Use atlas_bug_compress to organize and deduplicate
# 2. Ensure new bugs don't duplicate existing issues
# 3. Maintain clean bug tracking structure

check_compression_needed() {
    local bug_count=$(grep -c "^- \[ \]" bugs.md)
    if [ $bug_count -gt 20 ]; then
        echo "📊 CONSIDER: Run atlas_bug_compress to organize $bug_count open bugs"
    fi
}
```

## Automated Bug Report Examples

### Security Bug Discovery
```bash
# Example: Discovered authentication bypass
report_auth_bypass_bug() {
    cat >> bugs.md << 'EOF'

### [SECURITY] Authentication Bypass in Session Validation
- [ ] **Session Token Validation Bypass**: Missing signature verification in src/web/sessions.rs:245-260
  - **Impact**: Attackers can forge session tokens without authentication
  - **Attack Vector**: Network (HTTP request manipulation)
  - **Authentication Required**: None
  - **User Interaction**: None
  - **CVSS v3 Score**: 9.1 (Critical)
  - **Affected Versions**: Current production
  - **Component**: Web Interface/Authentication
  - **Reproducible**: Always with crafted token
  - **POC Available**: Yes - Modified session cookie validation
  - **Mitigation**: Restart service, implement proper token validation
  - **Sentry Tracking**: Not detected (silent bypass)
  - **Related Issues**: Session security improvements needed

EOF
}
```

### DNS Protocol Bug Discovery
```bash
# Example: DNS resolution failure
report_dns_bug() {
    cat >> bugs.md << 'EOF'

### [DNS] AAAA Query Timeout in Recursive Resolution
- [ ] **IPv6 Resolution Timeout**: AAAA queries fail with SERVFAIL in src/dns/resolve.rs:180-200
  - **DNS Protocol**: UDP/TCP (both affected)
  - **Query Types**: AAAA only (A records work)
  - **Symptoms**: 5-second timeout then SERVFAIL response
  - **Frequency**: Always for IPv6 queries
  - **Client Impact**: No IPv6 resolution, fallback to IPv4
  - **Server Logs**: "IPv6 upstream timeout" every AAAA query
  - **Upstream Impact**: Yes - blocks upstream IPv6 queries
  - **Zone Types**: Recursive only (authoritative works)
  - **Reproduction**: dig @atlas.alpha.opensam.foundation AAAA google.com
  - **Performance Impact**: 5s delay on dual-stack queries
  - **Workaround**: Use IPv4-only upstream resolvers

EOF
}
```

### API Endpoint Bug Discovery
```bash
# Example: API parsing error
report_api_bug() {
    cat >> bugs.md << 'EOF'

### [API] POST /api/v2/zones JSON Parsing Error
- [ ] **Zone Creation JSON Parsing**: Malformed JSON error for valid requests in src/web/api_v2.rs:450-470
  - **Endpoint**: POST /api/v2/zones
  - **Request Format**: JSON (Content-Type: application/json)
  - **Response Code**: 400 Bad Request (Expected: 201 Created)
  - **Response Body**: "Invalid JSON format" for valid JSON
  - **Authentication**: Required (Bearer token)
  - **Request Size**: Any size (even minimal JSON)
  - **Concurrency**: Single request affected
  - **Data Validation**: JSON parser fails before validation
  - **Database Impact**: No zones created due to parsing failure
  - **API Version**: v2 only (v1 works)
  - **Client Type**: All (Web UI, CLI, SDK)
  - **Error Rate**: 100% of JSON zone creation requests

EOF
}
```

### Performance Issue Discovery
```bash
# Example: Memory leak detection
report_performance_bug() {
    cat >> bugs.md << 'EOF'

### [PERF] Memory Leak in DNS Cache Management
- [ ] **DNS Cache Memory Growth**: Unbounded memory growth in src/dns/cache.rs:120-150
  - **Metric**: Memory Usage
  - **Current Value**: 2.5GB after 24 hours (started at 300MB)
  - **Expected Value**: Stable around 500MB maximum
  - **Degradation**: 800% increase over 24 hours
  - **Load Conditions**: Normal production load (10k QPS)
  - **Time Pattern**: Linear growth over time
  - **Resource Usage**: Memory leak in cache entries
  - **Scaling Behavior**: Linear with query volume
  - **Threshold**: 4GB available, becomes critical at 3.5GB
  - **User Impact**: Eventually causes OOM kill and service restart
  - **Monitoring Data**: Grafana shows steady memory increase
  - **Profiling**: Cache entries not being garbage collected

EOF
}
```

## Bug Report Quality Standards

### Minimum Information Requirements
1. **Clear Title**: Descriptive and specific
2. **Component Identification**: Exact file and line numbers if possible
3. **Reproduction Steps**: Detailed steps to reproduce
4. **Expected vs Actual**: What should happen vs what happens
5. **Environment**: Production URL and system context
6. **Impact Assessment**: User/system impact description

### Enhanced Information (When Available)
1. **Sentry Integration**: Error IDs and frequency data
2. **Performance Metrics**: Quantified performance impact
3. **Security Assessment**: CVSS scores for vulnerabilities
4. **Code Analysis**: Root cause analysis when possible
5. **Workarounds**: Temporary mitigation strategies

### Bug Report Validation Checklist
- [ ] Title clearly describes the issue
- [ ] Severity correctly assessed and categorized
- [ ] Component and file location specified
- [ ] Reproduction steps provided
- [ ] Impact clearly described
- [ ] Not a duplicate of existing bug
- [ ] Proper markdown formatting
- [ ] Added to correct section in bugs.md

## Post-Report Actions

### Immediate Actions for Critical/Security Bugs
```bash
# Automated response for critical bugs
handle_critical_bug() {
    local bug_title="$1"
    echo "🚨 CRITICAL BUG REPORTED: $bug_title"
    echo "1. Immediately assess production impact"
    echo "2. Consider emergency maintenance if needed"
    echo "3. Prepare for immediate atlas_bug_fix session"
    echo "4. Notify stakeholders if customer-facing"
}
```

### Follow-up Tracking
```bash
# Add to bugs.md with proper tracking
add_bug_tracking() {
    local bug_entry="$1"
    local timestamp=$(date +%Y-%m-%d_%H%M%S)
    
    # Backup current bugs.md
    cp bugs.md "bugs_backup_$(date +%Y%m%d_%H%M%S).md"
    
    # Add new bug to appropriate section
    # [Implementation to insert bug in correct priority section]
    
    echo "✅ Bug reported and tracked in bugs.md"
    echo "📋 Backup created: bugs_backup_${timestamp}.md"
}
```

## Notes for Claude (Atlas DNS Bug Reporting)

- **ASSESS SEVERITY CAREFULLY**: Use production impact and security implications to determine priority
- **CHECK FOR DUPLICATES**: Always search existing bugs.md before adding new entries
- **PROVIDE REPRODUCTION**: Include specific commands, URLs, or steps to reproduce
- **QUANTIFY IMPACT**: Use metrics, error rates, and performance data when available
- **INTEGRATE WITH SENTRY**: Include Sentry error IDs and frequency data when available
- **MAINTAIN FORMATTING**: Follow exact markdown structure for consistency
- **PRIORITIZE SECURITY**: Any security issue should be marked critical and require immediate attention
- **LINK TO CONTEXT**: Reference related files, commits, or other issues when relevant

Remember: Bug reports are critical for maintaining Atlas DNS production quality. Every report should provide enough information for immediate assessment and eventual resolution. Focus on clarity, accuracy, and actionable information to support effective bug triage and fixing workflows.
````
