````markdown
# /atlas_todo Command - Add New TODO Items to Atlas DNS Task Management

## Command Purpose
This command enables Claude to automatically analyze user requests, discovered feature needs, or implementation requirements and add them to the `todo.md` file with proper categorization, priority assessment, and structured task tracking for the Atlas DNS system.

## TODO Item Categories & Classification

### 🔥 Critical Priority (Start Immediately)
**Criteria**: Essential features for production readiness, security requirements, or critical performance issues
```markdown
# Template for Critical Priority TODO
- [ ] **[Feature/Task Name]** - [Brief description with impact]
  - **Priority**: Critical
  - **Impact**: [Security/Performance/Functionality]
  - **Effort**: [Small/Medium/Large/XL]
  - **Dependencies**: [Other tasks/features required first]
  - **Target**: [Performance metric/completion criteria]
```

**Examples**:
- Security vulnerabilities requiring immediate patches
- Production-blocking features
- Critical performance optimizations
- Essential protocol implementations

### 📊 High Priority (Enterprise Features)
**Criteria**: Important features for enterprise deployment, major functionality additions
```markdown
# Template for High Priority TODO
- [ ] **[Feature Name]** - [Description with business value]
  - **Priority**: High
  - **Business Value**: [Why this matters for users/enterprise]
  - **Technical Complexity**: [Implementation challenges]
  - **Integration Points**: [What systems this affects]
  - **Success Metrics**: [How to measure completion]
```

**Examples**:
- Advanced DNS features (GeoDNS, Load Balancing)
- Enterprise analytics and monitoring
- Protocol enhancements (DoH, DoT, DNSSEC)
- Developer experience improvements

### 🛠️ Medium Priority (Quality & Performance)
**Criteria**: Code quality improvements, performance optimizations, nice-to-have features
```markdown
# Template for Medium Priority TODO
- [ ] **[Improvement Name]** - [Description with benefits]
  - **Priority**: Medium
  - **Code Quality Impact**: [Maintainability/Readability/Performance]
  - **Technical Debt**: [How much this reduces technical debt]
  - **Performance**: [Expected performance improvement]
  - **Maintenance**: [Impact on ongoing maintenance]
```

**Examples**:
- Code cleanup and refactoring
- Performance optimizations
- Test coverage improvements
- Documentation enhancements

### 🔮 Future Priority (Innovation & Research)
**Criteria**: Experimental features, research projects, future technology adoption
```markdown
# Template for Future Priority TODO
- [ ] **[Innovation Name]** - [Description with future value]
  - **Priority**: Future
  - **Research Required**: [What needs to be investigated]
  - **Technology Readiness**: [Maturity of underlying tech]
  - **Market Demand**: [User/industry demand level]
  - **Timeline**: [Realistic implementation timeframe]
```

**Examples**:
- AI/ML features
- Experimental protocols
- Blockchain integration
- Next-generation technologies

## TODO Item Analysis Workflow

### Phase 1: Requirement Assessment
```bash
# Automated TODO analysis checklist

# 1. Understand the requirement
assess_requirement() {
    echo "=== Requirement Assessment ==="
    echo "1. What specific functionality is needed?"
    echo "2. Who are the target users? (End users/Developers/Administrators)"
    echo "3. What's the business/technical value?"
    echo "4. Are there existing alternatives or workarounds?"
    echo "5. What are the acceptance criteria?"
}

# 2. Analyze implementation complexity
assess_complexity() {
    echo "=== Implementation Complexity Analysis ==="
    echo "1. New code required vs. existing code modification"
    echo "2. External dependencies needed"
    echo "3. Impact on existing architecture"
    echo "4. Testing requirements"
    echo "5. Documentation requirements"
}

# 3. Determine priority level
determine_priority() {
    local requirement="$1"
    echo "=== Priority Determination ==="
    echo "1. Security impact: [Critical/High/Medium/Low/None]"
    echo "2. User impact: [High/Medium/Low]"
    echo "3. Technical debt: [Increases/Neutral/Reduces]"
    echo "4. Performance impact: [Positive/Neutral/Negative]"
    echo "5. Effort required: [Small/Medium/Large/XL]"
}
```

### Phase 2: Technical Analysis
```bash
# Analyze implementation requirements

analyze_technical_requirements() {
    local feature_name="$1"
    echo "=== Technical Requirements Analysis ==="
    
    # Check what files/modules would be affected
    echo "Potential affected files:"
    find src/ -name "*.rs" | xargs grep -l "$(echo $feature_name | tr A-Z a-z)" || echo "New implementation area"
    
    # Check for similar existing implementations
    echo "Similar existing features:"
    grep -r "$(echo $feature_name | cut -d' ' -f1)" src/ || echo "No similar implementations found"
    
    # Analyze dependencies
    echo "Current dependencies that might be relevant:"
    grep -A5 -B5 "$(echo $feature_name | tr A-Z a-z)" Cargo.toml || echo "May require new dependencies"
}

# Check integration points
analyze_integration_points() {
    local feature_area="$1"
    echo "=== Integration Point Analysis ==="
    
    case $feature_area in
        "dns"|"protocol")
            echo "Integration points: src/dns/ modules, protocol buffer, server.rs"
            ;;
        "web"|"api"|"ui")
            echo "Integration points: src/web/ modules, templates/, API endpoints"
            ;;
        "security"|"auth")
            echo "Integration points: src/web/users.rs, sessions.rs, authentication"
            ;;
        "performance"|"metrics")
            echo "Integration points: src/metrics/, cache systems, monitoring"
            ;;
        *)
            echo "Integration points: To be determined based on implementation"
            ;;
    esac
}
```

### Phase 3: TODO Item Generation
```bash
# Generate comprehensive TODO item

generate_todo_item() {
    local item_title="$1"
    local description="$2"
    local priority="$3"
    local category="$4"
    local effort="$5"
    local rationale="$6"
    
    echo "=== Generating TODO Item ==="
    
    # Determine priority section and emoji
    case $priority in
        "critical"|"immediate")
            PRIORITY_EMOJI="🔥"
            SECTION="Critical Priority (Start Immediately)"
            ;;
        "high"|"enterprise")
            PRIORITY_EMOJI="📊"
            SECTION="High Priority (Enterprise Features)"
            ;;
        "medium"|"quality"|"performance")
            PRIORITY_EMOJI="🛠️"
            SECTION="Medium Priority (Quality & Performance)"
            ;;
        "future"|"research"|"innovation")
            PRIORITY_EMOJI="🔮"
            SECTION="Future Priority (Innovation & Research)"
            ;;
        *)
            PRIORITY_EMOJI="🛠️"
            SECTION="Medium Priority"
            ;;
    esac
    
    # Create formatted TODO entry
    cat << EOF

#### $category
- [ ] **$item_title** - $description
  - **Priority**: $priority
  - **Effort**: $effort
  - **Rationale**: $rationale
  - **Added**: $(date +%Y-%m-%d)
  - **Category**: $category
  - **Integration**: [To be analyzed during implementation]

EOF
}
```

## TODO Item Templates by Category

### DNS Protocol & Server Enhancement
```markdown
#### DNS Protocol Implementation
- [ ] **[Protocol/Feature Name]** - [Description of DNS functionality]
  - **Priority**: [Critical/High/Medium/Future]
  - **RFC Compliance**: [RFC numbers if applicable]
  - **Protocol Support**: [UDP/TCP/DoH/DoT/DoQ/DNSSEC]
  - **Query Types**: [A/AAAA/CNAME/MX/TXT/NS/SOA/PTR affected]
  - **Performance Target**: [Response time/throughput goals]
  - **Backward Compatibility**: [Impact on existing functionality]
  - **Testing Requirements**: [Protocol conformance/Interop testing]
  - **Security Implications**: [Security considerations]
  - **Implementation Files**: [src/dns/ modules affected]
```

### Web Interface & API Enhancement
```markdown
#### Web Interface/API Feature
- [ ] **[Feature Name]** - [Description of web/API functionality]
  - **Priority**: [Critical/High/Medium/Future]
  - **User Interface**: [Dashboard/API/CLI affected]
  - **API Endpoints**: [New endpoints or modifications]
  - **Authentication**: [Auth requirements/changes]
  - **Data Model**: [Database/storage changes needed]
  - **Real-time Updates**: [WebSocket/SSE requirements]
  - **Mobile Support**: [Responsive design considerations]
  - **Accessibility**: [A11y requirements]
  - **Implementation Files**: [src/web/ modules affected]
```

### Performance & Scalability Enhancement
```markdown
#### Performance Optimization
- [ ] **[Optimization Name]** - [Description of performance improvement]
  - **Priority**: [Critical/High/Medium/Future]
  - **Performance Metric**: [Latency/Throughput/Memory/CPU]
  - **Current Performance**: [Baseline measurements]
  - **Target Performance**: [Goal measurements]
  - **Bottleneck Analysis**: [Where the performance issue occurs]
  - **Optimization Strategy**: [Caching/Algorithm/Architecture]
  - **Resource Impact**: [Memory/CPU/Network implications]
  - **Scalability**: [Impact on system scalability]
  - **Implementation Files**: [Modules requiring optimization]
```

### Security & Compliance Enhancement
```markdown
#### Security Implementation
- [ ] **[Security Feature]** - [Description of security enhancement]
  - **Priority**: Critical
  - **Security Domain**: [Authentication/Authorization/Encryption/Audit]
  - **Threat Model**: [What threats this addresses]
  - **Compliance**: [GDPR/HIPAA/SOC2 requirements if applicable]
  - **Implementation Approach**: [Libraries/Algorithms/Protocols]
  - **Performance Impact**: [Security vs performance trade-offs]
  - **Backward Compatibility**: [Impact on existing security]
  - **Testing Requirements**: [Security testing/Penetration testing]
  - **Implementation Files**: [Security-related modules]
```

### DevOps & Infrastructure Enhancement
```markdown
#### Infrastructure/DevOps Feature
- [ ] **[Infrastructure Feature]** - [Description of ops improvement]
  - **Priority**: [High/Medium/Future]
  - **Deployment Impact**: [CI/CD/Container/Kubernetes changes]
  - **Monitoring**: [Metrics/Logging/Alerting enhancements]
  - **Automation**: [Automated processes/Scripts]
  - **Reliability**: [Availability/Recovery improvements]
  - **Documentation**: [Runbook/Documentation updates]
  - **Training**: [Operational knowledge requirements]
  - **Implementation Files**: [Config/Scripts/Helm charts]
```

## Integration with Existing Atlas DNS Commands

### Workflow with atlas_do_work
```bash
# After adding TODOs with atlas_todo:
# 1. atlas_do_work picks up TODO items for implementation
# 2. TODOs should be well-defined enough for implementation
# 3. Include all necessary context for development

prepare_for_implementation() {
    local todo_item="$1"
    echo "=== TODO Implementation Readiness ==="
    echo "1. Requirements clearly defined: [Yes/No]"
    echo "2. Acceptance criteria specified: [Yes/No]"
    echo "3. Technical approach outlined: [Yes/No]"
    echo "4. Dependencies identified: [Yes/No]"
    echo "5. Testing approach defined: [Yes/No]"
    
    if [ "$(echo $todo_item | grep -c 'Priority.*Critical')" -gt 0 ]; then
        echo "⚠️  CRITICAL TODO: Consider immediate implementation with atlas_do_work"
    fi
}
```

### Workflow with atlas_bug_fix
```bash
# When bugs reveal missing features:
# 1. Use atlas_bug_fix to address the immediate bug
# 2. Use atlas_todo to track related feature improvements
# 3. Prevent similar bugs with proactive TODO items

convert_bug_to_todo() {
    local bug_description="$1"
    echo "🔄 Converting bug context to TODO item:"
    echo "1. What feature would prevent this bug?"
    echo "2. What improvement would detect this earlier?"
    echo "3. What tooling would help prevent recurrence?"
}
```

### Workflow with atlas_bug_compress
```bash
# Keep TODO list organized:
# 1. Use atlas_bug_compress concepts for TODO organization
# 2. Regularly review and prioritize TODO items
# 3. Archive completed items with implementation details

organize_todo_list() {
    local todo_count=$(grep -c "^- \[ \]" todo.md)
    echo "📊 TODO Organization Status:"
    echo "- Total open items: $todo_count"
    echo "- Critical items: $(grep -c "Priority.*Critical" todo.md)"
    echo "- High priority items: $(grep -c "Priority.*High" todo.md)"
    
    if [ $todo_count -gt 50 ]; then
        echo "📋 CONSIDER: Organize TODO list - may need categorization review"
    fi
}
```

## TODO Item Quality Standards

### Minimum Information Requirements
1. **Clear Title**: Specific and actionable
2. **Description**: What needs to be done and why
3. **Priority Level**: Appropriate priority assessment
4. **Effort Estimate**: Small/Medium/Large/XL
5. **Category**: Proper categorization for organization
6. **Success Criteria**: How to know when it's complete

### Enhanced Information (When Available)
1. **Technical Approach**: Suggested implementation strategy
2. **Dependencies**: What must be done first
3. **Performance Targets**: Specific metrics to achieve
4. **Integration Points**: What systems will be affected
5. **Testing Strategy**: How to verify completion

### TODO Item Validation Checklist
- [ ] Title is specific and actionable
- [ ] Priority correctly assessed based on impact/urgency
- [ ] Category matches the type of work
- [ ] Description provides sufficient context
- [ ] Success criteria are measurable
- [ ] Dependencies identified if applicable
- [ ] Effort estimate is realistic
- [ ] Not a duplicate of existing TODO

## Automated TODO Examples

### DNS Protocol Enhancement
```bash
# Example: User requests DNSSEC automation
add_dnssec_automation_todo() {
    cat >> todo.md << 'EOF'

#### DNS Protocol Implementation
- [ ] **DNSSEC Automation Enhancement** - Complete one-click zone signing with automatic key rotation
  - **Priority**: High
  - **RFC Compliance**: RFC 4033, 4034, 4035, 6781 (key rollover)
  - **Protocol Support**: DNSSEC for all zone types
  - **Query Types**: All types with DNSSEC validation
  - **Performance Target**: <2s zone signing, <1ms validation overhead
  - **Backward Compatibility**: Maintain unsigned zone support
  - **Testing Requirements**: DNSSEC validation suite, interop testing
  - **Security Implications**: Key management, HSM integration
  - **Implementation Files**: src/dns/dnssec.rs, src/dns/authority.rs
  - **Added**: 2025-09-03
  - **Rationale**: User request for production DNSSEC deployment

EOF
}
```

### Web Interface Enhancement
```bash
# Example: User requests real-time dashboard
add_realtime_dashboard_todo() {
    cat >> todo.md << 'EOF'

#### Web Interface/API Feature
- [ ] **Real-time Dashboard Updates** - WebSocket-based live data updates for monitoring dashboard
  - **Priority**: Medium
  - **User Interface**: Dashboard with live charts and metrics
  - **API Endpoints**: WebSocket /ws/metrics, enhanced /api/metrics
  - **Authentication**: Session-based WebSocket auth
  - **Data Model**: Time-series metrics streaming
  - **Real-time Updates**: Query rates, response times, error rates
  - **Mobile Support**: Responsive real-time charts
  - **Accessibility**: Screen reader support for live data
  - **Implementation Files**: src/web/server.rs, templates/dashboard.html
  - **Added**: 2025-09-03
  - **Rationale**: Replace 30-second refresh with instant updates

EOF
}
```

### Performance Optimization
```bash
# Example: User reports slow response times
add_performance_optimization_todo() {
    cat >> todo.md << 'EOF'

#### Performance Optimization
- [ ] **Query Processing Pipeline Optimization** - Reduce DNS query response time from 55ms to <10ms
  - **Priority**: Critical
  - **Performance Metric**: Query response latency
  - **Current Performance**: 55ms average response time
  - **Target Performance**: <10ms average, <20ms P99
  - **Bottleneck Analysis**: Network I/O, string parsing, cache lookup overhead
  - **Optimization Strategy**: Zero-copy buffers, async processing, cache optimization
  - **Resource Impact**: Potential memory increase for buffer pools
  - **Scalability**: Enable higher QPS with lower latency
  - **Implementation Files**: src/dns/server.rs, src/dns/buffer.rs, src/dns/cache.rs
  - **Added**: 2025-09-03
  - **Rationale**: Production performance requirements for enterprise deployment

EOF
}
```

### Security Enhancement
```bash
# Example: Security audit reveals need for enhancement
add_security_enhancement_todo() {
    cat >> todo.md << 'EOF'

#### Security Implementation
- [ ] **DNS Firewall with Threat Intelligence** - Real-time malware/phishing domain blocking
  - **Priority**: Critical
  - **Security Domain**: Threat protection, DNS filtering
  - **Threat Model**: Malware C&C, phishing, data exfiltration via DNS
  - **Compliance**: Enterprise security requirements
  - **Implementation Approach**: Real-time threat feeds, response policy zones
  - **Performance Impact**: <1ms additional latency for threat lookup
  - **Backward Compatibility**: Optional feature, disabled by default
  - **Testing Requirements**: Threat detection accuracy, false positive rate
  - **Implementation Files**: src/dns/firewall.rs, src/dns/threat_intel.rs
  - **Added**: 2025-09-03
  - **Rationale**: Enterprise customers require advanced threat protection

EOF
}
```

## TODO Item Lifecycle Management

### Status Tracking
```bash
# Track TODO item progress
update_todo_status() {
    local todo_title="$1"
    local status="$2"  # "in-progress", "completed", "blocked", "cancelled"
    local details="$3"
    
    case $status in
        "in-progress")
            sed -i '' "s/\[ \] \*\*${todo_title}\*\*/\[~\] \*\*${todo_title}\*\* 🔄/" todo.md
            echo "# Started: $(date)" >> todo.md
            ;;
        "completed")
            sed -i '' "s/\[ \] \*\*${todo_title}\*\*/\[x\] \*\*${todo_title}\*\* ✅/" todo.md
            echo "# Completed: $(date) - $details" >> todo.md
            ;;
        "blocked")
            sed -i '' "s/\[ \] \*\*${todo_title}\*\*/\[!\] \*\*${todo_title}\*\* ⚠️/" todo.md
            echo "# Blocked: $(date) - $details" >> todo.md
            ;;
    esac
}
```

### Priority Adjustment
```bash
# Adjust TODO priority based on new information
adjust_todo_priority() {
    local todo_title="$1"
    local new_priority="$2"
    local justification="$3"
    
    echo "🔄 Adjusting priority for: $todo_title"
    echo "New priority: $new_priority"
    echo "Justification: $justification"
    echo "Date: $(date)"
    
    # Move item to appropriate section in todo.md
    # Update priority field in the item
}
```

### Dependency Management
```bash
# Track TODO dependencies
add_todo_dependency() {
    local todo_title="$1"
    local dependency="$2"
    
    echo "🔗 Adding dependency: $todo_title depends on $dependency"
    # Update TODO item with dependency information
}
```

## Automated TODO Analysis

### Feature Gap Analysis
```bash
# Analyze feature gaps from user feedback/bug reports
analyze_feature_gaps() {
    echo "=== Feature Gap Analysis ==="
    
    # Check for recurring themes in bugs that suggest missing features
    echo "Analyzing bug patterns for feature gaps..."
    grep -i "missing\|not implemented\|feature request" bugs.md | head -5
    
    # Check for API endpoints returning "not implemented"
    echo "Checking for unimplemented API endpoints..."
    grep -r "not implemented\|unimplemented" src/web/ | head -5
    
    # Check user feedback themes
    echo "Common user feedback themes that suggest TODO items:"
    echo "1. Performance improvements"
    echo "2. Additional DNS features"
    echo "3. Better monitoring/analytics"
    echo "4. Enhanced security"
}
```

### Priority Calibration
```bash
# Calibrate TODO priorities based on system status
calibrate_priorities() {
    echo "=== TODO Priority Calibration ==="
    
    # Check current system health
    local response_time=$(curl -s https://atlas.alpha.opensam.foundation/api/system/metrics | jq -r '.response_time_ms // "unknown"')
    echo "Current response time: ${response_time}ms"
    
    # Adjust priorities based on system performance
    if [ "$response_time" != "unknown" ] && [ "$response_time" -gt 50 ]; then
        echo "⚠️  High response time detected - prioritize performance TODO items"
    fi
    
    # Check security status
    local critical_bugs=$(grep -c "🔴.*CRITICAL" bugs.md)
    if [ "$critical_bugs" -gt 0 ]; then
        echo "🚨 Critical security issues found - prioritize security TODO items"
    fi
}
```

## Integration Examples

### From User Feature Request
```bash
# Example: User requests "Add support for DNS-over-QUIC"
process_user_feature_request() {
    local request="DNS-over-QUIC support"
    
    echo "=== Processing User Feature Request: $request ==="
    
    # Analyze technical requirements
    echo "Technical analysis:"
    echo "- Protocol: QUIC (RFC 9250)"
    echo "- Implementation: New transport layer"
    echo "- Integration: src/dns/doq.rs, server routing"
    echo "- Dependencies: QUIC library (quinn?)"
    echo "- Effort: Large (new protocol implementation)"
    
    # Determine priority
    echo "Priority assessment:"
    echo "- User demand: Medium (emerging protocol)"
    echo "- Technical complexity: High"
    echo "- Business value: Future-proofing"
    echo "- Priority: Medium-High"
    
    # Generate TODO item
    add_doq_protocol_todo
}
```

### From System Analysis
```bash
# Example: Performance monitoring reveals optimization opportunity
process_performance_analysis() {
    local metric="Cache hit rate below target"
    
    echo "=== Processing Performance Analysis: $metric ==="
    
    # Analyze current state
    echo "Current cache hit rate: 75% (target: 95%)"
    echo "Impact: Higher upstream query load"
    echo "Root cause: Suboptimal cache eviction algorithm"
    
    # Generate improvement TODO
    add_cache_optimization_todo
}
```

## Notes for Claude (Atlas DNS TODO Management)

- **ASSESS IMPACT CAREFULLY**: Consider security, performance, user experience, and technical debt
- **CATEGORIZE APPROPRIATELY**: Use the correct priority level and category for organization
- **PROVIDE SUFFICIENT DETAIL**: Include enough context for future implementation
- **CHECK FOR DUPLICATES**: Search existing todo.md to avoid duplicate entries
- **CONSIDER DEPENDENCIES**: Identify what must be completed first
- **ESTIMATE EFFORT REALISTICALLY**: Base estimates on similar completed work
- **LINK TO REQUIREMENTS**: Reference user requests, bug reports, or system analysis
- **MAINTAIN ORGANIZATION**: Add items to the appropriate section for easy discovery

Remember: TODO items drive the future development of Atlas DNS. Each item should represent a valuable improvement with clear acceptance criteria and implementation guidance. Focus on creating actionable, well-defined tasks that advance the system's capabilities while maintaining production quality and security standards.
````
