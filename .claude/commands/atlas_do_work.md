````markdown
# /atlas_do_work Command - Automated TODO Item Implementation for Atlas DNS

## Command Purpose
This command enables Claude to automatically work on items in the `todo.md` file by implementing features, fixing issues, and completing tasks directly in the Atlas DNS codebase. The agent has full access to the live deployment for testing and verification of completed work.

## Live Test Environment Details

### Production Environment
- **URL**: https://atlas.alpha.opensam.foundation/
- **Admin Access**: Full development access for feature testing
- **Purpose**: Test and verify completed TODO items
- **Permission**: Complete testing access - stress test new features extensively

### System Context
- **Language**: Rust (high-performance DNS server)
- **Framework**: Custom DNS protocol implementation with web interface
- **Architecture**: Modular design with src/dns/, src/web/, src/metrics/ components
- **Deployment**: CapRover with automatic Git deployment
- **Version Control**: Gitea (production), GitHub (backup)

## TODO Item Categories & Implementation Strategy

### 🛠️ UIX Implementation Tasks (Immediate Priority)
**Focus**: Replace placeholder implementations with real functionality

#### Dashboard & Monitoring
```rust
// Current State: Placeholder/hardcoded values
// Target: Real-time data collection and display

// Example: Cache hit rate calculation
// File: src/web/api_v2.rs or src/metrics/mod.rs
impl CacheMetrics {
    pub fn calculate_hit_rate(&self) -> f64 {
        // TODO: Replace hardcoded 75% with actual cache metrics
        // self.hits as f64 / (self.hits + self.misses) as f64
    }
}
```

#### DNS Security Features  
```rust
// Current State: UI exists, backend returns "Not implemented"
// Target: Complete implementation

// Example: DNSSEC Implementation
// File: src/dns/dnssec.rs
impl DnssecManager {
    pub fn sign_zone(&mut self, zone: &str) -> Result<(), DnssecError> {
        // TODO: Implement actual DNSSEC zone signing
        // Currently returns "Not implemented" error
    }
}
```

#### Protocol Support
```rust
// Current State: Partial implementation
// Target: Complete RFC compliance

// Example: DoH (DNS-over-HTTPS) completion
// File: src/dns/doh.rs
impl DohServer {
    pub fn handle_request(&self, req: HttpRequest) -> Result<DnsResponse, DohError> {
        // TODO: Complete RFC 8484 implementation
        // Missing: HTTP/2 support, proper error handling
    }
}
```

### 🚀 Performance Optimization Tasks
**Focus**: Achieve enterprise-grade performance metrics

#### Memory & Resource Management
```rust
// Target: Implement efficient memory pooling
// File: src/dns/buffer.rs or new src/memory/pool.rs
pub struct MemoryPool {
    // TODO: Implement pre-allocated buffer pools
    // Target: Zero-copy networking capabilities
}
```

#### Query Processing Optimization
```rust
// Target: Sub-10ms response times
// File: src/dns/server.rs
impl DnsServer {
    pub async fn process_query(&self, query: DnsQuery) -> DnsResponse {
        // TODO: Optimize hot path for performance
        // Current: ~55ms, Target: <10ms
    }
}
```

### 📊 Analytics & Real-time Features
**Focus**: Connect UI to live data sources

#### GraphQL Metrics Implementation
```rust
// Current State: Returns mock data
// Target: Real analytics with live data
// File: src/web/graphql.rs

#[graphql_object]
impl Query {
    async fn query_analytics(&self, timeframe: String) -> QueryAnalytics {
        // TODO: Replace mock data with real query statistics
        // Connect to metrics collector, calculate real percentiles
    }
}
```

## Implementation Workflow

### Phase 1: Assessment and Planning (Always Start Here)
```bash
# 1. Analyze current TODO items for implementation priority
grep -n "\[ \]" todo.md | head -10

# 2. Identify related source files for each TODO item
find src/ -name "*.rs" | xargs grep -l "unimplemented\|TODO\|Not implemented"

# 3. Check current system status to verify deployment stability
curl https://atlas.alpha.opensam.foundation/api/version

# 4. Review existing tests to understand current functionality
find tests/ -name "*.rs" | head -5

# 5. Capture baseline metrics before implementation
curl -s https://atlas.alpha.opensam.foundation/api/system/metrics | jq '.response_time_ms'
```

### Phase 2: Feature Implementation
```bash
# Implementation checklist for each TODO item:

# A. Identify the exact file and function to implement
# B. Understand the expected interface (struct signatures, return types)
# C. Implement core functionality with proper error handling
# D. Add necessary dependencies to Cargo.toml if required
# E. Write or update tests for the new functionality
# F. Update documentation/comments in the code

# Example implementation workflow:
# 1. Edit source file
vim src/dns/dnssec.rs

# 2. Add dependencies if needed
vim Cargo.toml

# 3. Build and test locally
cargo build --release
cargo test

# 4. Update integration tests
vim tests/dns_integration.rs
```

### Phase 3: Testing and Verification
```bash
# Comprehensive testing checklist:

# 1. Unit tests pass
cargo test --lib

# 2. Integration tests pass  
cargo test --test integration_test

# 3. Local functionality test
./target/release/atlas --skip-privilege-check --test-mode

# 4. Code quality checks
cargo clippy -- -D warnings
cargo fmt --check

# 5. Performance verification (if applicable)
cargo bench
```

### Phase 4: Deployment and Production Verification
```bash
# Deployment workflow:

# 1. Update version timestamp
./update_version.sh

# 2. Commit all changes with descriptive message
git add .
git commit -m "feat: implement [TODO_ITEM_DESCRIPTION]

- Added [specific functionality]
- Fixed [specific issues]
- Performance: [metrics if applicable]
- Tests: [coverage information]

TODO: Mark as completed in todo.md
Tested: [testing details]"

# 3. Deploy to production
git push gitea master

# 4. Wait for deployment (3+ minutes)
sleep 200

# 5. Verify deployment
DEPLOYED_VERSION=$(curl -s https://atlas.alpha.opensam.foundation/api/version | jq -r '.code_version')
echo "Deployed version: $DEPLOYED_VERSION"

# 6. Test new functionality on live server
# [Feature-specific testing commands]

# 7. Performance verification
curl -s https://atlas.alpha.opensam.foundation/api/system/metrics | jq '.response_time_ms'

# 8. Update TODO item status in todo.md
sed -i '' 's/\[ \] \*\*Feature Name\*\*/\[x\] \*\*Feature Name\*\*/' todo.md
```

## TODO Item Implementation Patterns

### Pattern 1: Dashboard Metric Implementation
```markdown
# TODO Item Example:
- [ ] **Cache Hit Rate Calculation** - Replace hardcoded 75% with real metrics

# Implementation Steps:
1. File: src/metrics/cache.rs or src/dns/cache.rs
2. Add hit/miss counters to cache operations
3. Implement calculation method
4. Connect to API endpoint in src/web/api_v2.rs
5. Update dashboard template to display real data
6. Test with cache operations and verify accuracy
```

### Pattern 2: Security Feature Implementation  
```markdown
# TODO Item Example:
- [ ] **DNSSEC Implementation** - Backend currently returns "Not implemented"

# Implementation Steps:
1. File: src/dns/dnssec.rs (already exists)
2. Implement zone signing with ECDSA P-256
3. Add DNSSEC validation for queries
4. Update API endpoints to handle DNSSEC operations
5. Add configuration options
6. Test with signed zones and verify signatures
7. Update UI to show DNSSEC status correctly
```

### Pattern 3: Protocol Implementation
```markdown
# TODO Item Example:
- [ ] **DoH (DNS-over-HTTPS)** - Complete RFC 8484 implementation

# Implementation Steps:
1. File: src/dns/doh.rs (exists but incomplete)
2. Add HTTP/2 support for better performance
3. Implement proper content negotiation
4. Add error handling for malformed requests
5. Update routing in src/web/server.rs
6. Test with DoH-compatible clients
7. Performance testing for sub-10ms target
```

### Pattern 4: API Enhancement
```markdown
# TODO Item Example:
- [ ] **GraphQL Analytics API** - Connect to real data sources

# Implementation Steps:
1. File: src/web/graphql.rs
2. Replace mock data with real metrics collection
3. Implement time-series data aggregation
4. Add caching for expensive queries
5. Connect to Prometheus metrics if available
6. Test query performance and accuracy
7. Update frontend to consume real data
```

## Success Criteria for TODO Implementation

### Code Quality Standards
```rust
// All implementations must follow these patterns:

// 1. Proper error handling (no unwrap() or expect() calls)
match operation_result {
    Ok(value) => value,
    Err(e) => {
        log::error!("Operation failed: {}", e);
        return Err(CustomError::from(e));
    }
}

// 2. Comprehensive logging
log::info!("Starting feature operation: {}", operation_id);
log::debug!("Processing parameters: {:?}", params);

// 3. Performance considerations
use std::time::Instant;
let start = Instant::now();
// ... operation ...
let duration = start.elapsed();
log::info!("Operation completed in: {:?}", duration);

// 4. Thread safety where applicable
use std::sync::{Arc, RwLock};
let shared_data = Arc::new(RwLock::new(data));
```

### Testing Requirements
```rust
// Every TODO implementation must include:

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_feature_basic_functionality() {
        // Test basic operation
    }

    #[test]
    fn test_new_feature_error_conditions() {
        // Test error handling
    }

    #[test]
    fn test_new_feature_performance() {
        // Verify performance requirements
    }

    #[tokio::test]
    async fn test_new_feature_async_operations() {
        // Test async functionality if applicable
    }
}
```

### Performance Benchmarks
```rust
// Performance-critical features need benchmarks:

#[cfg(test)]
mod benches {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_new_feature(b: &mut Bencher) {
        b.iter(|| {
            // Benchmark the new feature
        });
    }
}
```

## TODO Item Prioritization Matrix

### Immediate Implementation (Start with these)
1. **Dashboard Real Data** - High impact, medium effort
   - Cache hit rate calculation
   - Active user tracking
   - Real-time updates

2. **Security Features** - High impact, high effort
   - DNSSEC implementation
   - DNS Firewall rules
   - DDoS protection logic

3. **API Completeness** - High impact, medium effort
   - GraphQL real data
   - API key management
   - Request metrics

### Secondary Implementation
1. **Protocol Support** - Medium impact, high effort
   - DoH completion
   - DoT finishing
   - DoQ implementation

2. **Performance Features** - Medium impact, medium effort
   - Memory pooling
   - Zero-copy networking
   - Cache optimization

### Future Implementation
1. **Advanced Features** - High impact, very high effort
   - GeoDNS backend
   - Load balancing pools
   - AI/ML features

2. **Integration Features** - Low impact, medium effort
   - Webhook system
   - Certificate management
   - Third-party integrations

## Automated TODO Progress Tracking

### Progress Update Script
```bash
#!/bin/bash
# Update todo.md with completion status

update_todo_completion() {
    local todo_description="$1"
    local status="$2"  # "complete" or "in-progress"
    local commit_hash="$3"
    local date="$4"
    
    if [ "$status" == "complete" ]; then
        # Mark as completed with details
        sed -i '' "s/\[ \] \*\*${todo_description}\*\*/\[x\] \*\*${todo_description}\*\* ✅ (${date} - ${commit_hash})/" todo.md
    elif [ "$status" == "in-progress" ]; then
        # Mark as in progress
        sed -i '' "s/\[ \] \*\*${todo_description}\*\*/\[~\] \*\*${todo_description}\*\* 🔄 (Started ${date})/" todo.md
    fi
}

# Usage examples:
# update_todo_completion "Cache Hit Rate Calculation" "complete" "abc123def" "2025-09-03"
# update_todo_completion "DNSSEC Implementation" "in-progress" "" "2025-09-03"
```

### Integration with Git Workflow
```bash
# Automatically update TODO status on successful deployment
post_deployment_todo_update() {
    local feature_name="$1"
    local commit_hash=$(git rev-parse --short HEAD)
    local current_date=$(date +%Y-%m-%d)
    
    # Mark as completed in todo.md
    update_todo_completion "$feature_name" "complete" "$commit_hash" "$current_date"
    
    # Commit the todo.md update
    git add todo.md
    git commit -m "docs: mark $feature_name as completed

- Implementation completed in commit $commit_hash
- Deployed and verified: $(date)
- Status: Production ready"
    
    git push gitea master
}
```

## Quality Assurance Checklist

### Before Implementation
- [ ] TODO item clearly understood and scope defined
- [ ] Related source files identified and analyzed
- [ ] Existing tests reviewed for context
- [ ] Dependencies and requirements understood
- [ ] Performance targets identified

### During Implementation
- [ ] Code follows Rust best practices and project conventions
- [ ] Proper error handling implemented (no panics)
- [ ] Logging added for debugging and monitoring
- [ ] Thread safety considered for concurrent operations
- [ ] Memory safety verified (no unsafe code without justification)

### After Implementation
- [ ] Unit tests written and passing
- [ ] Integration tests updated if needed
- [ ] Code review completed (self-review minimum)
- [ ] Performance verified against targets
- [ ] Documentation updated
- [ ] Deployment successful and verified

### Production Verification
- [ ] Feature working correctly on live server
- [ ] No performance regression detected
- [ ] Error rates within acceptable limits
- [ ] Logs show expected behavior
- [ ] Monitoring shows healthy metrics

## Integration with Existing Commands

### Workflow with atlas_bug_fix
```bash
# 1. Use atlas_bug_fix to ensure system stability
# 2. Use atlas_do_work to implement TODO items
# 3. Use atlas_bug_compress to clean up tracking files
# 4. Use atlas_todo to add new items discovered during implementation
```

### Workflow with atlas_todo
```bash
# During implementation, if new TODO items are discovered:
# 1. Use atlas_todo to document them immediately
# 2. Continue with current implementation
# 3. Return to new items in next work session
```

### Workflow with atlas_bug_report
```bash
# If bugs are discovered during implementation:
# 1. Use atlas_bug_report to document the issue
# 2. Decide whether to fix immediately or continue with TODO
# 3. Ensure bug is tracked before proceeding
```

## Notes for Claude (Atlas DNS TODO Implementation)

- **VERIFY TODO SCOPE**: Always read the full TODO item and understand the expected implementation
- **CHECK EXISTING CODE**: Look for partial implementations, related functions, and interface requirements
- **IMPLEMENT COMPLETELY**: Don't create placeholder implementations - fully implement the feature
- **TEST THOROUGHLY**: Every TODO implementation must be tested on the live server
- **UPDATE PROGRESS**: Always mark completed items in todo.md with commit hash and date
- **MAINTAIN QUALITY**: Follow all existing code quality standards and error handling patterns
- **CONSIDER PERFORMANCE**: TODO items often relate to performance improvements - verify targets are met
- **DOCUMENT DECISIONS**: Add comments explaining implementation choices and any trade-offs made

Remember: Atlas DNS is production infrastructure serving enterprise clients. Every TODO implementation must meet production quality standards with comprehensive testing and verification on the live deployment system. Focus on reliability, performance, and maintainability in all implementations.
````
