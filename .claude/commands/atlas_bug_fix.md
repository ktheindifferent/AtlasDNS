# /atlas_bug_fix Command - Automated Bug Detection and Fixing for Atlas DNS

## Command Purpose
This command enables Claude to automatically detect, analyze, and fix bugs in the Atlas DNS system by working directly with the existing Rust codebase. The agent has full access to test the live deployment to identify issues and implement fixes in the actual source files without creating duplicates or enhanced versions.

## Live Test Environment Details

### Web Application
- **URL**: https://atlas.alpha.opensam.foundation/
- **Admin Credentials**: admin / admin123 (default development credentials)
- **Purpose**: Test server for bug detection and API/UI testing
- **Permission**: Full testing access granted - feel free to stress test and probe for issues

### System Details
- **Language**: Rust
- **Web Framework**: tiny_http with SSL support
- **Template Engine**: Handlebars
- **Authentication**: SHA256 password hashing (needs upgrade to bcrypt)
- **Storage**: In-memory with file-based persistence
- **Deployment**: Docker via CapRover with automatic Git deployment

## System Architecture Overview

### Core Components

#### Main Entry Points
- **Main Binary**: `src/bin/atlas.rs` - Primary DNS server application
- **CLI Binary**: `src/bin/atlas-cli.rs` - Command-line interface
- **Library Root**: `src/lib.rs` - Core library definitions

#### DNS Server (`src/dns/`)
- **Protocol**: `protocol.rs`, `buffer.rs`, `query_type.rs`, `result_code.rs`
- **Server**: `server.rs`, `server_enhanced.rs`, `context.rs`
- **Authority**: `authority.rs` - Zone management
- **Cache**: `cache.rs`, `adaptive_cache.rs` - Response caching
- **Security**: `security/` directory with DDoS, firewall, rate limiting
- **Modern DNS**: `doh.rs` (DNS-over-HTTPS), `dot.rs` (DNS-over-TLS)
- **DNSSEC**: `dnssec.rs` - DNSSEC implementation
- **ACME**: `acme.rs` - Automatic certificate management

#### Web Interface (`src/web/`)
- **Server**: `server.rs` - HTTP/HTTPS server with routing
- **Authentication**: `users.rs`, `sessions.rs` - User and session management
- **API v2**: `api_v2.rs` - RESTful API endpoints
- **GraphQL**: `graphql.rs` - GraphQL API
- **Templates**: `templates/` - 28+ Handlebars templates
- **Authority API**: `authority.rs` - Zone management endpoints
- **Cache API**: `cache.rs` - Cache management endpoints

#### Supporting Modules
- **Metrics**: `src/metrics/` - Real-time analytics and monitoring
- **Kubernetes**: `src/k8s/` - Kubernetes operator support
- **Privilege**: `src/privilege_escalation.rs` - Port 53 binding

### In-Memory Data Structures
- **User Database**: `HashMap<String, User>` with RwLock
- **Session Store**: `HashMap<String, Session>` with RwLock
- **DNS Cache**: TTL-based cache with adaptive algorithms
- **Zone Files**: File-based storage in configurable directory

## Known Critical Issues to Check

### 🔴 CRITICAL Security Vulnerabilities

1. **Password Hashing Weakness** ✅ FIXED
   - **File**: `src/web/users.rs:148-156`
   - **Issue**: Using SHA256 instead of bcrypt/Argon2
   - **Fix**: Implement proper password hashing with salt
   - **Status**: Fixed with bcrypt + legacy migration support
   ```rust
   // Fixed code:
   pub fn hash_password(password: &str) -> String {
       hash(password, DEFAULT_COST).expect("Failed to hash password")
   }
   ```

2. **Session Cookie Security** ✅ FIXED
   - **File**: `src/web/sessions.rs:113-121`
   - **Issue**: Missing Secure flag for HTTPS, weak SameSite setting
   - **Fix**: Add Secure flag when SSL enabled, use SameSite=Strict
   - **Status**: Fixed with automatic SSL detection

3. **Default Admin Credentials** ✅ FIXED
   - **File**: `src/web/users.rs:126-136`
   - **Issue**: Hardcoded admin/admin123 credentials
   - **Fix**: Generate random password on first run or require setup
   - **Status**: Fixed with random 16-character password generation

4. **Case-Sensitive Cookie Header Bug** ✅ FIXED
   - **File**: `src/web/sessions.rs:37-40`
   - **Issue**: Cookie header comparison fails with lowercase "cookie" from proxies
   - **Status**: Fixed and verified working in production

### 🟠 HIGH Priority API & Functionality Issues

1. **JSON Authentication Parsing** ⚠️ DEPLOYMENT ISSUE
   - **File**: `src/web/server.rs:863-869`
   - **Issue**: JSON requests returning "username" instead of proper error messages
   - **Root Cause**: JSON parsing failure falls back to form parsing, causing MissingField error
   - **Fix Applied**: Improved error handling for JSON parsing failures
   - **Status**: Code fixed but deployment verification needed
   - **Workaround**: Use form-based authentication instead of JSON

2. **API Endpoints to Test**
   ```bash
   # Zone Management
   GET/POST /authority
   GET/POST/DELETE /authority/{zone}
   
   # Cache Management  
   GET /cache
   POST /cache/clear
   
   # User Management
   GET/POST /users
   GET/PUT/DELETE /users/{id}
   
   # Authentication
   POST /auth/login
   POST /auth/logout
   
   # API v2
   GET /api/v2/zones
   POST /api/v2/zones
   GET/PUT/DELETE /api/v2/zones/{zone}
   GET/POST /api/v2/zones/{zone}/records
   
   # GraphQL
   POST /graphql
   WS /graphql (subscriptions)
   
   # Security APIs
   GET /api/firewall/rules
   GET /api/rate-limiting/status
   GET /api/security/metrics
   ```

2. **DNS Resolution Issues**
   - **Files**: `src/dns/resolve.rs`, `src/dns/client.rs`
   - Check recursive resolution with forwarding
   - Verify DNSSEC validation
   - Test DNS-over-HTTPS/TLS functionality

3. **Memory Management**
   - **Files**: `src/dns/cache.rs`, `src/web/users.rs`
   - Check for memory leaks in cache operations
   - Verify session cleanup
   - Monitor long-running operations

### 🟡 MEDIUM Priority Code Quality Issues

1. **Error Handling**
   - Many `unwrap()` calls that could panic
   - Missing error context in Result types
   - Generic error messages to users

2. **Compilation Warnings**
   - 154+ warnings in latest build
   - Unused variables and imports
   - Mutable variables that don't need to be

3. **Missing Features**
   - No persistence across restarts (in-memory only)
   - PostgreSQL integration incomplete
   - Redis caching not implemented

### 🟢 LOW Priority Improvements

1. **Documentation**
   - Missing API documentation
   - Incomplete README sections
   - No inline code documentation

2. **Test Coverage**
   - Limited unit test coverage
   - Missing integration tests for API
   - No security test suite

## Sentry Integration Details

### Error Monitoring System
- **Sentry DSN**: `http://5ec005d5f2b84ed5a5d4ce190900dc5e@sentry.alpha.opensam.foundation/4`
- **Dashboard**: https://sentry.alpha.opensam.foundation/organizations/sam-international/issues/
- **Service Tags**: atlas-dns, version tracking, component-based categorization
- **Error Categories**: Error (critical), Warning (security), Info (operational)

### Sentry API Integration
```bash
# Sentry API Base URL
SENTRY_API="https://sentry.alpha.opensam.foundation/api/0"
SENTRY_TOKEN="your_auth_token_here"  # Replace with actual token

# Get recent issues
curl -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=24h&query=is:unresolved"

# Get issue details
curl -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/issues/{ISSUE_ID}/"

# Get issue events
curl -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/issues/{ISSUE_ID}/events/"
```

## Bug Detection Checklist

### Phase 0: Sentry Issue Analysis (NEW)
**Priority**: Run FIRST to identify real-world production issues
```bash
# 1. Query recent unresolved issues
echo "=== Fetching Recent Sentry Issues ==="
ISSUES=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=24h&query=is:unresolved" | \
  jq -r '.[] | "\(.id): \(.title) (\(.count) occurrences)"')

echo "$ISSUES"

# 2. Get top error patterns
echo "=== Top Error Patterns ==="
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=7d&sort=freq" | \
  jq -r '.[] | select(.count > 10) | "\(.count)x: \(.title) - \(.culprit)"' | head -10

# 3. Check for new panic events
echo "=== Recent Panic Events ==="
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?query=event.type:error%20level:fatal" | \
  jq -r '.[] | "\(.firstSeen): \(.title)"' | head -5

# 4. Security-related errors
echo "=== Security Events ==="
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?query=tag:error_type:authentication_error%20OR%20tag:error_type:authorization_error" | \
  jq -r '.[] | "\(.count)x: \(.title)"'

# 5. DNS operation errors
echo "=== DNS Operation Errors ==="
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?query=tag:component:dns%20OR%20tag:dns_operation:forward" | \
  jq -r '.[] | "\(.count)x: \(.title) - DNS: \(.tags.dns_operation // "N/A")"'
```

**Actions Based on Sentry Data**:
1. **High Frequency Errors (>50 occurrences/day)**: Immediate fix required
2. **Panic Events**: Critical - investigate stack traces and fix root cause
3. **Authentication Errors**: May indicate brute force attacks or credential issues
4. **DNS Forwarding Errors**: Check upstream server connectivity
5. **New Error Types**: Investigate recent code changes or environmental factors

**Sentry-Guided Bug Prioritization**:
```bash
# Get issue details with context
get_issue_details() {
  ISSUE_ID=$1
  echo "=== Issue Details: $ISSUE_ID ==="
  
  # Basic issue info
  curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/issues/$ISSUE_ID/" | \
    jq -r '{"title": .title, "count": .count, "level": .level, "status": .status, "firstSeen": .firstSeen, "lastSeen": .lastSeen}'
  
  # Get recent events with stack traces
  echo "=== Recent Events ==="
  curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/issues/$ISSUE_ID/events/" | \
    jq -r '.[] | {"timestamp": .dateCreated, "message": .message, "tags": .tags, "user": .user, "request": .request}'
  
  # Get stack trace for latest event
  LATEST_EVENT=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/issues/$ISSUE_ID/events/" | jq -r '.[0].id')
    
  if [ "$LATEST_EVENT" != "null" ]; then
    echo "=== Stack Trace ==="
    curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
      "$SENTRY_API/events/$LATEST_EVENT/" | \
      jq -r '.entries[] | select(.type == "exception") | .data.values[].stacktrace.frames[] | "\(.filename):\(.lineNo) in \(.function)"'
  fi
}

# Usage: get_issue_details "12345"
```

### Phase 1: Security Audit
```rust
// Check for SQL injection (if database implemented)
// Check for command injection in DNS operations
// Verify all user inputs are sanitized
// Test authentication bypass attempts
// Verify CSRF protection
// Check for XSS in web templates
```

### Phase 2: API Testing (Enhanced with Sentry Monitoring)
```bash
# Before API testing - capture baseline error count
echo "=== Baseline Error Count ==="
BASELINE_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=1h" | jq -r 'length')
echo "Current unresolved issues: $BASELINE_ERRORS"

# Test authentication (should generate Sentry events for failures)
echo "=== Testing Authentication ==="
curl -X POST https://atlas.alpha.opensam.foundation/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Trigger authentication errors intentionally
curl -X POST https://atlas.alpha.opensam.foundation/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"baduser","password":"badpass"}'

# Test zone creation
echo "=== Testing Zone Management ==="
curl -X POST https://atlas.alpha.opensam.foundation/api/v2/zones \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test.example.com","type":"master"}'

# Test invalid zone creation (should generate errors)
curl -X POST https://atlas.alpha.opensam.foundation/api/v2/zones \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}'

# Test DNS resolution (generates breadcrumbs)
echo "=== Testing DNS Resolution ==="
curl https://atlas.alpha.opensam.foundation/api/v2/resolve?name=example.com&type=A

# Test invalid DNS queries
curl https://atlas.alpha.opensam.foundation/api/v2/resolve?name=invalid..domain&type=INVALID

# Test cache operations
echo "=== Testing Cache Operations ==="
curl https://atlas.alpha.opensam.foundation/cache
curl -X POST https://atlas.alpha.opensam.foundation/cache/clear

# Wait for Sentry to process events (2-3 minutes)
echo "=== Waiting for Sentry Processing ==="
sleep 180

# Check for new errors after testing
echo "=== Post-Test Error Analysis ==="
NEW_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=1h" | jq -r 'length')
echo "New unresolved issues: $((NEW_ERRORS - BASELINE_ERRORS))"

# Get any new high-frequency errors
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=1h&sort=freq" | \
  jq -r '.[] | select(.count > 5) | "HIGH FREQ: \(.count)x \(.title) - \(.culprit)"'
```

### Phase 3: Performance Testing (Enhanced with Sentry Monitoring)
```bash
# Capture performance baseline
echo "=== Performance Test Baseline ==="
PERF_BASELINE=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?query=tag:dns_operation:forward" | jq -r 'length')
echo "DNS operation errors before test: $PERF_BASELINE"

# Concurrent DNS queries (may trigger rate limiting or timeouts)
echo "=== Concurrent DNS Load Test ==="
for i in {1..100}; do
  curl "https://atlas.alpha.opensam.foundation/api/v2/resolve?name=test$i.example.com" &
done
wait

# Large payload test (may trigger memory or parsing errors)  
echo "=== Large Payload Test ==="
# Create large test data
cat > /tmp/large_zone.txt << EOF
testzone.example.com.	300	IN	A	1.2.3.4
EOF

# Repeat the record 1000 times
for i in {1..1000}; do
  echo "record$i.testzone.example.com.	300	IN	A	1.2.3.$((i % 255))" >> /tmp/large_zone.txt
done

# Test large zone import
curl -X POST https://atlas.alpha.opensam.foundation/api/v2/zones/bulk \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/tmp/large_zone.txt"

# Memory monitoring
echo "=== Memory and System Monitoring ==="
curl https://atlas.alpha.opensam.foundation/api/system/metrics

# Stress test with rapid-fire requests (may trigger errors)
echo "=== Rapid Request Stress Test ==="
for i in {1..50}; do
  curl -s https://atlas.alpha.opensam.foundation/api/version > /dev/null &
  curl -s https://atlas.alpha.opensam.foundation/cache > /dev/null &
  curl -s https://atlas.alpha.opensam.foundation/api/v2/resolve?name=stress$i.test &
done
wait

# Wait for Sentry processing
echo "=== Waiting for Performance Test Results ==="
sleep 180

# Analyze performance-related errors
echo "=== Performance Error Analysis ==="
PERF_AFTER=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?query=tag:dns_operation:forward" | jq -r 'length')
echo "DNS operation errors after test: $((PERF_AFTER - PERF_BASELINE))"

# Check for timeout/memory/rate limit errors
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=30m&query=level:error" | \
  jq -r '.[] | select(.count > 3) | "PERFORMANCE ISSUE: \(.count)x \(.title) - \(.tags.error_type // "unknown")"'

# Check for new panic events (memory exhaustion, etc.)
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=30m&query=level:fatal" | \
  jq -r '.[] | "CRITICAL: \(.title) - First seen: \(.firstSeen)"'

# Clean up
rm -f /tmp/large_zone.txt
```

### Phase 4: UI Testing (Enhanced with Sentry JavaScript Integration)
```bash
# UI testing with browser automation and Sentry monitoring
echo "=== UI Testing with Error Monitoring ==="

# Check for JavaScript errors in Sentry (if browser SDK is integrated)
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?query=platform:javascript" | \
  jq -r '.[] | "JS ERROR: \(.title) - \(.count) occurrences"'

# Manual UI testing checklist
echo "Manual UI Testing (check browser console and Sentry dashboard):"
echo "1. Dashboard loading: https://atlas.alpha.opensam.foundation/"
echo "2. Zone management: https://atlas.alpha.opensam.foundation/zones"  
echo "3. User management: https://atlas.alpha.opensam.foundation/users"
echo "4. Cache viewer: https://atlas.alpha.opensam.foundation/cache"
echo "5. Login flow: Test authentication with invalid credentials"
echo "6. Session persistence: Check session timeout behavior"
echo "7. Mobile responsiveness: Test on different screen sizes"
```

### Phase 5: Sentry-Driven Issue Resolution (NEW)
**Priority**: Use Sentry data to guide bug fixes
```bash
# Automated issue triage and resolution workflow
sentry_guided_bug_fix() {
  echo "=== Sentry-Guided Bug Fix Workflow ==="
  
  # 1. Get high-priority issues
  HIGH_PRIORITY=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=7d&sort=freq&query=is:unresolved" | \
    jq -r '.[:5] | .[] | "\(.id)|\(.title)|\(.count)|\(.level)|\(.culprit)"')
  
  echo "=== Top 5 Issues Requiring Attention ==="
  echo "$HIGH_PRIORITY" | while IFS='|' read -r id title count level culprit; do
    echo "Priority: $count occurrences - $level"
    echo "Issue: $title"  
    echo "Location: $culprit"
    echo "Sentry URL: https://sentry.alpha.opensam.foundation/organizations/sam-international/issues/$id/"
    echo "---"
  done
  
  # 2. Get detailed context for top issue
  TOP_ISSUE_ID=$(echo "$HIGH_PRIORITY" | head -1 | cut -d'|' -f1)
  if [ -n "$TOP_ISSUE_ID" ]; then
    echo "=== Analyzing Top Issue: $TOP_ISSUE_ID ==="
    get_issue_details "$TOP_ISSUE_ID"
    
    # Suggest file locations to investigate
    echo "=== Suggested Investigation ==="
    curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
      "$SENTRY_API/issues/$TOP_ISSUE_ID/events/" | \
      jq -r '.[0].entries[] | select(.type == "exception") | .data.values[].stacktrace.frames[] | .filename' | \
      sort -u | head -5 | while read -r file; do
        echo "Investigate: $file"
      done
  fi
  
  # 3. Check for regression patterns
  echo "=== Regression Analysis ==="
  curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=24h&query=is:unresolved%20firstSeen:>$(date -d '24 hours ago' --iso-8601)" | \
    jq -r '.[] | "NEW ISSUE: \(.title) - First seen: \(.firstSeen)"'
}

# Usage in bug fixing session
sentry_guided_bug_fix
```

## Fix Priority Guidelines

### Immediate (Do First)
1. **Password Hashing** - Upgrade from SHA256 to bcrypt
   ```rust
   // In src/web/users.rs
   use bcrypt::{hash, verify, DEFAULT_COST};
   
   pub fn hash_password(password: &str) -> String {
       hash(password, DEFAULT_COST).expect("Failed to hash password")
   }
   
   pub fn verify_password(password: &str, hash: &str) -> bool {
       verify(password, hash).unwrap_or(false)
   }
   ```

2. **Session Security** - Add Secure flag and improve SameSite
   ```rust
   // In src/web/sessions.rs
   pub fn create_session_cookie(token: &str, secure: bool) -> Header {
       let mut cookie = format!(
           "session_token={}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict",
           token
       );
       if secure {
           cookie.push_str("; Secure");
       }
       Header::from_bytes(&b"Set-Cookie"[..], cookie.as_bytes())
           .expect("Failed to create session cookie header")
   }
   ```

3. **Remove Default Admin** - Generate on first run
   ```rust
   // In src/web/users.rs
   fn create_default_admin(&mut self) {
       use rand::Rng;
       let password: String = rand::thread_rng()
           .sample_iter(&Alphanumeric)
           .take(16)
           .map(char::from)
           .collect();
       
       log::warn!("Generated admin password: {}", password);
       log::warn!("Please change this password immediately!");
       // ... rest of admin creation
   }
   ```

### Short-term (Within Session)
1. Fix compilation warnings
2. Improve error handling
3. Add input validation
4. Implement rate limiting
5. Add CSRF protection

### Long-term (Document for Later)
1. Implement PostgreSQL persistence
2. Add Redis caching layer
3. Complete DNSSEC implementation
4. Add comprehensive test suite
5. Implement proper logging

## Bug Tracking and Progress Management

### Progress File Location
- **File**: `bugs.md` in project root
- **Format**: Markdown with structured sections

### Progress File Template
```markdown
# Atlas DNS Bug Tracking and Fixes

## Session: [Date/Time]
**Environment**: https://atlas.alpha.opensam.foundation/
**Codebase**: Rust-based DNS server with web interface

## Critical Security Issues (🔴) 

### 1. Weak Password Hashing ❌
- **File**: src/web/users.rs:148-156
- **Issue**: Using SHA256 instead of bcrypt
- **Impact**: Passwords vulnerable to rainbow table attacks
- **Fix Required**: Implement bcrypt with proper salt
- **Status**: Not started

### 2. Session Cookie Security ❌
- **File**: src/web/sessions.rs:113-121
- **Issue**: Missing Secure flag, weak SameSite
- **Impact**: Session hijacking risk
- **Fix Required**: Add Secure flag, use SameSite=Strict
- **Status**: Not started

### 3. Default Admin Credentials ❌
- **File**: src/web/users.rs:126-136
- **Issue**: Hardcoded admin/admin123
- **Impact**: Unauthorized admin access
- **Fix Required**: Generate random password
- **Status**: Not started

## High Priority Issues (🟠)

### 1. Case-Insensitive Cookie Headers ✅
- **File**: src/web/sessions.rs:37-40
- **Issue**: Failed with lowercase "cookie" header
- **Fix Applied**: Added case-insensitive comparison
- **Testing**: Verified on live server
- **Status**: Fixed in commit 6857bbb24

## Fixed Issues ✅

[Move items here as they're completed]

## Testing Results

### API Endpoints
- [ ] /auth/login - Authentication
- [ ] /api/v2/zones - Zone management
- [ ] /api/v2/records - Record management
- [ ] /cache - Cache operations
- [ ] /users - User management

### Security Tests
- [ ] SQL injection attempts
- [ ] XSS payload testing
- [ ] Authentication bypass
- [ ] Session hijacking
- [ ] CSRF attacks

## Deployment History
- [Date/Time] - Commit: [hash] - Description
```

## Enhanced Workflow with Sentry Integration

### Starting a Sentry-Guided Bug Fix Session

**ALWAYS START WITH SENTRY ANALYSIS** - This is now Phase 0, run before any manual testing:

```bash
# 1. Run automated Sentry bug detection
./sentry_bug_detection.sh

# 2. Export Sentry token for API access
export SENTRY_AUTH_TOKEN="your_sentry_auth_token_here"

# 3. Review generated bug report
cat /tmp/sentry_bug_report.md

# 4. Identify top priority issues from Sentry dashboard
# https://sentry.alpha.opensam.foundation/organizations/sam-international/issues/
```

**Decision Tree Based on Sentry Data:**

1. **If Fatal Errors (Panics) Found**: 
   - Priority: CRITICAL - Fix immediately
   - Focus: Stack traces, investigate crash causes
   - Files: Usually in src/dns/ or src/web/

2. **If High-Frequency Errors (>50/week)**:
   - Priority: HIGH - Fix within session
   - Focus: Root cause analysis of repeated failures
   - Approach: Add proper error handling, validation

3. **If New Issues (first seen <24h)**:
   - Priority: MEDIUM - May indicate regression
   - Focus: Recent code changes, deployment issues
   - Approach: Review recent commits, rollback if needed

4. **If Authentication/Authorization Errors**:
   - Priority: SECURITY - Investigate for attacks
   - Focus: Login patterns, IP analysis
   - Files: src/web/users.rs, src/web/sessions.rs

**Sentry-Guided Testing Scripts Available:**
- `sentry_bug_detection.sh` - Automated issue analysis
- `sentry_integration_test.sh` - Error generation for testing

## Deployment Process

### 1. Fix Bugs in Place (Enhanced with Sentry Confirmation)
```bash
# Edit actual source files
vim src/web/users.rs  # Fix password hashing
vim src/web/sessions.rs  # Fix cookie security
```

### 2. Test Locally
```bash
# Build and test
cargo build --release
cargo test

# Run locally if possible
./target/release/atlas --skip-privilege-check
```

### 3. Commit Changes
```bash
git add .
git commit -m "fix: critical security vulnerabilities

- Upgrade password hashing from SHA256 to bcrypt
- Add Secure flag to session cookies
- Remove hardcoded admin credentials
- Fix case-insensitive cookie headers

Security: High priority fixes for production
Tested: https://atlas.alpha.opensam.foundation/"
```

### 4. Deploy to Production
```bash
# Push to gitea (CapRover deployment server) - THIS IS CRITICAL
git push gitea master

# Note: origin is GitHub, gitea is the actual deployment server
# Only gitea pushes trigger automatic deployment
```

### 5. Wait for Deployment
**CRITICAL**: Wait EXACTLY 3+ minutes for deployment to complete
- Do NOT test immediately after push
- Deployment server needs time to build and deploy
- Set a timer for 3 minutes minimum
- **Note**: Deployment may take longer than 3 minutes in some cases
- Use `/api/version` endpoint to verify deployment completion

### 6. Verify Deployment (Enhanced with Sentry Monitoring)
```bash
# After 3+ minute wait, use version endpoint to verify deployment
curl https://atlas.alpha.opensam.foundation/api/version
# Compare timestamp with git commit time to confirm deployment

# Capture pre-fix error baseline from Sentry
BASELINE_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=1h" | jq -r 'length')
echo "Baseline errors before testing: $BASELINE_ERRORS"

# Test specific fixes
curl -X POST https://atlas.alpha.opensam.foundation/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"[new_password]"}'

# Check for security headers
curl -I https://atlas.alpha.opensam.foundation/ | grep -i "set-cookie"

# Test form-based authentication (more reliable than JSON)
curl -X POST https://atlas.alpha.opensam.foundation/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"

# Test case-insensitive headers
curl -H "cookie: test=value" https://atlas.alpha.opensam.foundation/api/version

# Intentionally trigger errors to test Sentry reporting
echo "Testing Sentry error reporting..."
curl -X POST https://atlas.alpha.opensam.foundation/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent","password":"testing"}'

# Wait for Sentry processing
sleep 120

# Verify fix effectiveness in Sentry
echo "=== Post-Fix Sentry Analysis ==="
AFTER_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=1h" | jq -r 'length')
echo "Errors after testing: $AFTER_ERRORS"

# Check if specific error types were reduced (example for authentication errors)
CURRENT_AUTH_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=24h&query=tag:error_type:authentication_error" | \
  jq -r 'map(select(.count > 10)) | length')
echo "High-frequency auth errors (>10 occurrences): $CURRENT_AUTH_ERRORS"

# Confirm no new critical errors were introduced
NEW_CRITICAL=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
  "$SENTRY_API/projects/sam-international/4/issues/?statsPeriod=30m&query=level:fatal" | \
  jq -r 'length')
if [ "$NEW_CRITICAL" -gt 0 ]; then
  echo "⚠️  WARNING: $NEW_CRITICAL new critical errors detected!"
  echo "Review: https://sentry.alpha.opensam.foundation/organizations/sam-international/issues/"
else
  echo "✅ No new critical errors introduced"
fi
```

## Testing Scripts

### Comprehensive Security Test Suite
```bash
#!/bin/bash
# security_verification_test.sh - Complete verification of all security fixes

URL="https://atlas.alpha.opensam.foundation"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔒 Atlas DNS Security Verification Test Suite"
echo "=============================================="
echo "Target: $URL"
echo "Started: $(date)"
echo ""

# Test 1: Version endpoint (deployment verification)
echo -e "${YELLOW}Test 1: Version Endpoint${NC}"
VERSION_RESPONSE=$(curl -s "$URL/api/version")
if echo "$VERSION_RESPONSE" | grep -q "code_version"; then
    echo -e "${GREEN}✅ Version endpoint working${NC}"
    echo "   Response: $VERSION_RESPONSE"
else
    echo -e "${RED}❌ Version endpoint failed${NC}"
    echo "   Response: $VERSION_RESPONSE"
fi
echo ""

# Test 2: Default admin credentials (should fail)
echo -e "${YELLOW}Test 2: Default Admin Credentials (should fail)${NC}"
AUTH_RESPONSE=$(curl -s -X POST "$URL/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=admin123")

if echo "$AUTH_RESPONSE" | grep -q "Invalid credentials"; then
    echo -e "${GREEN}✅ Default admin credentials disabled${NC}"
    echo "   Response: $AUTH_RESPONSE"
else
    echo -e "${RED}❌ Default admin credentials still working!${NC}"
    echo "   Response: $AUTH_RESPONSE"
fi
echo ""

# Test 3: JSON authentication error handling
echo -e "${YELLOW}Test 3: JSON Authentication Error Handling${NC}"
JSON_AUTH_RESPONSE=$(curl -s -X POST "$URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d '{"username":"admin","password":"admin123"}')

if echo "$JSON_AUTH_RESPONSE" | grep -q "Invalid"; then
    echo -e "${GREEN}✅ JSON authentication working correctly${NC}"
    echo "   Response: $JSON_AUTH_RESPONSE"
elif echo "$JSON_AUTH_RESPONSE" | grep -q "username"; then
    echo -e "${RED}❌ JSON authentication still broken (old behavior)${NC}"
    echo "   Response: $JSON_AUTH_RESPONSE"
else
    echo -e "${YELLOW}⚠️  JSON authentication: unexpected response${NC}"
    echo "   Response: $JSON_AUTH_RESPONSE"
fi
echo ""

# Test 4: Case-insensitive cookie headers
echo -e "${YELLOW}Test 4: Case-Insensitive Cookie Headers${NC}"
COOKIE_RESPONSE=$(curl -s -H "cookie: test=value" "$URL/api/version")
if echo "$COOKIE_RESPONSE" | grep -q "code_version"; then
    echo -e "${GREEN}✅ Case-insensitive cookie headers working${NC}"
    echo "   Lowercase 'cookie' header accepted"
else
    echo -e "${RED}❌ Case-insensitive cookie headers failed${NC}"
    echo "   Response: $COOKIE_RESPONSE"
fi
echo ""

echo "=============================================="
echo "🔒 Security Verification Complete"
echo "Tested: $(date)"
echo ""
```

### Performance Test Suite
```bash
#!/bin/bash
# performance_test.sh

URL="https://atlas.alpha.opensam.foundation"

echo "Testing Atlas DNS Performance..."

# Concurrent requests
echo "1. Testing concurrent requests..."
for i in {1..100}; do
  curl -s "$URL/api/v2/resolve?name=test$i.example.com" &
done
wait

# Large payload
echo "2. Testing large payload..."
python3 -c "print('{\"name\":\"' + 'a'*10000 + '.example.com\"}')" | \
  curl -X POST "$URL/api/v2/zones" \
    -H "Content-Type: application/json" \
    -d @-

# Memory usage
echo "3. Checking memory usage..."
curl "$URL/api/system/metrics" | jq '.memory'

echo "Performance tests complete!"
```

## Expected Deliverables

1. **Bug Report**: Complete assessment in `bugs.md`
2. **Security Fixes**: Critical vulnerabilities patched ✅
3. **Performance Improvements**: Memory leaks and bottlenecks resolved
4. **Code Quality**: Compilation warnings fixed
5. **Test Results**: Evidence of successful fixes ✅
6. **Documentation**: Updated with findings and recommendations ✅
7. **Deployed Code**: All fixes live on production server ✅ (mostly)

## Success Criteria

✅ The bug fix session is successful when:
1. All critical security vulnerabilities are patched ✅
2. Authentication system is secure (bcrypt, secure cookies) ✅
3. No default credentials remain ✅
4. API endpoints handle edge cases properly (partial - JSON auth pending)
5. Memory leaks are identified and fixed
6. Compilation warnings are resolved
7. All fixes pass testing on live server ✅ (mostly)
8. Changes are deployed to production ✅
9. Documentation is updated in `bugs.md` ✅
10. Live verification confirms fixes work ✅ (critical fixes verified)

## Notes for Claude

### Starting a Session
1. **ALWAYS START**: Read `bugs.md` first to check previous progress
2. **Check current issues**: Review what's already been fixed
3. **Prioritize**: Security → Performance → Code Quality

### During Development
1. **Edit in place**: Modify actual source files, not copies
2. **No new files**: Work within existing structure
3. **Test thoroughly**: Use the live server for verification
4. **Document everything**: Update `bugs.md` continuously

### Deployment Rules
1. **Commit properly**: Use descriptive commit messages
2. **Push to deploy**: Git push triggers automatic deployment
3. **WAIT 3 MINUTES**: Never test before 3-minute wait
4. **Verify deployment**: Check live server after waiting
5. **Document results**: Update `bugs.md` with outcomes

### Important Reminders
- This is production DNS infrastructure - be careful but thorough
- The test server is yours to probe aggressively
- Focus on security first, then performance
- **ALL CRITICAL SECURITY FIXES ARE NOW DEPLOYED** ✅
- SHA256 password hashing vulnerability is FIXED ✅
- Cookie security headers are FIXED ✅
- Default admin credentials are DISABLED ✅
- Case-insensitive headers are WORKING ✅
- All fixes must be tested on https://atlas.alpha.opensam.foundation/
- Deployment takes 3+ minutes minimum - sometimes longer
- **Use `/api/version` endpoint to verify deployments**
- **Form-based authentication is more reliable than JSON for testing**
- **Remember: `git push gitea master` for actual deployment (not origin)**

## Lessons Learned from This Session

### Deployment Verification
1. **Version Endpoint is Essential**: The `/api/version` endpoint is critical for verifying deployments
2. **Deployment Can Take >3 Minutes**: Some deployments took 5-10 minutes to complete
3. **Git Remote Matters**: `gitea` remote triggers deployment, `origin` is just GitHub backup
4. **Timestamp Comparison**: Compare `/api/version` timestamp with `git log` commit time

### Authentication Testing
1. **Form Data More Reliable**: `application/x-www-form-urlencoded` works more consistently than JSON
2. **JSON Parsing Can Fail**: JSON authentication may have bugs that form authentication doesn't
3. **Error Responses Vary**: Different content types may return different error formats
4. **Default Credentials Test**: "Invalid credentials" response confirms security fix worked

### Security Fix Verification
1. **Test Multiple Ways**: Use both positive and negative test cases
2. **Check Headers**: Case sensitivity, cookie attributes, security flags
3. **Verify Error Messages**: Proper error handling indicates code quality
4. **Cross-Reference Code**: Match live behavior with code changes

### Documentation Updates
1. **Real-Time Updates**: Update `bugs.md` throughout the session, not just at the end
2. **Status Tracking**: Use clear status indicators (✅❌⚠️⏳)
3. **Commit References**: Always include commit hashes for traceability
4. **Test Results**: Document both successful and failed tests

## Summary: Enhanced Sentry-Driven Bug Fix Workflow

### 🔄 **New Workflow Order**
1. **Phase 0**: Sentry Issue Analysis (ALWAYS START HERE)
2. **Phase 1**: Security Audit (guided by Sentry security events)
3. **Phase 2**: API Testing (enhanced with Sentry monitoring)
4. **Phase 3**: Performance Testing (with error rate monitoring)
5. **Phase 4**: UI Testing (with JavaScript error tracking)
6. **Phase 5**: Sentry-Driven Resolution (automated issue triage)

### 📊 **Sentry Integration Benefits**
- **Real-world Issue Detection**: Focus on actual production problems
- **Error Frequency Analysis**: Prioritize fixes by impact
- **Stack Trace Guidance**: Know exactly which files to investigate
- **Regression Detection**: Identify new issues from recent changes
- **Fix Verification**: Confirm error rates decrease after deployment
- **Performance Monitoring**: Track DNS operation failures

### 🛠 **Available Tools**
- `sentry_bug_detection.sh` - Automated Sentry analysis and bug prioritization
- `sentry_integration_test.sh` - Comprehensive error testing for Sentry validation
- Sentry Dashboard: https://sentry.alpha.opensam.foundation/organizations/sam-international/issues/
- Sentry API: Full programmatic access to error data and analytics

### 🎯 **Success Criteria (Enhanced)**
A bug fix session is successful when:
✅ All critical Sentry issues (fatal level) are resolved
✅ High-frequency errors (>50/week) are addressed
✅ No new critical errors introduced during testing
✅ Error rates decrease in Sentry monitoring post-deployment
✅ All fixes pass both manual testing AND Sentry confirmation
✅ Documentation updated with Sentry-guided findings

### ⚡ **Quick Start for Bug Fix Session**
```bash
# 1. Set up Sentry access
export SENTRY_AUTH_TOKEN="your_sentry_token"

# 2. Run automated analysis
./sentry_bug_detection.sh

# 3. Review priorities
cat /tmp/sentry_bug_report.md

# 4. Focus on top issues from Sentry dashboard

# 5. Fix -> Deploy -> Verify in Sentry -> Repeat
```

**Remember**: You're working on critical network infrastructure. Security and reliability are paramount. The live test environment is available for aggressive testing, but all fixes must be carefully implemented and verified before deployment. **With Sentry integration, you now have production error data to guide your bug fixing efforts and confirm fix effectiveness.**