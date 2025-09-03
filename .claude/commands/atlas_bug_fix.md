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

## Bug Detection Checklist

### Phase 1: Security Audit
```rust
// Check for SQL injection (if database implemented)
// Check for command injection in DNS operations
// Verify all user inputs are sanitized
// Test authentication bypass attempts
// Verify CSRF protection
// Check for XSS in web templates
```

### Phase 2: API Testing
```bash
# Test authentication
curl -X POST https://atlas.alpha.opensam.foundation/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Test zone creation
curl -X POST https://atlas.alpha.opensam.foundation/api/v2/zones \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test.example.com","type":"master"}'

# Test DNS resolution
curl https://atlas.alpha.opensam.foundation/api/v2/resolve?name=example.com&type=A

# Test cache operations
curl https://atlas.alpha.opensam.foundation/cache
curl -X POST https://atlas.alpha.opensam.foundation/cache/clear
```

### Phase 3: Performance Testing
```bash
# Concurrent DNS queries
for i in {1..100}; do
  curl "https://atlas.alpha.opensam.foundation/api/v2/resolve?name=test$i.example.com" &
done

# Large zone import
curl -X POST https://atlas.alpha.opensam.foundation/api/v2/zones/bulk \
  -H "Content-Type: application/json" \
  -F "file=@large_zone.txt"

# Memory monitoring
curl https://atlas.alpha.opensam.foundation/api/system/metrics
```

### Phase 4: UI Testing
- Dashboard loading and data display
- Zone management interface
- User management pages
- Cache viewer functionality
- Login/logout flow
- Session persistence
- Mobile responsiveness

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

## Deployment Process

### 1. Fix Bugs in Place
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

### 6. Verify Deployment
```bash
# After 3+ minute wait, use version endpoint to verify deployment
curl https://atlas.alpha.opensam.foundation/api/version
# Compare timestamp with git commit time to confirm deployment

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

Remember: You're working on critical network infrastructure. Security and reliability are paramount. The live test environment is available for aggressive testing, but all fixes must be carefully implemented and verified before deployment.