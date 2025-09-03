#!/bin/bash

# Sentry-Integrated Bug Detection Script for Atlas DNS
# This script uses Sentry API to identify production issues and guide bug fixing

# Configuration
SENTRY_API="https://sentry.alpha.opensam.foundation/api/0"
SENTRY_TOKEN="${SENTRY_AUTH_TOKEN:-your_token_here}"  # Set via environment variable
ATLAS_URL="https://atlas.alpha.opensam.foundation"
PROJECT_ID="sam-international/4"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Sentry-Guided Bug Detection for Atlas DNS${NC}"
echo "=================================================="
echo "Sentry API: $SENTRY_API"
echo "Atlas URL: $ATLAS_URL"
echo "Started: $(date)"
echo ""

# Check Sentry API connection
if ! curl -s -H "Authorization: Bearer $SENTRY_TOKEN" "$SENTRY_API/projects/$PROJECT_ID/" > /dev/null 2>&1; then
    echo -e "${RED}❌ Cannot connect to Sentry API. Check SENTRY_AUTH_TOKEN environment variable.${NC}"
    echo "Set token with: export SENTRY_AUTH_TOKEN=your_sentry_token"
    exit 1
fi

echo -e "${GREEN}✅ Connected to Sentry API${NC}"
echo ""

# Function to get issue details
get_issue_details() {
    local issue_id=$1
    echo -e "${YELLOW}=== Issue Details: $issue_id ===${NC}"
    
    # Basic issue info
    curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
        "$SENTRY_API/issues/$issue_id/" | \
        jq -r '{
            "title": .title, 
            "count": .count, 
            "level": .level, 
            "status": .status, 
            "firstSeen": .firstSeen, 
            "lastSeen": .lastSeen,
            "culprit": .culprit
        }'
    
    # Get latest event with stack trace
    local latest_event=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
        "$SENTRY_API/issues/$issue_id/events/" | jq -r '.[0].id // empty')
    
    if [ -n "$latest_event" ]; then
        echo -e "${YELLOW}Latest Stack Trace:${NC}"
        curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
            "$SENTRY_API/events/$latest_event/" | \
            jq -r '.entries[]? | select(.type == "exception") | .data.values[]?.stacktrace.frames[]? | "\(.filename):\(.lineNo) in \(.function)"' | head -10
    fi
    echo ""
}

# Phase 0: Sentry Issue Analysis
echo -e "${YELLOW}Phase 0: Production Issue Analysis${NC}"
echo "=================================="

# 1. Get recent unresolved issues
echo "1. Recent Unresolved Issues (24h):"
RECENT_ISSUES=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?statsPeriod=24h&query=is:unresolved" | \
    jq -r '.[] | "\(.id): \(.title) (\(.count) occurrences)"')

if [ -n "$RECENT_ISSUES" ]; then
    echo "$RECENT_ISSUES" | head -10
else
    echo "No recent issues found"
fi
echo ""

# 2. High-frequency errors (7 days)
echo "2. High-Frequency Errors (7d, >10 occurrences):"
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?statsPeriod=7d&sort=freq" | \
    jq -r '.[] | select(.count > 10) | "\(.count)x: \(.title) - \(.culprit)"' | head -5
echo ""

# 3. Critical errors (panics, fatal)
echo "3. Critical Errors (Fatal level):"
CRITICAL_ISSUES=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?query=level:fatal" | \
    jq -r '.[] | "\(.id)|\(.title)|\(.firstSeen)"')

if [ -n "$CRITICAL_ISSUES" ]; then
    echo "$CRITICAL_ISSUES" | while IFS='|' read -r id title first_seen; do
        echo "CRITICAL: $title (First: $first_seen)"
        echo "  URL: https://sentry.alpha.opensam.foundation/organizations/sam-international/issues/$id/"
    done
else
    echo "No critical errors found"
fi
echo ""

# 4. Security-related errors
echo "4. Security-Related Errors:"
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?query=tag:error_type:authentication_error%20OR%20tag:error_type:authorization_error" | \
    jq -r '.[] | "\(.count)x: \(.title)"' | head -5
echo ""

# 5. DNS operation errors
echo "5. DNS Operation Errors:"
curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?query=tag:component:dns%20OR%20tag:dns_operation:forward" | \
    jq -r '.[] | "\(.count)x: \(.title) - DNS: \(.tags.dns_operation // "N/A")"' | head -5
echo ""

# Get top issue for detailed analysis
TOP_ISSUE_ID=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?statsPeriod=7d&sort=freq&query=is:unresolved" | \
    jq -r '.[0].id // empty')

if [ -n "$TOP_ISSUE_ID" ]; then
    echo -e "${BLUE}=== Detailed Analysis of Top Issue ===${NC}"
    get_issue_details "$TOP_ISSUE_ID"
fi

# Phase 1: Targeted Testing Based on Sentry Data
echo -e "${YELLOW}Phase 1: Targeted Testing Based on Issues${NC}"
echo "=========================================="

# Test authentication errors if they exist
AUTH_ISSUES=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?query=tag:error_type:authentication_error" | \
    jq -r 'length')

if [ "$AUTH_ISSUES" -gt 0 ]; then
    echo "Testing authentication (found $AUTH_ISSUES auth issues):"
    curl -s -X POST "$ATLAS_URL/auth/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=testuser&password=wrongpass" | head -1
fi

# Test DNS operations if there are DNS errors
DNS_ISSUES=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?query=tag:dns_operation:forward" | \
    jq -r 'length')

if [ "$DNS_ISSUES" -gt 0 ]; then
    echo "Testing DNS operations (found $DNS_ISSUES DNS issues):"
    curl -s "$ATLAS_URL/api/v2/resolve?name=example.com&type=A" | head -1
fi

echo ""

# Phase 2: Fix Recommendations
echo -e "${YELLOW}Phase 2: Fix Recommendations${NC}"
echo "============================="

# Analyze error patterns and suggest fixes
echo "Analyzing error patterns for fix suggestions..."

# Check for common error types
MISSING_FIELD_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?query=tag:error_type:missing_field" | \
    jq -r 'length')

IO_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?query=tag:error_type:io_error" | \
    jq -r 'length')

SERIALIZATION_ERRORS=$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?query=tag:error_type:serialization_error" | \
    jq -r 'length')

echo "Error Type Analysis:"
echo "- Missing Field Errors: $MISSING_FIELD_ERRORS (suggests input validation issues)"
echo "- IO Errors: $IO_ERRORS (suggests network/file system issues)"
echo "- Serialization Errors: $SERIALIZATION_ERRORS (suggests JSON/data format issues)"
echo ""

# Recommendations based on error counts
if [ "$MISSING_FIELD_ERRORS" -gt 5 ]; then
    echo -e "${RED}HIGH PRIORITY: Missing field validation${NC}"
    echo "  Fix: Improve form validation in src/web/users.rs and API endpoints"
fi

if [ "$IO_ERRORS" -gt 3 ]; then
    echo -e "${RED}HIGH PRIORITY: IO error handling${NC}"
    echo "  Fix: Add better error handling in src/dns/client.rs and file operations"
fi

if [ "$SERIALIZATION_ERRORS" -gt 3 ]; then
    echo -e "${RED}MEDIUM PRIORITY: JSON serialization${NC}"
    echo "  Fix: Validate JSON schemas in src/web/server.rs API endpoints"
fi

echo ""

# Phase 3: Generate Bug Report
echo -e "${YELLOW}Phase 3: Generated Bug Report${NC}"
echo "=============================="

cat > /tmp/sentry_bug_report.md << EOF
# Sentry-Generated Bug Report - $(date)

## Summary
Based on Sentry analysis of Atlas DNS production errors:

### Critical Issues
$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?query=level:fatal" | \
    jq -r '.[] | "- **\(.title)** - \(.count) occurrences, first seen: \(.firstSeen)"')

### High-Frequency Issues (>10 occurrences)
$(curl -s -H "Authorization: Bearer $SENTRY_TOKEN" \
    "$SENTRY_API/projects/$PROJECT_ID/issues/?statsPeriod=7d&sort=freq" | \
    jq -r '.[] | select(.count > 10) | "- **\(.title)** - \(.count) occurrences in \(.culprit)"' | head -5)

### Recommended Actions
1. **Immediate**: Fix any fatal-level errors (panics)
2. **Short-term**: Address high-frequency errors (>50/week)  
3. **Medium-term**: Improve error handling for common patterns
4. **Long-term**: Add monitoring alerts for new error types

### Sentry Dashboard
View detailed analysis: https://sentry.alpha.opensam.foundation/organizations/sam-international/issues/

Generated by: Sentry Bug Detection Script
EOF

echo "Bug report generated: /tmp/sentry_bug_report.md"
echo ""

# Summary
echo -e "${GREEN}=== Bug Detection Complete ===${NC}"
echo "✅ Analyzed production errors from Sentry"
echo "✅ Identified high-priority issues" 
echo "✅ Generated targeted test scenarios"
echo "✅ Created bug report with recommendations"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Review generated bug report: /tmp/sentry_bug_report.md"
echo "2. Investigate top issues in Sentry dashboard"
echo "3. Implement fixes based on error frequency and severity"
echo "4. Test fixes using integrated test scenarios"
echo "5. Monitor Sentry for issue resolution confirmation"
echo ""
echo "Completed: $(date)"