#!/bin/bash

# Sentry Integration Test Suite for Atlas DNS
# This script tests various error conditions to ensure Sentry is capturing events

URL="https://atlas.alpha.opensam.foundation"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔍 Atlas DNS Sentry Integration Test Suite${NC}"
echo "=============================================="
echo "Target: $URL"
echo "Started: $(date)"
echo ""

# Test 1: Authentication errors
echo -e "${YELLOW}Test 1: Authentication Errors${NC}"
echo "Testing invalid login credentials (should generate WebError::AuthenticationError)..."
RESULT1=$(curl -s -X POST "$URL/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=invaliduser&password=wrongpassword")
echo "Response: $RESULT1"
echo ""

# Test 2: Missing field errors  
echo -e "${YELLOW}Test 2: Missing Field Errors${NC}"
echo "Testing incomplete JSON data (should generate WebError::MissingField)..."
RESULT2=$(curl -s -X POST "$URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"password":"test"}')
echo "Response: $RESULT2"
echo ""

# Test 3: Protected resource access
echo -e "${YELLOW}Test 3: Authorization Errors${NC}"
echo "Testing access to protected resource without auth (should generate WebError::AuthenticationError)..."
RESULT3=$(curl -s "$URL/users" -w "\nHTTP Status: %{http_code}")
echo "Response: $RESULT3"
echo ""

# Test 4: DNS resolution (breadcrumbs)
echo -e "${YELLOW}Test 4: DNS Operations (Breadcrumbs)${NC}"
echo "Testing DNS resolution to generate breadcrumbs..."
RESULT4=$(curl -s "$URL/api/v2/resolve?name=example.com&type=A" -w "\nHTTP Status: %{http_code}")
echo "Response: $RESULT4"
echo ""

# Test 5: Malformed requests
echo -e "${YELLOW}Test 5: Invalid Requests${NC}"
echo "Testing malformed JSON request (should generate WebError::InvalidInput)..."
RESULT5=$(curl -s -X POST "$URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"invalid": json}')
echo "Response: $RESULT5"
echo ""

# Test 6: Server status check
echo -e "${YELLOW}Test 6: Server Health Check${NC}"
echo "Verifying server is running with Sentry integration..."
VERSION=$(curl -s "$URL/api/version")
echo "Server version: $VERSION"
echo ""

echo "=============================================="
echo -e "${GREEN}✅ Sentry Integration Tests Completed${NC}"
echo "Completed: $(date)"
echo ""
echo -e "${YELLOW}Expected Sentry Events:${NC}"
echo "• WebError::AuthenticationError (Test 1, 3)"
echo "• WebError::MissingField (Test 2)"  
echo "• DNS resolution breadcrumbs (Test 4)"
echo "• JSON parsing errors (Test 5)"
echo ""
echo "Check your Sentry dashboard at:"
echo "https://sentry.alpha.opensam.foundation/organizations/sam-international/issues/"
echo ""
echo -e "${YELLOW}Note:${NC} Events may take 1-2 minutes to appear in Sentry dashboard"