#!/bin/bash

# Test script for HTTP request/response size tracking

echo "Testing HTTP Request/Response Size Tracking"
echo "==========================================="

# Start the server in the background (if not already running)
# cargo run --release &
# SERVER_PID=$!
# sleep 5

# Function to make a request and check logs
test_request() {
    local method=$1
    local path=$2
    local data=$3
    local headers=$4
    
    echo ""
    echo "Testing: $method $path"
    echo "Data: ${data:-none}"
    echo "Headers: ${headers:-none}"
    
    if [ "$method" = "GET" ]; then
        if [ -n "$headers" ]; then
            curl -X GET "http://localhost:8080$path" $headers -v 2>&1 | grep -E "< HTTP|> GET|Content-Length"
        else
            curl -X GET "http://localhost:8080$path" -v 2>&1 | grep -E "< HTTP|> GET|Content-Length"
        fi
    elif [ "$method" = "POST" ]; then
        if [ -n "$data" ]; then
            curl -X POST "http://localhost:8080$path" \
                -H "Content-Type: application/json" \
                -d "$data" \
                -v 2>&1 | grep -E "< HTTP|> POST|Content-Length"
        else
            curl -X POST "http://localhost:8080$path" -v 2>&1 | grep -E "< HTTP|> POST|Content-Length"
        fi
    fi
    
    # Check the logs for size tracking
    # tail -n 20 /var/log/atlas/atlas.log | grep -E "request_size|response_size"
}

# Test 1: Simple GET request
test_request "GET" "/" ""

# Test 2: GET request with referer header
test_request "GET" "/api/metrics" "" "-H 'Referer: https://example.com/dashboard'"

# Test 3: Small POST request
test_request "POST" "/auth/login" '{"username":"test","password":"test123"}'

# Test 4: Large POST request (1KB payload)
large_data=$(python3 -c "import json; print(json.dumps({'data': 'x' * 1000}))")
test_request "POST" "/api/test" "$large_data"

# Test 5: Very large POST request (10KB payload)
very_large_data=$(python3 -c "import json; print(json.dumps({'data': 'x' * 10000}))")
test_request "POST" "/api/test" "$very_large_data"

echo ""
echo "==========================================="
echo "Test completed. Check the server logs for request_size and response_size values."
echo ""
echo "To view metrics:"
echo "curl http://localhost:8080/metrics | grep -E 'atlas_web_request_size|atlas_web_response_size'"

# Clean up
# kill $SERVER_PID 2>/dev/null