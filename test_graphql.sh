#!/bin/bash

# Test GraphQL endpoint with sample queries

echo "Testing GraphQL Analytics API..."
echo "================================"

# Test 1: Server Stats Query
echo -e "\n1. Testing Server Stats Query..."
curl -X POST http://localhost:5380/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { serverStats { totalZones totalRecords cacheEntries uptimeSeconds version } }"
  }' 2>/dev/null | jq .

# Test 2: Cache Stats Query  
echo -e "\n2. Testing Cache Stats Query..."
curl -X POST http://localhost:5380/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { cacheStats { totalEntries hitCount missCount hitRate memoryUsage avgTtlSeconds evictionCount } }"
  }' 2>/dev/null | jq .

# Test 3: Query Type Distribution
echo -e "\n3. Testing Query Type Distribution..."
curl -X POST http://localhost:5380/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { queryTypeDistribution { queryType count percentage } }"
  }' 2>/dev/null | jq .

# Test 4: Top Domains
echo -e "\n4. Testing Top Domains Query..."
curl -X POST http://localhost:5380/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { topDomains(limit: 5) { domain queryCount percentage avgResponseTimeMs cacheHitRate } }"
  }' 2>/dev/null | jq .

# Test 5: Performance Analytics
echo -e "\n5. Testing Performance Analytics..."
curl -X POST http://localhost:5380/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { performanceAnalytics { avgResponseTimeMs p50ResponseTimeMs p95ResponseTimeMs p99ResponseTimeMs queriesPerSecond errorRate upstreamQueryRatio } }"
  }' 2>/dev/null | jq .

# Test 6: Health Analytics
echo -e "\n6. Testing Health Analytics..."
curl -X POST http://localhost:5380/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { healthAnalytics { healthScore uptimePercentage failedChecks componentHealth { name status lastCheck errorMessage } } }"
  }' 2>/dev/null | jq .

# Test 7: Security Analytics
echo -e "\n7. Testing Security Analytics..."
curl -X POST http://localhost:5380/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { securityAnalytics { totalEvents rateLimitEvents blockedQueries suspiciousDomains topThreatSources { ipAddress queryCount severity actionsTaken } } }"
  }' 2>/dev/null | jq .

# Test 8: Mutation - Clear Cache
echo -e "\n8. Testing Clear Cache Mutation..."
curl -X POST http://localhost:5380/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { clearCache }"
  }' 2>/dev/null | jq .

echo -e "\n================================"
echo "GraphQL API Tests Complete!"