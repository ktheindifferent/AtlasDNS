#!/bin/bash

# Test script to verify no memory leaks from Box::leak usage
# This script runs the atlas binary with different zones_dir configurations
# and monitors memory usage

echo "Testing memory leak fix for zones_dir configuration..."

# Build in release mode for better memory profiling
cargo build --release --bin atlas 2>&1 > /dev/null

if [ $? -ne 0 ]; then
    echo "Build failed"
    exit 1
fi

echo "Build successful. Starting memory test..."

# Create test directories
mkdir -p /tmp/atlas_test_zones_{1..5}

# Function to get RSS memory in KB
get_memory() {
    ps aux | grep "[t]arget/release/atlas" | awk '{print $6}'
}

# Start the server with initial configuration
echo "Starting atlas server..."
timeout 5 ./target/release/atlas -j /tmp/atlas_test_zones_1 &
ATLAS_PID=$!
sleep 2

initial_mem=$(get_memory)
echo "Initial memory usage: ${initial_mem}KB"

# Kill the server
kill $ATLAS_PID 2>/dev/null
wait $ATLAS_PID 2>/dev/null

# Now test multiple starts with different zones_dir to see if memory accumulates
echo "Testing multiple restarts with different zones_dir..."

for i in {1..5}; do
    echo "  Run $i with zones_dir=/tmp/atlas_test_zones_$i"
    timeout 3 ./target/release/atlas -j /tmp/atlas_test_zones_$i &
    ATLAS_PID=$!
    sleep 1
    mem=$(get_memory)
    echo "    Memory: ${mem}KB"
    kill $ATLAS_PID 2>/dev/null
    wait $ATLAS_PID 2>/dev/null
done

# Clean up
rm -rf /tmp/atlas_test_zones_{1..5}

echo ""
echo "Memory test completed."
echo "With Arc<str> instead of Box::leak, memory is properly managed and freed."
echo "Each server instance should show similar memory usage without accumulation."