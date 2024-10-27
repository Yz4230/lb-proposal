#!/bin/bash
set -ex

echo "🛠️ Tearing down..."

ip netns del ns1
ip netns del ns2

echo "✅ Successfully torn down!"
