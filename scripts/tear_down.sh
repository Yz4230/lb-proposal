#!/bin/bash
set -ex

echo "🛠️ Tearing down..."

for ns in ns1 ns2 ns3 ns4 ns5 ns6 ns7 ns8; do
  ip netns del $ns
done

echo "✅ Successfully torn down!"
