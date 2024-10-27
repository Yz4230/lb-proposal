#!/bin/bash
set -ex

echo "🛠️ Tearing up..."

# Create ns1, ns2
# if already exists, delete them
if ip netns list | grep -q ns1; then
  ip netns del ns1
fi
if ip netns list | grep -q ns2; then
  ip netns del ns2
fi
ip netns add ns1
ip netns add ns2

# Create veth1-2, veth2-1, veth2-3, veth3-2
ip link add veth1-2 type veth peer name veth2-1

ip link set veth1-2 netns ns1
ip link set veth2-1 netns ns2

# Enable IP forwarding and SRv6
ip netns exec ns1 sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec ns1 sysctl -w net.ipv6.conf.all.seg6_enabled=1
ip netns exec ns1 sysctl -w net.ipv6.conf.veth1-2.seg6_enabled=1
ip netns exec ns2 sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec ns2 sysctl -w net.ipv6.conf.all.seg6_enabled=1
ip netns exec ns2 sysctl -w net.ipv6.conf.veth2-1.seg6_enabled=1

# Assign IP addresses
ip netns exec ns1 ip -6 addr add fc00:a:12::/32 dev veth1-2
ip netns exec ns2 ip -6 addr add fc00:a:21::/32 dev veth2-1
echo "🔗 Assigned IP addresses!"

# Up interfaces
ip netns exec ns1 ip link set dev lo up
ip netns exec ns1 ip link set dev veth1-2 up
ip netns exec ns2 ip link set dev lo up
ip netns exec ns2 ip link set dev veth2-1 up
echo "🔗 Up interfaces!"

# Summary
# - ns1: veth1-2 (fc00:a:12::/64) <-> ns2: veth2-1 (fc00:a:21::/64)

ip netns exec ns1 ip -6 route add fc00:a::/32 via fc00:a:21::
# ip netns exec ns1 ip -6 route add fc00:a:ff::/48 encap bpf xmit obj bpf.o section test_data via fc00:a:ff::
ip netns exec ns2 ip -6 route add fc00:a::/32 via fc00:a:12::
echo "🔗 Set up routing!"
