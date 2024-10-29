#!/bin/bash
set -ex

echo "🛠️ Tearing up..."

# Create ns1, ns2, ns3, ns4
for ns in ns1 ns2 ns3 ns4; do
  if ip netns list | grep -q $ns; then
    ip netns del $ns
  fi
  ip netns add $ns
done

# Star topology, ns1 <-> ns2, ns1 <-> ns3, ns1 <-> ns4
for i in {2..4}; do
  ip link add veth1-$i type veth peer name veth${i}-1
  ip link set veth1-$i netns ns1
  ip link set veth${i}-1 netns ns$i
done

# Enable IP forwarding and SRv6
ip netns exec ns1 sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec ns1 sysctl -w net.ipv6.conf.all.seg6_enabled=1
for i in {2..4}; do
  ip netns exec ns1 sysctl -w net.ipv6.conf.veth1-$i.seg6_enabled=1
  ip netns exec ns$i sysctl -w net.ipv6.conf.all.forwarding=1
  ip netns exec ns$i sysctl -w net.ipv6.conf.all.seg6_enabled=1
  ip netns exec ns$i sysctl -w net.ipv6.conf.veth${i}-1.seg6_enabled=1
done

# Assign IP addresses
# ns1 <-> ns2: fc00:a::/32, ns1(12) <-> ns2(21)
# ns1 <-> ns3: fc00:b::/32, ns1(13) <-> ns3(31)
# ns1 <-> ns4: fc00:c::/32, ns1(14) <-> ns4(41)

ip netns exec ns1 ip -6 addr add fc00:a:12::/32 dev veth1-2
ip netns exec ns2 ip -6 addr add fc00:a:21::/32 dev veth2-1
ip netns exec ns1 ip -6 addr add fc00:b:13::/32 dev veth1-3
ip netns exec ns3 ip -6 addr add fc00:b:31::/32 dev veth3-1
ip netns exec ns1 ip -6 addr add fc00:c:14::/32 dev veth1-4
ip netns exec ns4 ip -6 addr add fc00:c:41::/32 dev veth4-1
echo "🔗 Assigned IP addresses!"

# Up interfaces
ip netns exec ns1 ip link set dev lo up
ip netns exec ns1 ip link set dev veth1-2 up
ip netns exec ns1 ip link set dev veth1-3 up
ip netns exec ns1 ip link set dev veth1-4 up
ip netns exec ns2 ip link set dev lo up
ip netns exec ns2 ip link set dev veth2-1 up
ip netns exec ns3 ip link set dev lo up
ip netns exec ns3 ip link set dev veth3-1 up
ip netns exec ns4 ip link set dev lo up
ip netns exec ns4 ip link set dev veth4-1 up
echo "🔗 Up interfaces!"

# Summary
# - ns1: veth1-2 (fc00:a:12::/32) <-> ns2: veth2-1 (fc00:a:21::/32)
# - ns1: veth1-3 (fc00:b:13::/32) <-> ns3: veth3-1 (fc00:b:31::/32)
# - ns1: veth1-4 (fc00:c:14::/32) <-> ns4: veth4-1 (fc00:c:41::/32)

# ip netns exec ns1 ip -6 route add fc00:a::/32 via fc00:a:21:: metric 1
# ip netns exec ns1 ip -6 route add fc00:b::/32 via fc00:b:31:: metric 1
# ip netns exec ns1 ip -6 route add fc00:c::/32 via fc00:c:41:: metric 1
ip netns exec ns2 ip -6 route add fc00:b::/32 via fc00:a:12:: metric 1
ip netns exec ns2 ip -6 route add fc00:c::/32 via fc00:a:12:: metric 1
# ip netns exec ns2 ip -6 route add fc00:a::/32 via fc00:a:12:: metric 1
ip netns exec ns3 ip -6 route add fc00:a::/32 via fc00:b:13:: metric 1
ip netns exec ns3 ip -6 route add fc00:c::/32 via fc00:b:13:: metric 1
# ip netns exec ns3 ip -6 route add fc00:b::/32 via fc00:b:13:: metric 1
ip netns exec ns4 ip -6 route add fc00:a::/32 via fc00:c:14:: metric 1
ip netns exec ns4 ip -6 route add fc00:b::/32 via fc00:c:14:: metric 1
# ip netns exec ns4 ip -6 route add fc00:c::/32 via fc00:c:14:: metric 1
echo "🔗 Set up routing!"

# # ping test
# sleep 2
# # ns2 -> ns3
# ip netns exec ns2 ping6 -c 3 fc00:b:31::
# # ns3 -> ns4
# ip netns exec ns3 ping6 -c 3 fc00:c:41::
# # ns4 -> ns2
# ip netns exec ns4 ping6 -c 3 fc00:a:21::
