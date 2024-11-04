#!/bin/bash
set -ex

echo "🛠️ Tearing up..."

# Create ns1, ns2, ns3, ns4, ns5, ns6
for ns in ns1 ns2 ns3 ns4 ns5 ns6; do
  if ip netns list | grep -q $ns; then
    ip netns del $ns
  fi
  ip netns add $ns
done

# Topology:
#            ns3
#           /   \
# ns1 -- ns2     ns5 -- ns6
#           \   /
#            ns4
#
# Interfaces:
# - ns1(veth-12,fc00:a:12/32) -- ns2(veth-21,fc00:a:21/32)
# - ns2(veth-23,fc00:b:23/32) -- ns3(veth-32,fc00:b:32/32)
# - ns2(veth-24,fc00:c:24/32) -- ns4(veth-42,fc00:c:42/32)
# - ns3(veth-35,fc00:d:35/32) -- ns5(veth-53,fc00:d:53/32)
# - ns4(veth-45,fc00:e:45/32) -- ns5(veth-54,fc00:e:54/32)
# - ns5(veth-56,fc00:d:56/32) -- ns6(veth-65,fc00:d:65/32)

ip link add veth-12 type veth peer name veth-21
ip link set veth-12 netns ns1
ip link set veth-21 netns ns2
ip link add veth-23 type veth peer name veth-32
ip link set veth-23 netns ns2
ip link set veth-32 netns ns3
ip link add veth-24 type veth peer name veth-42
ip link set veth-24 netns ns2
ip link set veth-42 netns ns4
ip link add veth-35 type veth peer name veth-53
ip link set veth-35 netns ns3
ip link set veth-53 netns ns5
ip link add veth-45 type veth peer name veth-54
ip link set veth-45 netns ns4
ip link set veth-54 netns ns5
ip link add veth-56 type veth peer name veth-65
ip link set veth-56 netns ns5
ip link set veth-65 netns ns6

# Enable IP forwarding and SRv6
for ns in ns1 ns2 ns3 ns4 ns5 ns6; do
  ip netns exec $ns sysctl -w net.ipv6.conf.all.forwarding=1
  ip netns exec $ns sysctl -w net.ipv6.conf.all.seg6_enabled=1
done
ip netns exec ns1 sysctl -w net.ipv6.conf.veth-12.seg6_enabled=1
ip netns exec ns2 sysctl -w net.ipv6.conf.veth-21.seg6_enabled=1
ip netns exec ns2 sysctl -w net.ipv6.conf.veth-23.seg6_enabled=1
ip netns exec ns3 sysctl -w net.ipv6.conf.veth-32.seg6_enabled=1
ip netns exec ns2 sysctl -w net.ipv6.conf.veth-24.seg6_enabled=1
ip netns exec ns4 sysctl -w net.ipv6.conf.veth-42.seg6_enabled=1
ip netns exec ns3 sysctl -w net.ipv6.conf.veth-35.seg6_enabled=1
ip netns exec ns5 sysctl -w net.ipv6.conf.veth-53.seg6_enabled=1
ip netns exec ns4 sysctl -w net.ipv6.conf.veth-45.seg6_enabled=1
ip netns exec ns5 sysctl -w net.ipv6.conf.veth-54.seg6_enabled=1
ip netns exec ns5 sysctl -w net.ipv6.conf.veth-56.seg6_enabled=1
ip netns exec ns6 sysctl -w net.ipv6.conf.veth-65.seg6_enabled=1

# Assign IP addresses
# ns1 <-> ns2: fc00:a::/32, ns1(12) <-> ns2(21)
# ns1 <-> ns3: fc00:b::/32, ns1(13) <-> ns3(31)
# ns1 <-> ns4: fc00:c::/32, ns1(14) <-> ns4(41)

ip netns exec ns1 ip -6 addr add fc00:a:12::/32 dev veth-12
ip netns exec ns2 ip -6 addr add fc00:a:21::/32 dev veth-21
ip netns exec ns2 ip -6 addr add fc00:b:23::/32 dev veth-23
ip netns exec ns2 ip -6 addr add fc00:c:24::/32 dev veth-24
ip netns exec ns3 ip -6 addr add fc00:b:32::/32 dev veth-32
ip netns exec ns3 ip -6 addr add fc00:d:35::/32 dev veth-35
ip netns exec ns4 ip -6 addr add fc00:c:42::/32 dev veth-42
ip netns exec ns4 ip -6 addr add fc00:e:45::/32 dev veth-45
ip netns exec ns5 ip -6 addr add fc00:d:53::/32 dev veth-53
ip netns exec ns5 ip -6 addr add fc00:e:54::/32 dev veth-54
ip netns exec ns5 ip -6 addr add fc00:f:56::/32 dev veth-56
ip netns exec ns6 ip -6 addr add fc00:f:65::/32 dev veth-65
echo "🔗 Assigned IP addresses!"

# Up interfaces
ip netns exec ns1 ip link set dev lo up
ip netns exec ns1 ip link set dev veth-12 up
ip netns exec ns2 ip link set dev lo up
ip netns exec ns2 ip link set dev veth-21 up
ip netns exec ns2 ip link set dev veth-23 up
ip netns exec ns2 ip link set dev veth-24 up
ip netns exec ns3 ip link set dev lo up
ip netns exec ns3 ip link set dev veth-32 up
ip netns exec ns3 ip link set dev veth-35 up
ip netns exec ns4 ip link set dev lo up
ip netns exec ns4 ip link set dev veth-42 up
ip netns exec ns4 ip link set dev veth-45 up
ip netns exec ns5 ip link set dev lo up
ip netns exec ns5 ip link set dev veth-53 up
ip netns exec ns5 ip link set dev veth-54 up
ip netns exec ns5 ip link set dev veth-56 up
ip netns exec ns6 ip link set dev lo up
ip netns exec ns6 ip link set dev veth-65 up
echo "🔗 Up interfaces!"

ip netns exec ns1 ip -6 route add default via fc00:a:21::
ip netns exec ns2 ip -6 route add fc00:a::/32 dev veth-21
ip netns exec ns2 ip -6 route add fc00:b::/32 via fc00:b:32::
ip netns exec ns2 ip -6 route add fc00:c::/32 via fc00:c:42::
ip netns exec ns2 ip -6 route add fc00:d::/32 via fc00:b:32::
ip netns exec ns2 ip -6 route add fc00:e::/32 via fc00:c:42::
ip netns exec ns2 ip -6 route add fc00:f::/32 via fc00:c:42::
ip netns exec ns3 ip -6 route add fc00:a::/32 via fc00:b:23::
ip netns exec ns3 ip -6 route add fc00:b::/32 dev veth-32
ip netns exec ns3 ip -6 route add fc00:c::/32 dev veth-32
ip netns exec ns3 ip -6 route add fc00:d::/32 via fc00:d:53::
ip netns exec ns3 ip -6 route add fc00:e::/32 dev veth-35
ip netns exec ns3 ip -6 route add fc00:f::/32 via fc00:d:53::
ip netns exec ns4 ip -6 route add fc00:a::/32 via fc00:c:24::
ip netns exec ns4 ip -6 route add fc00:b::/32 dev veth-42
ip netns exec ns4 ip -6 route add fc00:c::/32 dev veth-42
ip netns exec ns4 ip -6 route add fc00:d::/32 dev veth-45
ip netns exec ns4 ip -6 route add fc00:e::/32 dev veth-45
ip netns exec ns4 ip -6 route add fc00:f::/32 via fc00:e:54::
ip netns exec ns5 ip -6 route add fc00:a::/32 via fc00:d:35::
ip netns exec ns5 ip -6 route add fc00:b::/32 dev veth-53
ip netns exec ns5 ip -6 route add fc00:c::/32 dev veth-54
ip netns exec ns5 ip -6 route add fc00:d::/32 dev veth-53
ip netns exec ns5 ip -6 route add fc00:e::/32 dev veth-54
ip netns exec ns5 ip -6 route add fc00:f::/32 via fc00:f:65::
ip netns exec ns6 ip -6 route add default via fc00:f:56::
echo "🔗 Set up routing!"
