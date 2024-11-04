#!/bin/bash
set -ex

# ns2 -> ns3の場合に、ns2 -> ns4 -> ns3の経路を通るようにする
# すでにある経路を削除

index=$(ip netns exec ns2 ip link | grep veth-23 | awk -F: '{print $1}')
index_hex=$(printf "%02x" $index)
ip netns exec ns1 ip -6 route add fc00:f:65:: encap seg6 mode encap segs fc00:a:21:0:8000:0200:01$index_hex:00a0,fc00:b:32::,fc00:d:53:0:8001:0100::,fc00:c:42::,fc00:f:65:: via fc00:a:21:: metric 1
ip netns exec ns1 ip -6 route add fc00:a::/32 via fc00:a:21:: metric 1
ip netns exec ns3 ip -6 route add fc00:d::/32 via fc00:d:53:: metric 1
ip netns exec ns4 ip -6 route add fc00:e::/32 via fc00:e:54:: metric 1
