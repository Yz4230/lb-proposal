#!/bin/bash
set -ex

# ns2 -> ns3の場合に、ns2 -> ns4 -> ns3の経路を通るようにする
# すでにある経路を削除

ip netns exec ns2 ip -6 route del fc00:b::/32
index=$(ip netns exec ns1 ip link | grep veth1-4 | awk -F: '{print $1}')
index_hex=$(printf "%02x" $index)
ip netns exec ns2 ip -6 route add fc00:b::/32 encap seg6 mode encap segs fc00:a:12:0:8000:0100:01$index_hex:00a0,fc00:c:41:: via fc00:a:12:: metric 1
ip netns exec ns2 ip -6 route add fc00:a::/32 via fc00:a:12:: metric 1
