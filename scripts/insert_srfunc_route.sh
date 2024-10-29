#!/bin/bash
set -ex

# ns2 -> ns3の場合に、ns2 -> ns4 -> ns3の経路を通るようにする
# すでにある経路を削除

ip netns exec ns2 ip -6 route del fc00:b::/32
ip netns exec ns2 ip -6 route add fc00:b::/32 encap seg6 mode encap segs fc00:a:12:0:8000::,fc00:c:41:: via fc00:a:12:: metric 1
ip netns exec ns2 ip -6 route add fc00:a::/32 via fc00:a:12:: metric 1
