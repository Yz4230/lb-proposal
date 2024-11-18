ip netns exec ns2 ./build/ebpf-test fc00:a:21::/64 fc00:a:: 10ms &
ip netns exec ns5 ./build/ebpf-test fc00:d:53::/64 fc00:d:: 10ms &
ip netns exec ns5 ./build/ebpf-test fc00:e:54::/64 fc00:e:: 10ms &

wait
