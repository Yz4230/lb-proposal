ip netns exec ns2 ./build/ebpf-test fc00:a:21::/64 fc00:a:: 1s &
ip netns exec ns5 ./build/ebpf-test fc00:d:53::/64 fc00:d:: 1s &
ip netns exec ns5 ./build/ebpf-test fc00:e:54::/64 fc00:e:: 1s &

wait
