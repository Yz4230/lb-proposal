ip netns exec ns2 ./build/lb-proposal -p fc00:a:21::/64 -g fc00:a:: -i 10ms &
ip netns exec ns5 ./build/lb-proposal -p fc00:d:53::/64 -g fc00:d:: -i 10ms &
ip netns exec ns5 ./build/lb-proposal -p fc00:e:54::/64 -g fc00:e:: -i 10ms &

wait
