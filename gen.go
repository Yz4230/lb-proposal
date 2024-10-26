package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 counter bpf/counter.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf bpf/bpf.c
