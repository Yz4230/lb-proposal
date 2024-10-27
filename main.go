package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	target := net.ParseIP("fc00:a:ff::")
	bpfEncap := &netlink.BpfEncap{}
	bpfEncap.SetProg(nl.LWT_BPF_XMIT, objs.DoTestData.FD(), "lwt_xmit/test_data")
	route := netlink.Route{
		Dst: &net.IPNet{
			IP:   target,
			Mask: net.CIDRMask(48, 128),
		},
		Encap: bpfEncap,
		Gw:    target,
	}

	if err := netlink.RouteAdd(&route); err != nil {
		log.Fatalf("Failed to add route: %v", err)
	}

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
