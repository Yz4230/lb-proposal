package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
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

	// fc00:a:12:0:8000::/80
	target := &net.IPNet{IP: net.ParseIP(os.Args[1]), Mask: net.CIDRMask(64, 128)}
	gw := net.ParseIP(os.Args[2])

	fmt.Printf("target=%s, gw=%s\n", target, gw)
	bpfEncap := &netlink.BpfEncap{}
	bpfEncap.SetProg(nl.LWT_BPF_XMIT, objs.DoTestData.FD(), "lwt_xmit/test_data")
	route := netlink.Route{
		Dst:      target,
		Encap:    bpfEncap,
		Gw:       gw,
		Priority: 1,
	}

	if err := netlink.RouteAdd(&route); err != nil {
		log.Fatalf("Failed to add route: %v", err)
	}

	wg := &sync.WaitGroup{}
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		handleULogF(stop, objs.LogEntries)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		timer := time.NewTicker(1 * time.Second)
		lastStats := make(map[int]*netlink.LinkStatistics) // map index -> stats
		for {
			select {
			case <-timer.C:
				links, err := netlink.LinkList()
				if err != nil {
					log.Fatalf("Failed to list links: %v", err)
				}
				var logs []string
				for _, link := range links {
					attrs := link.Attrs()
					if lastStat, ok := lastStats[attrs.Index]; ok {
						diff := attrs.Statistics.TxBytes - lastStat.TxBytes
						objs.TxBytesPerSec.Update(uint32(attrs.Index), uint64(diff), ebpf.UpdateAny)
						logs = append(logs, fmt.Sprintf("%s(%d): %d", attrs.Name, attrs.Index, diff))
					}
					lastStats[attrs.Index] = attrs.Statistics
				}
				log.Printf("Link stats: %s", strings.Join(logs, ", "))
			case <-stop:
				return
			}
		}
	}()

	interrupt := make(chan os.Signal, 5)
	signal.Notify(interrupt, os.Interrupt)

	// Wait for the program to be interrupted.
	<-interrupt
	close(stop)

	if err := netlink.RouteDel(&route); err != nil {
		log.Fatalf("Failed to delete route: %v", err)
	}

	wg.Wait()
}
