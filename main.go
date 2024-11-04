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

type CLArgs struct {
	Prefix *net.IPNet
	Gw     net.IP
}

func parseArgs(ca *CLArgs) {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <prefix> <gw>", os.Args[0])
	}
	_, prefix, err := net.ParseCIDR(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to parse prefix: %v", err)
	}
	ca.Prefix = prefix

	gw := net.ParseIP(os.Args[2])
	if gw == nil {
		log.Fatalf("Failed to parse gw: %v", err)
	}
	ca.Gw = gw
}

func main() {
	var clArgs CLArgs
	parseArgs(&clArgs)

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

	bpfEncap := &netlink.BpfEncap{}
	bpfEncap.SetProg(nl.LWT_BPF_XMIT, objs.DoTestData.FD(), "lwt_xmit/test_data")
	route := netlink.Route{
		Dst:      clArgs.Prefix,
		Encap:    bpfEncap,
		Gw:       clArgs.Gw,
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
				if len(logs) > 0 {
					log.Printf("Link stats: %s", strings.Join(logs, ", "))
				}
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
