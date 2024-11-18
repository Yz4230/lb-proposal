package main

import (
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type CLArgs struct {
	Prefix   *net.IPNet
	Gw       net.IP
	Interval time.Duration
}

func parseArgs(ca *CLArgs) {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <prefix> <gw> <interval>", os.Args[0])
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

	interval, err := time.ParseDuration(os.Args[3])
	if err != nil {
		log.Fatalf("Failed to parse interval: %v", err)
	}
	ca.Interval = interval
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
	log.Printf("Added route: %s", route)

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
		window := uint64(clArgs.Interval.Milliseconds())
		statTimer := time.NewTicker(clArgs.Interval)
		logTimer := time.NewTicker(1 * time.Second)
		lastTxBytes := make(map[int]uint64) // map index -> tx bytes
		lastDiff := make(map[int]uint64)    // map index -> metrics
		for {
			select {
			case <-statTimer.C:
				links, err := netlink.LinkList()
				if err != nil {
					log.Fatalf("Failed to list links: %v", err)
				}
				for _, link := range links {
					attrs := link.Attrs()
					if lastTxByte, ok := lastTxBytes[attrs.Index]; ok {
						diff := (attrs.Statistics.TxBytes - lastTxByte) / window
						objs.TxBytesPerSec.Update(uint32(attrs.Index), uint64(diff), ebpf.UpdateAny)
						lastDiff[attrs.Index] = uint64(diff)
					}
					lastTxBytes[attrs.Index] = attrs.Statistics.TxBytes
				}
			case <-logTimer.C:
				indices := slices.Sorted(maps.Keys(lastDiff))
				parts := make([]string, 0, len(indices))
				for _, idx := range indices {
					diff := lastDiff[idx]
					parts = append(parts, fmt.Sprintf("%d: %s/%s", idx, humanizeSize(diff), clArgs.Interval))
				}
				log.Println(strings.Join(parts, ", "))
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
	log.Printf("Deleted route: %s", route)

	wg.Wait()
}

func humanizeSize(size uint64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	size /= 1024
	if size < 1024 {
		return fmt.Sprintf("%d KiB", size)
	}
	size /= 1024
	if size < 1024 {
		return fmt.Sprintf("%d MiB", size)
	}
	size /= 1024
	if size < 1024 {
		return fmt.Sprintf("%d GiB", size)
	}
	size /= 1024
	return fmt.Sprintf("%d TiB", size)
}
