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

	idxToName := make(map[int]string)
	if links, err := netlink.LinkList(); err != nil {
		log.Fatalf("Failed to list links: %v", err)
	} else {
		for _, link := range links {
			attrs := link.Attrs()
			idxToName[attrs.Index] = attrs.Name
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		span := int(clArgs.Interval.Milliseconds())
		statTimer := time.NewTicker(clArgs.Interval)
		logTimer := time.NewTicker(1 * time.Second)
		lastTxBytes := make(map[int]uint64) // map index -> tx bytes
		lastRxBytes := make(map[int]uint64) // map index -> rx bytes
		emas := make(map[int]*EMA)          // map index -> EMA
		for {
			select {
			case <-statTimer.C:
				links, err := netlink.LinkList()
				if err != nil {
					log.Fatalf("Failed to list links: %v", err)
				}
				for _, link := range links {
					attrs := link.Attrs()
					stats := attrs.Statistics

					bytesPerMs := 0.0
					if last, ok := lastTxBytes[attrs.Index]; ok {
						bytesPerMs += float64(stats.TxBytes-last) / float64(span)
					}
					lastTxBytes[attrs.Index] = stats.TxBytes
					if last, ok := lastRxBytes[attrs.Index]; ok {
						bytesPerMs += float64(stats.RxBytes-last) / float64(span)
					}
					lastRxBytes[attrs.Index] = stats.RxBytes

					ema, ok := emas[attrs.Index]
					if !ok {
						ema = NewEMA(span)
						emas[attrs.Index] = ema
					}
					metric := ema.Update(bytesPerMs)
					objs.XbytesPerSec.Update(uint32(attrs.Index), uint64(metric), ebpf.UpdateAny)
				}
			case <-logTimer.C:
				indices := slices.Sorted(maps.Keys(emas))
				parts := make([]string, 0, len(indices))
				for _, idx := range indices {
					if ema, ok := emas[idx]; ok {
						part := fmt.Sprintf("%s(%d): %s/%s",
							idxToName[idx], idx, humanizeSize(uint64(ema.GetValue())), clArgs.Interval)
						parts = append(parts, part)
					}
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
