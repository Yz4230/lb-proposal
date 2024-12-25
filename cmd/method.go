package cmd

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cockroachdb/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf ../bpf/bpf.c -- -DDISABLE_ULOGF

func runProposal() error {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return errors.Wrap(err, "Failed to remove memlock resource limit")
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return errors.Wrap(err, "Failed to load eBPF objects")
	}
	defer objs.Close()

	bpfEncap := &netlink.BpfEncap{}
	bpfEncap.SetProg(nl.LWT_BPF_XMIT, objs.DoProposal.FD(), "lwt_xmit/proposal")
	route := netlink.Route{
		Dst:      &flags.Prefix,
		Encap:    bpfEncap,
		Gw:       flags.Gateway,
		Priority: 1,
	}

	if err := netlink.RouteAdd(&route); err != nil {
		return errors.Wrap(err, "Failed to add route")
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
		return errors.Wrap(err, "Failed to list links")
	} else {
		for _, link := range links {
			attrs := link.Attrs()
			idxToName[attrs.Index] = attrs.Name
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		statTimer := time.NewTicker(flags.Interval)
		intervalSec := flags.Interval.Seconds()
		lastBandwidth := make(map[int]float64) // map index -> bandwidth
		emas := make(map[int]*EMA)             // map index -> EMA

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

					bytesPerSec := 0.0
					bandwidth := float64(stats.TxBytes + stats.RxBytes)
					if last, ok := lastBandwidth[attrs.Index]; ok {
						bytesPerSec = (bandwidth - last) / intervalSec
					}
					lastBandwidth[attrs.Index] = bandwidth

					ema := emas[attrs.Index]
					if ema == nil {
						ema = NewEMA(1000)
						emas[attrs.Index] = ema
					}
					megaBitsPerSec := bytesPerSec * 8 / 1e6
					metric := ema.Update(megaBitsPerSec)

					objs.BwBitsPerSec.Update(uint32(attrs.Index), uint64(metric), ebpf.UpdateAny)
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
		return errors.Wrap(err, "Failed to delete route")
	}
	log.Printf("Deleted route: %s", route)

	wg.Wait()

	return nil
}
