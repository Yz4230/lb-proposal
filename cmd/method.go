package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
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

	ts := time.Now().Unix()
	var logRawStatsWriter *os.File
	if flags.LogRawStats {
		if writer, err := os.Create(fmt.Sprintf("raw_stats_%d.ndjson", ts)); err != nil {
			return errors.Wrap(err, "Failed to create raw_stats.log")
		} else {
			logRawStatsWriter = writer
			defer logRawStatsWriter.Close()
		}
	}
	var logRawEMAWriter *os.File
	if flags.LogRawEMA {
		if writer, err := os.Create(fmt.Sprintf("raw_ema_%d.ndjson", ts)); err != nil {
			return errors.Wrap(err, "Failed to create raw_ema.log")
		} else {
			logRawEMAWriter = writer
			defer logRawEMAWriter.Close()
		}
	}

	ifidxToIfname := make(map[int]string)
	links, err := netlink.LinkList()
	if err != nil {
		return errors.Wrap(err, "Failed to list links")
	}
	for _, link := range links {
		attrs := link.Attrs()
		ifidxToIfname[attrs.Index] = attrs.Name
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		statTimer := time.NewTicker(flags.Interval)
		intervalSec := flags.Interval.Seconds()
		lastTotalBandwidth := make(map[int]float64) // map index -> bandwidth
		emas := make(map[int]*EMA)                  // map index -> EMA

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
					totalBandwidth := float64(stats.TxBytes + stats.RxBytes)
					if last, ok := lastTotalBandwidth[attrs.Index]; ok {
						bytesPerSec = (totalBandwidth - last) / intervalSec
					}
					lastTotalBandwidth[attrs.Index] = totalBandwidth

					ema := emas[attrs.Index]
					if ema == nil {
						ema = NewEMA(flags.EMASpan)
						emas[attrs.Index] = ema
					}
					megaBitsPerSec := bytesPerSec * 8 / 1e6
					metric := ema.Update(megaBitsPerSec)

					objs.BwBitsPerSec.Update(uint32(attrs.Index), uint64(metric), ebpf.UpdateAny)
				}
				ts := time.Now().UnixNano()
				if flags.LogRawStats {
					line := map[string]interface{}{
						"timestamp": ts,
						"bandwidth": lastTotalBandwidth,
					}
					encoded, err := json.Marshal(line)
					if err != nil {
						log.Fatalf("Failed to encode raw stats: %v", err)
					}
					logRawStatsWriter.WriteString(fmt.Sprintf("%s\n", encoded))
				}
				if flags.LogRawEMA {
					line := map[string]interface{}{
						"timestamp": ts,
						"ema":       emas,
					}
					encoded, err := json.Marshal(line)
					if err != nil {
						log.Fatalf("Failed to encode raw EMA: %v", err)
					}
					logRawEMAWriter.WriteString(fmt.Sprintf("%s\n", encoded))
				}
			case <-stop:
				return
			}
		}
	}()

	interrupt := make(chan os.Signal, 5)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

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
