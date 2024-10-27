package main

import (
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cilium/ebpf/perf"
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

	wg := &sync.WaitGroup{}

	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.Tick(time.Second)
		for {
			select {
			case <-tick:
				var count uint64
				if err := objs.PktCount.Lookup(uint32(0), &count); err != nil {
					log.Fatal("Map lookup:", err)
				}
				log.Printf("Received %d packets", count)
			case <-stop:
				log.Println("Stopping packet counter")
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		r, err := perf.NewReader(objs.LogEntries, os.Getpagesize())
		if err != nil {
			log.Fatalf("Failed to create perf event reader: %v", err)
		}
		defer r.Close()
		evCh := make(chan []byte)

		stopped := false
		done := make(chan struct{})
		go func() {
			defer close(done)
			for !stopped {
				r.SetDeadline(time.Now().Add(500 * time.Millisecond))
				ev, err := r.Read()
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				if err != nil {
					log.Fatalf("Failed to read perf event: %v", err)
				}
				evCh <- ev.RawSample
			}
		}()

		for {
			select {
			case ev := <-evCh:
				log.Printf("Received event: %s", ev)
			case <-stop:
				log.Println("Stopping event reader")
				stopped = true
				<-done
				return
			}
		}
	}()

	interrupt := make(chan os.Signal, 5)
	signal.Notify(interrupt, os.Interrupt)

	// Wait for the program to be interrupted.
	<-interrupt
	close(stop)

	wg.Wait()
}
