package main

import (
	"errors"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

func handleULogF(stop chan struct{}, m *ebpf.Map) {
	r, err := perf.NewReader(m, os.Getpagesize())
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
			log.Println(string(ev))
		case <-stop:
			log.Println("Stopping event reader")
			stopped = true
			<-done
			return
		}
	}
}
