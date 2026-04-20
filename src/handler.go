package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Exact parity at bit level for the event to be consumed from the ring buffer
type Event struct {
	Pid        uint32
	Ppid       uint32
	StorageWritten uint32
	Comm       [16]byte
	ParentComm [16]byte
	Filename   [128]byte
	RequestID  [64]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	// Load the program from the object file
	spec, err := ebpf.LoadCollectionSpec("command-logger.bpf.o")
	if err != nil {
		log.Fatalf("failed to load BPF spec: %v", err)
	}

	// Load and verify the BPF program. The verifier checks for correctness,
	// bounded loops, valid memory access, and allowed helper calls.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "Verifier error:\n%+v\n", ve)
		}
		log.Fatalf("failed to load BPF collection: %v", err)
	}
	defer coll.Close()

	// Attach the hook section to the corresponding tracepoint
	tp, err := link.Tracepoint("sched", "sched_process_exec",
		coll.Programs["handle_exec"], nil)
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	// Setup the rinbuffer reader from the map defined in the bpf code.
	rd, err := ringbuf.NewReader(coll.Maps["rb"])
	if err != nil {
		log.Fatalf("failed to open ring buffer: %v", err)
	}
	defer rd.Close()

	fmt.Println("Listening... Ctrl+C to stop")
	fmt.Printf("%-8s %-8s %-16s %-16s %-40s %-36s %-8s\n",
		"PID", "PPID", "COMM", "PARENT", "FILENAME", "REQUEST_ID", "STORED")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	for {
		// triggers everytime the bpf program calls submit on the ring buffer
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("error reading from ring buffer: %v", err)
			continue
		}

		var event Event
		if err := binary.Read(bytes.NewReader(record.RawSample),
			binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing event: %v", err)
			continue
		}

		fmt.Printf("%-8d %-8d %-16s %-16s %-40s %-36s %-8d\n",
			event.Pid,
			event.Ppid,
			nullTerminated(event.Comm[:]),
			nullTerminated(event.ParentComm[:]),
			nullTerminated(event.Filename[:]),
			nullTerminated(event.RequestID[:]),
			event.StorageWritten,
		)
	}
}

func nullTerminated(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}