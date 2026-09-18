// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Workload for the Go channel span link suite.
//
// Every endpoint hands work between two goroutines that each carry their own
// OBI span, which is the only shape that produces a link: emit_channel_handoff
// needs a valid, distinct span context on both sides.
//
// Two servers on purpose:
//
//   - :8080 is net/http, so requests are traced by the Go protocol uprobes and
//     both goroutines appear in the tracer's per-operation maps.
//   - :8081 speaks HTTP/1.1 over a hand-rolled TCP listener, so net/http
//     uprobes never fire and requests are traced by the generic protocol
//     parser instead. Those goroutines are reachable only through go_trace_map.
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"
)

type job struct{ id int }

var (
	unbuffered    = make(chan job)
	buffered      = make(chan job, 8)
	rawUnbuffered = make(chan job)
	rawBuffered   = make(chan job, 8)

	// nobody is ever scheduled to receive on this one within a request
	orphan = make(chan job, 1)
)

// reschedule makes it likely that the goroutine resumes on a different OS
// thread than the one that read the request, which is what distinguishes a
// goroutine-keyed context source from a thread-keyed one.
func reschedule() {
	runtime.Gosched()
	time.Sleep(2 * time.Millisecond)
	runtime.Gosched()
}

func httpHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/send", func(w http.ResponseWriter, _ *http.Request) {
		reschedule()
		unbuffered <- job{id: 1}
		fmt.Fprint(w, "sent")
	})
	mux.HandleFunc("/recv", func(w http.ResponseWriter, _ *http.Request) {
		reschedule()
		j := <-unbuffered
		fmt.Fprintf(w, "recv %d", j.id)
	})
	mux.HandleFunc("/send-buffered", func(w http.ResponseWriter, _ *http.Request) {
		reschedule()
		buffered <- job{id: 2}
		fmt.Fprint(w, "sent-buffered")
	})
	mux.HandleFunc("/recv-buffered", func(w http.ResponseWriter, _ *http.Request) {
		reschedule()
		j := <-buffered
		fmt.Fprintf(w, "recv-buffered %d", j.id)
	})

	// Negative case: the send has a span, the receive happens on a background
	// goroutine that has none, so no link may be emitted.
	mux.HandleFunc("/orphan-send", func(w http.ResponseWriter, _ *http.Request) {
		reschedule()
		select {
		case orphan <- job{id: 3}:
		default:
		}
		fmt.Fprint(w, "orphan-sent")
	})

	// Negative case: both sides of the handoff run on the same goroutine
	// inside one request, so sender and receiver share a span and the link
	// would be a self-link.
	mux.HandleFunc("/self", func(w http.ResponseWriter, _ *http.Request) {
		self := make(chan job, 1)
		reschedule()
		self <- job{id: 4}
		j := <-self
		fmt.Fprintf(w, "self %d", j.id)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	})
}

func drainOrphan() {
	for range orphan {
		// consumed outside any request, long after the sender's span ended
		time.Sleep(50 * time.Millisecond)
	}
}

func rawReply(c net.Conn, body string) {
	fmt.Fprintf(c,
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

func rawHandle(c net.Conn) {
	defer c.Close()

	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" || h == "\n" {
			break
		}
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		rawReply(c, "bad")
		return
	}

	reschedule()

	switch parts[1] {
	case "/raw-send":
		rawUnbuffered <- job{id: 5}
		rawReply(c, "raw-sent")
	case "/raw-recv":
		j := <-rawUnbuffered
		rawReply(c, fmt.Sprintf("raw-recv %d", j.id))
	case "/raw-send-buffered":
		rawBuffered <- job{id: 6}
		rawReply(c, "raw-sent-buffered")
	case "/raw-recv-buffered":
		j := <-rawBuffered
		rawReply(c, fmt.Sprintf("raw-recv-buffered %d", j.id))
	default:
		rawReply(c, "ok")
	}
}

func serveRaw(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("raw listener: %v", err)
	}
	log.Println("raw listener on", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go rawHandle(c)
	}
}

func main() {
	go drainOrphan()
	go serveRaw(":8081")

	mux := http.NewServeMux()
	httpHandlers(mux)

	log.Println("gochannels listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
