// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	aero "github.com/aerospike/aerospike-client-go/v7"
)

const (
	namespace = "test"
	set       = "demo"
)

// HTTPHandler triggers a deterministic sequence of Aerospike record operations
// (PUT, GET, DELETE, SCAN) on every request so OBI can observe them passively.
func HTTPHandler(log *slog.Logger, client *aero.Client) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Debug("received request", "url", req.RequestURI)

		wp := aero.NewWritePolicy(0, 0)
		key, _ := aero.NewKey(namespace, set, "obi")

		// PUT
		if err := client.PutBins(wp, key, aero.NewBin("product", "rocks")); err != nil {
			log.Debug("put failed", "error", err)
		}
		// GET
		if _, err := client.Get(nil, key); err != nil {
			log.Debug("get failed", "error", err)
		}
		// DELETE
		if _, err := client.Delete(wp, key); err != nil {
			log.Debug("delete failed", "error", err)
		}
		// SCAN
		if rs, err := client.ScanAll(nil, namespace, set); err != nil {
			log.Debug("scan failed", "error", err)
		} else if rs != nil {
			for range rs.Results() {
			}
		}

		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("ok"))
	}
}

func main() {
	log := slog.With("component", "goaerospike")

	cp := aero.NewClientPolicy()
	cp.Timeout = 10 * time.Second

	var client *aero.Client
	var err error
	// The server may still be starting up; retry the initial connection.
	for i := 0; i < 30; i++ {
		client, err = aero.NewClientWithPolicy(cp, "aerospike", 3000)
		if err == nil {
			break
		}
		log.Info("waiting for aerospike", "error", err)
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Error("could not connect to aerospike", "error", err)
		return
	}
	defer client.Close()

	address := fmt.Sprintf(":%d", 8080)
	log.Info("starting HTTP server", "address", address)
	if err := http.ListenAndServe(address, HTTPHandler(log, client)); err != nil {
		log.Error("HTTP server has unexpectedly stopped", "error", err)
	}
}
