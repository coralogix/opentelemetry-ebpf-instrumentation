// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// ErrMissingCapPerfmon is returned when the kernel verifier rejects the
// netolly BPF programs because the process lacks CAP_PERFMON.
// bpf_trace_printk (emitted by bpf_dbg_printk) is gated on CAP_PERFMON
// in mainline kernels (bpf_base_func_proto, kernel/bpf/helpers.c).
// See https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2431
var ErrMissingCapPerfmon = errors.New(
	"BPF verifier rejected bpf_trace_printk helper: process lacks CAP_PERFMON " +
		"(or CAP_SYS_ADMIN). Grant CAP_PERFMON to the OBI container/process, or run with CAP_SYS_ADMIN")

// annotateVerifierError returns err wrapped with a clear capability hint if
// the underlying VerifierError log mentions a bpf_trace_printk rejection.
// Other failures pass through untouched.
func annotateVerifierError(err error) error {
	if err == nil {
		return nil
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return err
	}
	if !logMentionsTracePrintkRejection(ve.Log) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrMissingCapPerfmon, err)
}

func logMentionsTracePrintkRejection(log []string) bool {
	for _, line := range log {
		if strings.Contains(line, "bpf_trace_printk") &&
			strings.Contains(line, "cannot use helper") {
			return true
		}
	}
	return false
}
