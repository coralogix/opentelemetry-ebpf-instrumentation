// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestDropDisabledPrograms(t *testing.T) {
	makeSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				progObiKprobeTcpCloseSrtt:         {Name: progObiKprobeTcpCloseSrtt},
				progObiTracepointInetSockSetState: {Name: progObiTracepointInetSockSetState},
			},
		}
	}

	tests := []struct {
		name         string
		rttEnabled   bool
		failedEnabled bool
		want         map[string]bool // progName -> should remain in spec
	}{
		{
			name:          "both enabled",
			rttEnabled:    true,
			failedEnabled: true,
			want: map[string]bool{
				progObiKprobeTcpCloseSrtt:         true,
				progObiTracepointInetSockSetState: true,
			},
		},
		{
			name:          "rtt only",
			rttEnabled:    true,
			failedEnabled: false,
			want: map[string]bool{
				progObiKprobeTcpCloseSrtt:         true,
				progObiTracepointInetSockSetState: false,
			},
		},
		{
			name:          "failed-conn only",
			rttEnabled:    false,
			failedEnabled: true,
			want: map[string]bool{
				progObiKprobeTcpCloseSrtt:         false,
				progObiTracepointInetSockSetState: true,
			},
		},
		{
			name:          "both disabled",
			rttEnabled:    false,
			failedEnabled: false,
			want: map[string]bool{
				progObiKprobeTcpCloseSrtt:         false,
				progObiTracepointInetSockSetState: false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := makeSpec()
			kprobes := []probe{{
				progName: progObiKprobeTcpCloseSrtt,
				hookName: KprobeTCPClose,
				enabled:  tc.rttEnabled,
			}}
			tracepoints := []probe{{
				progName: progObiTracepointInetSockSetState,
				hookName: TracepointInetSockSetState,
				enabled:  tc.failedEnabled,
			}}

			dropDisabledPrograms(spec, kprobes, tracepoints)

			for name, shouldRemain := range tc.want {
				_, present := spec.Programs[name]
				if present != shouldRemain {
					t.Errorf("program %q: present=%v, want %v", name, present, shouldRemain)
				}
			}
		})
	}
}
