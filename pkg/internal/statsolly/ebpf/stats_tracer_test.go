// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"sort"
	"strings"
	"testing"
)

func TestTracepointConstantFormat(t *testing.T) {
	hooks := []string{
		TracepointInetSockSetState,
	}
	for _, hook := range hooks {
		if _, _, ok := strings.Cut(hook, "/"); !ok {
			t.Errorf("tracepoint constant %q is not in group/name format", hook)
		}
	}
}

func TestEnabledProgramNames(t *testing.T) {
	tests := []struct {
		name          string
		rttEnabled    bool
		failedEnabled bool
		want          []string
	}{
		{
			name:          "both enabled",
			rttEnabled:    true,
			failedEnabled: true,
			want: []string{
				progObiKprobeTCPCloseSrtt,
				progObiTracepointInetSockSetState,
			},
		},
		{
			name:          "rtt only",
			rttEnabled:    true,
			failedEnabled: false,
			want:          []string{progObiKprobeTCPCloseSrtt},
		},
		{
			name:          "failed-conn only",
			rttEnabled:    false,
			failedEnabled: true,
			want:          []string{progObiTracepointInetSockSetState},
		},
		{
			name:          "both disabled",
			rttEnabled:    false,
			failedEnabled: false,
			want:          nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kprobes := []probe{{
				progName: progObiKprobeTCPCloseSrtt,
				hookName: KprobeTCPClose,
				enabled:  tc.rttEnabled,
			}}
			tracepoints := []probe{{
				progName: progObiTracepointInetSockSetState,
				hookName: TracepointInetSockSetState,
				enabled:  tc.failedEnabled,
			}}

			got := enabledProgramNames(kprobes, tracepoints)
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)

			if len(got) != len(want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
				}
			}
		})
	}
}
