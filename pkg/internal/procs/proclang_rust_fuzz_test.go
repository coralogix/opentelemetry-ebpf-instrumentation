//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"fmt"
	"testing"
)

// rustDemangleSeeds covers both mangling schemes, the prefixes the demanglers must
// reject, a truncated symbol, and a back-reference chain that doubles its text per
// element.
func rustDemangleSeeds() []string {
	const h2Stream = "_RNvMs0_NtNtNtCs9jSgvtFl8W9_5tokio7runtime4task7harnessINtB5_7HarnessINtNtNtNtCsiWqk3PIG25g_5hyper5proto2h26server8H2StreamINtNtNtCslucI2pHvjt9_10hyper_util7service4glue25TowerToHyperServiceFutureINtNtNtCs2X6c5HaYEso_5tower4util11map_request10MapRequestNtNtCshMmHa2FyZAo_4axum7routing6RouterNCNCNvXs0_NtB46_5serveINtB4O_5ServeB42_B42_ENtNtNtCsjCd2fZ6KadX_4core6future11into_future10IntoFuture11into_future0s1_0EINtNtCsi3ewrsuCVNV_4http7request7RequestNtNtNtB1d_4body8incoming8IncomingEENtNtCs5zVckKwpyv3_9axum_core4body4BodyNtNtNtB23_2rt5tokio13TokioExecutorEINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtB9_9scheduler14current_thread6HandleEE4pollCskAyKhQTcune_6server"

	return []string{
		"",
		"_Z",
		"_ZN",
		"_ZN3foo",
		"_ZN3foo3barE",
		"_ZN3foo3bar17h0123456789abcdefE",
		"_ZN3foo3bar$LT$E",
		"_ZN9227000000000000000",
		"_ZN5tokio7runtime4task4list24LocalOwnedTasks$LT$S$GT$4bind17he45315048f19b0faE",
		"_ZN5tokio4task5local6Shared8schedule17hc1df551b6d75b431E",
		"_R",
		"_RN",
		"_RNv",
		"_RNvC",
		"_RNvC3foo3bar",
		"_RNvC9227000000000000000",
		"_RB_",
		"_RIE",
		"_RNvMs9_NtNtCscMapNUXOuou_5tokio4task5localNtB5_6Shared8schedule",
		"_RNvMNtNtNtCsec06QdWoQn_5tokio7runtime4task4listINtB2_10OwnedTasksINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtB6_9scheduler14current_thread6HandleEE10bind_innerCsjqY7L67gDVE_8actix_rt",
		"__RNvMs4_NtNtNtCscMapNUXOuou_5tokio7runtime8blocking4poolNtB5_7Spawner10spawn_task",
		h2Stream,
		h2Stream[:len(h2Stream)/2],
		v0BackrefChain(8),
	}
}

// checkRustDemangle holds the demanglers to what the symbol scan relies on: no panic
// and bounded output.
func checkRustDemangle(t *testing.T, name string) {
	t.Helper()

	// A legacy path only drops bytes from its input and joins the parts with "::".
	if legacy := rustDemangle(name); len(legacy) > 2*len(name) {
		t.Fatalf("legacy demangling grew %d bytes into %d", len(name), len(legacy))
	}

	if v0 := rustDemangleV0(name); len(v0) > maxRustV0PathLen {
		t.Fatalf("v0 demangling grew %d bytes into %d", len(name), len(v0))
	}
}

func TestRustDemangleCorpus(t *testing.T) {
	for i, seed := range rustDemangleSeeds() {
		t.Run(fmt.Sprintf("seed-%d", i), func(t *testing.T) {
			checkRustDemangle(t, seed)
		})
	}
}

func FuzzRustDemangle(f *testing.F) {
	for _, seed := range rustDemangleSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		checkRustDemangle(t, name)
	})
}
