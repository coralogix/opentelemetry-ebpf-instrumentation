// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: dump-gosyms <binary> <substr>")
		os.Exit(2)
	}
	ef, err := elf.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer ef.Close()
	pclntab := ef.Section(".gopclntab")
	if pclntab == nil {
		panic("no .gopclntab")
	}
	pcdata, err := pclntab.Data()
	if err != nil {
		panic(err)
	}
	textSec := ef.Section(".text")
	var textAddr uint64
	if textSec != nil {
		textAddr = textSec.Addr
	}
	pcln := gosym.NewLineTable(pcdata, textAddr)
	tab, err := gosym.NewTable(nil, pcln)
	if err != nil {
		panic(err)
	}
	needle := os.Args[2]
	for _, f := range tab.Funcs {
		if needle == "" || strings.Contains(f.Name, needle) {
			fmt.Printf("%#x  %s  size=%d\n", f.Entry, f.Name, f.End-f.Entry)
		}
	}
}
