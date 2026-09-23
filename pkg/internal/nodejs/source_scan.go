// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"context"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
)

var sigusr1Quoted = []string{`"SIGUSR1"`, `'SIGUSR1'`, "`SIGUSR1`"}

// sourceHasSIGUSR1Reference scans the Node.js application's source files for
// references to "SIGUSR1", 'SIGUSR1', or `SIGUSR1`. This is a fallback
// detection method used when the symbol-based detection fails (e.g. stripped
// binaries with dynamic libuv).
func sourceHasSIGUSR1Reference(ctx context.Context, pid int) bool {
	dir, err := harvest.FindNodeJSAppDir(app.PID(pid))
	if err != nil {
		return false
	}

	return dirHasSIGUSR1Reference(ctx, dir)
}

func lineContainsSIGUSR1(line string) bool {
	for _, pattern := range sigusr1Quoted {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}

func scanFileForSIGUSR1(path string) bool {
	found := false
	_ = harvest.ScanJSFileLines(path, func(line string) bool {
		if lineContainsSIGUSR1(line) {
			found = true
			return true
		}
		return false
	})
	return found
}

// dirHasSIGUSR1Reference scans JS/TS source files in the given directory for
// quoted SIGUSR1 references.
// The walk has no file cap, so a large source tree can outlast the budget the
// caller allowed for the gates. Abandoning it reads as no reference found, the
// same fail-open answer an unreadable tree gives, so the caller checks the gate
// context before acting on it. The check is per file: a tree slow in directory
// traversal rather than in files is not interrupted here.
func dirHasSIGUSR1Reference(ctx context.Context, dir string) bool {
	found := false

	_ = harvest.WalkJSFiles(dir, func(path string) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}

		if scanFileForSIGUSR1(path) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})

	return found
}
