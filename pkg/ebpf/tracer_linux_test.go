// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type recordingCloser struct {
	closed bool
}

func (r *recordingCloser) Close() error {
	r.closed = true
	return nil
}

// Containers sharing an image share one instrumenter: unlinking one executable
// must not close the Go probe links the surviving siblings depend on.
func TestUnlinkExecutable_SharedInstrumenterSurvivesSiblingUnlink(t *testing.T) {
	firstKey := ExecutableKey{Dev: 100, Ino: 1234}
	secondKey := ExecutableKey{Dev: 200, Ino: 1234}
	closer := &recordingCloser{}

	shared := &instrumenter{
		key:        firstKey,
		references: 2,
		closables:  []io.Closer{closer},
	}
	tracer := &ProcessTracer{
		log:  slog.Default(),
		Type: Go,
		Instrumentables: map[ExecutableKey]*instrumenter{
			firstKey:  shared,
			secondKey: shared,
		},
		instrumentableGenerations: map[ExecutableKey]uint64{
			firstKey:  1,
			secondKey: 2,
		},
		goInstrumentablesByInode: map[uint64]*instrumenter{1234: shared},
	}
	firstFile := execpkg.New(execpkg.Init{Dev: 100, Ino: 1234})
	secondFile := execpkg.New(execpkg.Init{Dev: 200, Ino: 1234})

	// a stale generation must not unlink anything
	tracer.UnlinkExecutable(firstFile, 999)
	assert.False(t, closer.closed)
	assert.Len(t, tracer.Instrumentables, 2)

	tracer.UnlinkExecutable(firstFile, 1)
	assert.False(t, closer.closed)
	assert.Contains(t, tracer.goInstrumentablesByInode, uint64(1234))
	assert.Len(t, tracer.Instrumentables, 1)

	tracer.UnlinkExecutable(secondFile, 2)
	assert.True(t, closer.closed)
	assert.Empty(t, tracer.goInstrumentablesByInode)
	assert.Empty(t, tracer.Instrumentables)
}
