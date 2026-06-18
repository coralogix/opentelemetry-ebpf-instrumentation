// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"errors"
	"log/slog"
	"os"
	"sync"

	v2 "github.com/containers/common/pkg/cgroupv2"
	"golang.org/x/sys/unix"
)

const (
	// SelfMountPath is where OBI mounts its own cgroupv2 hierarchy when
	// the host has no unified or hybrid mount available (issue #603).
	SelfMountPath = "/run/obi-cgroupv2"

	cgroupFSRoot     = "/sys/fs/cgroup"
	cgroupV2Hybrid   = "/sys/fs/cgroup/unified"
	cgroup2Magic     = 0x63677270
	selfMountPerm    = 0o700
)

var errNoCgroupV2 = errors.New("no cgroupv2 hierarchy found; sockops cannot be attached")

type cgroupV2Result struct {
	path string
	err  error
}

var cgroupV2Once = sync.OnceValue(func() cgroupV2Result {
	log := slog.With("component", "ebpf.cgroupv2")
	if enabled, err := v2.Enabled(); err == nil && enabled {
		return cgroupV2Result{path: cgroupFSRoot}
	}
	if _, err := os.Stat(cgroupV2Hybrid); err == nil {
		return cgroupV2Result{path: cgroupV2Hybrid}
	}
	if p, err := selfMountCgroupV2(log); err == nil {
		return cgroupV2Result{path: p}
	} else {
		log.Warn("could not self-mount cgroupv2", "path", SelfMountPath, "error", err)
	}
	return cgroupV2Result{err: errNoCgroupV2}
})

func selfMountCgroupV2(log *slog.Logger) (string, error) {
	if isCgroup2Mount(SelfMountPath) {
		return SelfMountPath, nil
	}
	if err := os.MkdirAll(SelfMountPath, selfMountPerm); err != nil {
		return "", err
	}
	if err := unix.Mount("none", SelfMountPath, "cgroup2", 0, ""); err != nil {
		return "", err
	}
	log.Info("self-mounted cgroup2 hierarchy for sockops attach", "path", SelfMountPath)
	return SelfMountPath, nil
}

func isCgroup2Mount(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Type == cgroup2Magic
}

func CgroupV2Path() (string, error) {
	r := cgroupV2Once()
	return r.path, r.err
}
