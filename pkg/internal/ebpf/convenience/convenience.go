// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfconvenience // import "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

// This file contains convenience functions around the cilum/ebpf
// CollectionSpec.Variables API.
// This wrapper has been deprecated in the main cilium/ebpf codebase.

const PinInternal = ebpf.PinType(100)

func roundToNearestMultiple(x, n uint32) uint32 {
	if x < n {
		return n
	}

	if x%n == 0 {
		return x
	}

	return (x + n/2) / n * n
}

// RingBuf map types must be a multiple of os.Getpagesize()
func alignMaxEntriesIfRingBuf(m *ebpf.MapSpec) {
	if m.Type == ebpf.RingBuf {
		m.MaxEntries = roundToNearestMultiple(m.MaxEntries, uint32(os.Getpagesize()))
	}
}

// ResolveMaps sets up internal maps and ensures sane max entries values
func ResolveMaps(spec *ebpf.CollectionSpec, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex) (*ebpf.CollectionOptions, error) {
	collOpts := ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{}}

	mu.Lock()
	defer mu.Unlock()

	for k, v := range spec.Maps {
		alignMaxEntriesIfRingBuf(v)

		if v.Pinning != PinInternal {
			continue
		}

		v.Pinning = ebpf.PinNone
		internalMap := sharedMaps[k]

		var err error

		if internalMap == nil {
			internalMap, err = ebpf.NewMap(v)
			if err != nil {
				return nil, fmt.Errorf("failed to load shared map: %w", err)
			}

			sharedMaps[k] = internalMap
			runtime.SetFinalizer(internalMap, (*ebpf.Map).Close)
		}

		collOpts.MapReplacements[k] = internalMap
	}

	return &collOpts, nil
}

// LoadSpecOptions configures how LoadSpec loads a BPF collection.
type LoadSpecOptions struct {
	// Objects, if non-nil, receives all programs and maps via LoadAndAssign;
	// the returned collection is nil in this case.
	// Mutually exclusive with EnabledPrograms.
	Objects any

	// EnabledPrograms, if non-nil, prunes all other programs from the spec
	// before load so they never enter the kernel. An empty slice drops every
	// program. Only used when Objects is nil.
	EnabledPrograms []string

	// Constants is an optional map of BPF volatile constants to rewrite.
	Constants map[string]any

	// SharedMaps is a store for PinInternal maps shared across specs within
	// the same agent. May be empty; must not be nil.
	SharedMaps map[string]*ebpf.Map

	// Mu guards SharedMaps.
	Mu *sync.Mutex

	// PinPath is the bpffs pin path for PinByName maps; empty skips pinning.
	PinPath string
}

// LoadSpec loads a BPF collection spec, handling constant rewriting,
// PinInternal map resolution, and optional program pruning.
//
// When opts.Objects is non-nil, all programs and maps are assigned to the
// struct via LoadAndAssign and the returned collection is nil.
//
// When opts.Objects is nil, only programs listed in opts.EnabledPrograms are
// loaded; the raw *ebpf.Collection is returned so the caller can pick programs
// and maps by name (DetachProgram/DetachMap). The caller owns the returned
// collection and must Close() it.
func LoadSpec(spec *ebpf.CollectionSpec, opts LoadSpecOptions) (*ebpf.Collection, error) {
	if opts.EnabledPrograms != nil {
		for name := range spec.Programs {
			if !slices.Contains(opts.EnabledPrograms, name) {
				delete(spec.Programs, name)
			}
		}
	}

	if opts.Constants != nil {
		if err := RewriteConstants(spec, opts.Constants); err != nil {
			return nil, fmt.Errorf("rewriting BPF constants: %w", err)
		}
	}

	collOpts, err := ResolveMaps(spec, opts.SharedMaps, opts.Mu)
	if err != nil {
		return nil, fmt.Errorf("resolving maps: %w", err)
	}

	collOpts.Programs = ebpf.ProgramOptions{LogSizeStart: 640 * 1024}
	collOpts.Maps = ebpf.MapOptions{PinPath: opts.PinPath}

	if opts.Objects != nil {
		if err := spec.LoadAndAssign(opts.Objects, collOpts); err != nil {
			return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
		}
		return nil, nil
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, *collOpts)
	if err != nil {
		return nil, fmt.Errorf("loading BPF collection: %w", err)
	}
	return coll, nil
}

const (
	MaxMapEntries       uint32 = 1 << 24
	MinMapEntries       uint32 = 64
	MinResizableMapSize uint32 = 64
)

// isResizableMapType returns true for map types where scaling MaxEntries
// is meaningful. Excludes special map types whose MaxEntries has fixed
// semantics (e.g. ProgramArray entries are tail-call slots, not data).
func isResizableMapType(t ebpf.MapType) bool {
	switch t {
	case ebpf.ProgramArray, ebpf.PerfEventArray, ebpf.CGroupArray,
		ebpf.ArrayOfMaps, ebpf.HashOfMaps,
		ebpf.DevMap, ebpf.SockMap, ebpf.CPUMap, ebpf.XSKMap, ebpf.SockHash,
		ebpf.DevMapHash, ebpf.ReusePortSockArray:
		return false
	default:
		return true
	}
}

// SetupMapSizes scales all resizable maps in the spec by globalScaleFactor.
// If globalScaleFactor > 0, sizes are doubled that many times (left shift).
// If globalScaleFactor < 0, sizes are halved that many times (right shift).
// Maps with PinByName are skipped regardless of scale factor.
func SetupMapSizes(spec *ebpf.CollectionSpec, globalScaleFactor int) {
	if globalScaleFactor == 0 {
		return
	}

	for _, mSpec := range spec.Maps {
		if !isResizableMapType(mSpec.Type) {
			continue
		}

		if mSpec.MaxEntries < MinResizableMapSize {
			continue
		}

		if mSpec.Pinning == ebpf.PinByName {
			continue
		}

		oldEntries := mSpec.MaxEntries
		var newEntries uint32

		if globalScaleFactor > 0 {
			newEntries = oldEntries << uint32(globalScaleFactor)
			if newEntries < oldEntries {
				newEntries = MaxMapEntries
			}
		} else {
			newEntries = oldEntries >> uint32(-globalScaleFactor)
		}

		if newEntries < MinMapEntries && oldEntries >= MinMapEntries {
			newEntries = MinMapEntries
		}
		if newEntries > MaxMapEntries {
			newEntries = MaxMapEntries
		}

		mSpec.MaxEntries = newEntries
	}
}

// MissingConstantsError is returned by [ebpf.CollectionSpec.RewriteConstants].
type MissingConstantsError struct {
	// The constants missing from .rodata.
	Constants []string
}

func (m *MissingConstantsError) Error() string {
	return "some constants are missing from .rodata: " + strings.Join(m.Constants, ", ")
}

// RewriteConstants replaces the value of multiple constants.
//
// The constant must be defined like so in the C program:
//
//	volatile const type foobar;
//	volatile const type foobar = default;
//
// Replacement values must be of the same length as the C sizeof(type).
// If necessary, they are marshaled according to the same rules as
// map values.
//
// From Linux 5.5 the verifier will use constants to eliminate dead code.
//
// Returns an error wrapping [MissingConstantsError] if a constant doesn't exist.
func RewriteConstants(cs *ebpf.CollectionSpec, consts map[string]any) error {
	var missing []string
	for n, c := range consts {
		v, ok := cs.Variables[n]
		if !ok {
			missing = append(missing, n)
			continue
		}

		if !v.Constant() {
			return fmt.Errorf("variable %s is not a constant", n)
		}

		if err := v.Set(c); err != nil {
			return fmt.Errorf("rewriting constant %s: %w", n, err)
		}
	}

	if len(missing) != 0 {
		return fmt.Errorf("rewrite constants: %w", &MissingConstantsError{Constants: missing})
	}

	return nil
}
