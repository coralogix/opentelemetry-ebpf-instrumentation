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

// LoadSpec loads a BPF collection spec into the provided objects, handling
// constant rewriting, PinInternal map resolution, and bpffs pin path setup.
// Notes about some parameters:
// - constants: optional map of BPF constants to rewrite (may be nil)
// - sharedMaps: map store for PinInternal maps, shared across specs within the same agent
// - pinPath: bpffs pin path for PinByName maps (empty string to skip)
func LoadSpec(spec *ebpf.CollectionSpec, objects any, constants map[string]any, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, pinPath string) error {
	if constants != nil {
		if err := RewriteConstants(spec, constants); err != nil {
			return fmt.Errorf("rewriting BPF constants: %w", err)
		}
	}

	collOpts, err := ResolveMaps(spec, sharedMaps, mu)
	if err != nil {
		return fmt.Errorf("resolving maps: %w", err)
	}

	collOpts.Programs = ebpf.ProgramOptions{LogSizeStart: 640 * 1024}
	collOpts.Maps = ebpf.MapOptions{PinPath: pinPath}

	if err := spec.LoadAndAssign(objects, collOpts); err != nil {
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	return nil
}

// pruneToEnabled removes from spec.Programs any program whose name is not in
// the enabled set. To keep every program in the spec, callers must pass the
// full list of program names — there is no special-cased "keep all" value, so
// an empty slice unambiguously drops everything.
func pruneToEnabled(spec *ebpf.CollectionSpec, enabled []string) {
	for name := range spec.Programs {
		if !slices.Contains(enabled, name) {
			delete(spec.Programs, name)
		}
	}
}

// LoadPartial behaves like LoadSpec but loads via NewCollectionWithOptions
// instead of LoadAndAssign, returning the *ebpf.Collection so the caller can
// pick programs and maps off it by name (typical use: per-probe attach loops
// where only a subset of programs is enabled at runtime).
//
// Programs whose name is not in enabledPrograms are removed from spec.Programs
// before load and never enter the kernel. To keep every program, pass the full
// list of program names; an empty slice drops everything.
//
// The caller owns the returned *ebpf.Collection: detach the maps/programs it
// needs, then Close() to free the rest.
//
// Notes about other parameters match LoadSpec:
// - constants: optional map of BPF constants to rewrite (may be nil)
// - sharedMaps: map store for PinInternal maps, shared across specs within the same agent
// - pinPath: bpffs pin path for PinByName maps (empty string to skip)
func LoadPartial(spec *ebpf.CollectionSpec, enabledPrograms []string, constants map[string]any, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, pinPath string) (*ebpf.Collection, error) {
	pruneToEnabled(spec, enabledPrograms)

	if constants != nil {
		if err := RewriteConstants(spec, constants); err != nil {
			return nil, fmt.Errorf("rewriting BPF constants: %w", err)
		}
	}

	collOpts, err := ResolveMaps(spec, sharedMaps, mu)
	if err != nil {
		return nil, fmt.Errorf("resolving maps: %w", err)
	}

	collOpts.Programs = ebpf.ProgramOptions{LogSizeStart: 640 * 1024}
	collOpts.Maps = ebpf.MapOptions{PinPath: pinPath}

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
