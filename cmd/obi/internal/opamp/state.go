// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package opamp // import "go.opentelemetry.io/obi/cmd/obi/internal/opamp"

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	instanceUIDFile  = "instance_uid"
	remoteConfigFile = "remote_config.yaml"
	remoteHashFile   = "remote_config.hash"
)

type stateDir string

func (s stateDir) enabled() bool { return s != "" }

func (s stateDir) read(name string) ([]byte, error) {
	if !s.enabled() {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Join(string(s), name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func (s stateDir) write(name string, data []byte) error {
	if !s.enabled() {
		return nil
	}
	if err := os.MkdirAll(string(s), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(string(s), name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(string(s), name))
}

func (s stateDir) remove(names ...string) error {
	if !s.enabled() {
		return nil
	}
	var errs []error
	for _, name := range names {
		if err := os.Remove(filepath.Join(string(s), name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
