// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"
	"fmt"
)

var ErrRestartRequired = errors.New("restart required")

type restartRequiredError struct {
	msg string
}

func (e *restartRequiredError) Error() string { return e.msg }

func (e *restartRequiredError) Is(target error) bool { return target == ErrRestartRequired }

func RestartRequiredf(format string, args ...any) error {
	return &restartRequiredError{msg: fmt.Sprintf(format, args...)}
}
