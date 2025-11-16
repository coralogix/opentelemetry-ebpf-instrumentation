// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import "go.opentelemetry.io/obi/pkg/appolly/services"

type LogEnricherConfig struct {
	Services []LogEnricherServiceConfig `yaml:"services"`
}

func (p LogEnricherConfig) Enabled() bool {
	return len(p.Services) > 0
}

type LogFormat string

const (
	LogFormatInfer LogFormat = "infer"
	LogFormatJSON  LogFormat = "json"
	LogFormatPlain LogFormat = "plain"
)

type LogEnricherServiceConfig struct {
	// Service should also be contained in 'services' in the Discovery section
	Service services.GlobDefinitionCriteria `yaml:"service" validate:"required"`

	// Specify the log format:
	//   json: for JSON formatted logs, trace and span IDs will be injected as separate JSON fields
	//   plain: for plain text logs, trace and span IDs will be injected as key=value pairs at the end of the log line
	//   infer: try to infer the log format from the first log line (default)
	// TODO(matt): only JSON for now?
	Format LogFormat `yaml:"format"`

	// TODO(matt): specify log casing, spaces, etc?
}
