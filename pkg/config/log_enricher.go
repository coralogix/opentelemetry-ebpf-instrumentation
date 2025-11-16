// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

type LogEnricherConfig struct {
	// Services to enable log enrichment for
	Services []LogEnricherServiceConfig `yaml:"services"`

	// CacheTTL defines the TTL for cached file descriptors
	// Default: 30m
	CacheTTL time.Duration `yaml:"cache_ttl" validate:"gt=1m" env:"OTEL_EBPF_BPF_LOG_ENRICHER_CACHE_TTL"`

	// CacheSize defines the maximum number of cached file descriptors
	// Default: 128
	CacheSize int `yaml:"cache_size" validate:"gt=64" env:"OTEL_EBPF_BPF_LOG_ENRICHER_CACHE_SIZE"`
}

func (p LogEnricherConfig) Enabled() bool {
	return len(p.Services) > 0
}

type LogEnricherServiceConfig struct {
	// Service should also be contained in 'services' in the Discovery section
	Service services.GlobDefinitionCriteria `yaml:"service" validate:"required"`
}
