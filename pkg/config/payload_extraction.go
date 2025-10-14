// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

type PayloadExtraction struct {
	HTTP HTTPConfig `yaml:"http"`
}

func (p PayloadExtraction) Enabled() bool {
	return p.HTTP.AWS.Enabled || p.HTTP.GraphQL.Enabled
}

type HTTPConfig struct {
	// GraphQL payload extraction and parsing
	GraphQL GraphQLConfig `yaml:"graphql"`
	// AWS payload extraction and parsing
	AWS AWSConfig `yaml:"aws"`
}

type GraphQLConfig struct {
	// Enable GraphQL payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_GRAPHQL_ENABLED"`
}

type AWSConfig struct {
	// Enable AWS services (S3, sqs, ...) payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_AWS_ENABLED"`
}
