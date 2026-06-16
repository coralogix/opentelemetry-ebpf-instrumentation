// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen // import "go.opentelemetry.io/obi/pkg/export/otel/tracesgen"

import "strings"

// buildRedactSet converts a slice of sensitive keys into a lookup set.
// Returns nil when keys is empty so callers can short-circuit cheaply.
func buildRedactSet(keys []string) map[string]struct{} {
	if len(keys) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[k] = struct{}{}
	}
	return set
}

// scrubQuery replaces the values of keys present in redactSet in the raw query
// string qs with REDACTED, preserving parameter order and non-sensitive values.
// Returns qs unchanged when redactSet is nil/empty or qs is empty.
// https://opentelemetry.io/docs/specs/semconv/http/http-spans/
func scrubQuery(qs string, redactSet map[string]struct{}) string {
	if len(redactSet) == 0 || qs == "" {
		return qs
	}
	var b strings.Builder
	b.Grow(len(qs))
	rest := qs
	first := true
	for rest != "" {
		var part string
		if i := strings.IndexByte(rest, '&'); i >= 0 {
			part, rest = rest[:i], rest[i+1:]
		} else {
			part, rest = rest, ""
		}
		if !first {
			b.WriteByte('&')
		}
		first = false
		key, val, hasVal := strings.Cut(part, "=")
		if !hasVal {
			b.WriteString(part)
			continue
		}
		b.WriteString(key)
		b.WriteByte('=')
		if _, isSensitive := redactSet[key]; isSensitive {
			b.WriteString("REDACTED")
		} else {
			b.WriteString(val)
		}
	}
	return b.String()
}
