// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import "testing"

// TestZZ_WeaverValidate stops the in-cluster weaver pod and validates the
// telemetry it received against the OBI semconv registry. The `ZZ` prefix +
// `z_` filename make it sort last so it runs after the suite's real tests but
// while the kind cluster is still up. Observe mode: it logs which advisories
// would fail under enforce, but never fails the test, while this suite is
// brought online weaver-first.
func TestZZ_WeaverValidate(t *testing.T) {
	cluster.ValidateWeaver(t, true /* observeOnly */)
}
