// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// This is the deterministic (non-weaver, non-Docker) backstop for issue #2562
// acceptance criterion 3: "CI detects undeclared attributes ... including
// optional or feature-specific telemetry where practical."
//
// The weaver live-check only validates attributes that a running integration
// test actually exercises, so an optional / feature-gated metric attribute
// that no suite triggers can stay undeclared forever. This test closes that
// gap for METRIC attributes: it enumerates every attribute OBI's metric
// attribute-selection registry (getDefinitions) can emit — with every AttrGroup
// enabled, independent of runtime feature flags — and asserts each one is
// declared either in the OBI schema registry (schemas/obi) or in the pinned
// upstream OpenTelemetry semantic-conventions model.
//
// Scope: metric attributes only. Span attributes are assembled on a different
// path and are out of scope here (see the weaver live-check suites for spans).

// relRepoRoot is the path from this package dir (pkg/export/attributes) to the
// repository root.
const relRepoRoot = "../../.."

// declaredAttributeDirs are the registry roots whose attribute_group `id`s make
// up the set of "declared" attribute names.
var declaredAttributeDirs = []string{
	filepath.Join(relRepoRoot, "schemas", "obi", "groups"),
	filepath.Join(relRepoRoot, "schemas", "obi", ".deps", "upstream-v1.41.0", "model"),
}

// allAttrGroups returns every AttrGroups bit set, so getDefinitions yields the
// maximal attribute set OBI can emit rather than only what a given feature
// combination enables.
func allAttrGroups() AttrGroups {
	var g AttrGroups
	for _, bit := range []AttrGroups{
		GroupKubernetes, GroupContainer, GroupPrometheus, GroupHTTPRoutes,
		GroupNetIfaceDirection, GroupNetCIDR, GroupTraces, GroupApp, GroupNet,
		GroupNetKube, GroupAppKube, GroupServerInfo, GroupHTTPClientInfo,
		GroupGRPCClientInfo, GroupHTTPCommon, GroupHost, GroupMessaging,
		GroupNetGeoIP, GroupStats, GroupStatsKube,
	} {
		g.Add(bit)
	}
	return g
}

// internalSelectorNames are entries that appear in getDefinitions() but are
// never emitted as literal OTLP attribute keys — they are internal selector
// placeholders that span_getters.go remaps to a real semconv attribute at
// emission time. They must not be treated as registry attributes.
//
//   - "gen_ai.token.type_output": a GenAI event produces two token metrics
//     (input, output) from one span. This synthetic selector key exists so the
//     selector can carry both; span_getters.go (case attr.GenAITokenTypeOutput)
//     emits the real semconv `gen_ai.token.type` key with value "output".
//   - "db.response.error": not a spec attribute. tracesgen.go reads its value
//     only to populate the span status message, then removes it from the final
//     span attributes (see the m.Remove call in tracesgen.go), so it is never
//     emitted.
var internalSelectorNames = map[attr.Name]struct{}{
	attr.GenAITokenTypeOutput: {},
	attr.DBResponseError:      {},
}

// emittedMetricAttributes collects every attribute name reachable through the
// metric attribute-selection registry with all groups enabled, minus the
// internal selector placeholders that are remapped before emission.
func emittedMetricAttributes() map[attr.Name]struct{} {
	defs := getDefinitions(allAttrGroups(), GroupAttributes{})
	emitted := map[attr.Name]struct{}{}
	for section := range defs {
		grp := defs[section]
		for name := range grp.All() {
			if _, internal := internalSelectorNames[name]; internal {
				continue
			}
			emitted[name] = struct{}{}
		}
	}
	return emitted
}

// registryFile is the subset of the semconv registry YAML schema we need: every
// group's attributes, keyed by their fully-qualified `id`.
type registryFile struct {
	Groups []struct {
		Attributes []struct {
			ID string `yaml:"id"`
		} `yaml:"attributes"`
	} `yaml:"groups"`
}

// loadDeclaredAttributes walks the OBI and upstream registries and returns the
// set of every declared attribute id.
func loadDeclaredAttributes(t *testing.T) map[string]struct{} {
	t.Helper()
	declared := map[string]struct{}{}
	for _, root := range declaredAttributeDirs {
		info, err := os.Stat(root)
		require.NoErrorf(t, err, "registry dir %s not found (did `make fetch-upstream-semconv` run?)", root)
		require.Truef(t, info.IsDir(), "%s is not a directory", root)

		err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var rf registryFile
			if err := yaml.Unmarshal(raw, &rf); err != nil {
				// Not every YAML file is a registry file; skip unparseable ones.
				return nil
			}
			for _, g := range rf.Groups {
				for _, a := range g.Attributes {
					if a.ID != "" {
						declared[a.ID] = struct{}{}
					}
				}
			}
			return nil
		})
		require.NoErrorf(t, err, "walking registry dir %s", root)
	}
	return declared
}

func TestEmittedMetricAttributesAreDeclared(t *testing.T) {
	emitted := emittedMetricAttributes()
	require.NotEmpty(t, emitted, "getDefinitions() returned no attributes")

	declared := loadDeclaredAttributes(t)
	require.NotEmpty(t, declared, "no attributes loaded from the registries")

	var undeclared []string
	for name := range emitted {
		if _, ok := declared[string(name)]; !ok {
			undeclared = append(undeclared, string(name))
		}
	}
	sort.Strings(undeclared)

	require.Emptyf(t, undeclared,
		"%d metric attribute(s) emitted by getDefinitions() are declared in neither "+
			"schemas/obi nor upstream semconv — declare them in schemas/obi/groups "+
			"or add a documented exception:\n  %s",
		len(undeclared), strings.Join(undeclared, "\n  "))
}
