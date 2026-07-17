// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"log/slog"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	kubemeta "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

func TestParsePostgresEnv(t *testing.T) {
	pgEndpoint := func(host string, port int, db string) envCandidate {
		return envCandidate{enricher: pgEnricherName, host: host, port: port, value: db}
	}

	testCases := []struct {
		name     string
		env      map[string]string
		expected []envCandidate
	}{
		{
			name: "URL with credentials keeps only endpoint and database",
			env:  map[string]string{"DATABASE_URL": "postgres://user:secret@pgbouncer:6432/sunflower"},
			expected: []envCandidate{
				pgEndpoint("pgbouncer", 6432, "sunflower"),
			},
		},
		{
			name: "postgresql scheme with query params",
			env:  map[string]string{"DB": "postgresql://u@pgb.sunflower:6432/sunflower?sslmode=disable"},
			expected: []envCandidate{
				pgEndpoint("pgb.sunflower", 6432, "sunflower"),
			},
		},
		{
			name: "two URLs to distinct endpoints",
			env: map[string]string{
				"DATABASE_URL":    "postgres://u:p@pgb-rw:6432/sunflower",
				"DATABASE_RO_URL": "postgres://u:p@pgb-ro:6432/sunflower-ro",
			},
			expected: []envCandidate{
				pgEndpoint("pgb-rw", 6432, "sunflower"),
				pgEndpoint("pgb-ro", 6432, "sunflower-ro"),
			},
		},
		{
			name: "default port",
			env:  map[string]string{"DB": "postgres://u@dbhost/mydb"},
			expected: []envCandidate{
				pgEndpoint("dbhost", 5432, "mydb"),
			},
		},
		{
			name: "PGPORT fills missing URL port",
			env: map[string]string{
				"DB":     "postgres://u@dbhost/mydb",
				"PGPORT": "6543",
			},
			expected: []envCandidate{
				pgEndpoint("dbhost", 6543, "mydb"),
			},
		},
		{
			name: "dbname query parameter",
			env:  map[string]string{"DB": "postgres://u@dbhost:5432?dbname=mydb"},
			expected: []envCandidate{
				pgEndpoint("dbhost", 5432, "mydb"),
			},
		},
		{
			name:     "conflicting path and dbname parameter is skipped",
			env:      map[string]string{"DB": "postgres://u@dbhost:5432/one?dbname=other"},
			expected: nil,
		},
		{
			name: "database defaults to user name",
			env:  map[string]string{"DB": "postgres://sunflower@dbhost:5432"},
			expected: []envCandidate{
				pgEndpoint("dbhost", 5432, "sunflower"),
			},
		},
		{
			name: "PGDATABASE wins over URL user",
			env: map[string]string{
				"DB":         "postgres://someuser@dbhost:5433",
				"PGDATABASE": "mydb",
			},
			// the PG* variables alone contribute no endpoint without PGHOST
			expected: []envCandidate{
				pgEndpoint("dbhost", 5433, "mydb"),
			},
		},
		{
			name: "multi-host URL",
			env:  map[string]string{"DB": "postgres://u:p@h1:5432,h2:5433/db"},
			expected: []envCandidate{
				pgEndpoint("h1", 5432, "db"),
				pgEndpoint("h2", 5433, "db"),
			},
		},
		{
			name: "IPv6 literal is canonicalized",
			env:  map[string]string{"DB": "postgres://u@[::1]:5432/db"},
			expected: []envCandidate{
				pgEndpoint("::1", 5432, "db"),
			},
		},
		{
			name: "PG variables",
			env: map[string]string{
				"PGHOST":     "DBHost",
				"PGPORT":     "6432",
				"PGDATABASE": "mydb",
			},
			expected: []envCandidate{
				pgEndpoint("dbhost", 6432, "mydb"),
			},
		},
		{
			name: "PGHOSTADDR wins over PGHOST",
			env: map[string]string{
				"PGHOST":     "dbhost",
				"PGHOSTADDR": "10.0.0.7",
				"PGDATABASE": "mydb",
			},
			expected: []envCandidate{
				pgEndpoint("10.0.0.7", 5432, "mydb"),
			},
		},
		{
			name: "PGDATABASE falls back to PGUSER",
			env: map[string]string{
				"PGHOST": "dbhost",
				"PGUSER": "myuser",
			},
			expected: []envCandidate{
				pgEndpoint("dbhost", 5432, "myuser"),
			},
		},
		{
			name: "unix socket PGHOST is skipped",
			env: map[string]string{
				"PGHOST":     "/var/run/postgresql",
				"PGDATABASE": "mydb",
			},
			expected: nil,
		},
		{
			name: "multi PGHOST with pairwise PGPORT",
			env: map[string]string{
				"PGHOST":     "h1,h2",
				"PGPORT":     "5432,5433",
				"PGDATABASE": "mydb",
			},
			expected: []envCandidate{
				pgEndpoint("h1", 5432, "mydb"),
				pgEndpoint("h2", 5433, "mydb"),
			},
		},
		{
			name: "mismatched multi PGHOST and PGPORT lengths are skipped",
			env: map[string]string{
				"PGHOST":     "h1,h2,h3",
				"PGPORT":     "5432,5433",
				"PGDATABASE": "mydb",
			},
			expected: nil,
		},
		{
			name:     "PGDATABASE without PGHOST contributes nothing",
			env:      map[string]string{"PGDATABASE": "mydb"},
			expected: nil,
		},
		{
			name: "non-postgres values are ignored",
			env: map[string]string{
				"REDIS_URL": "redis://cache:6379/0",
				"HOME":      "/home/app",
				"BROKEN":    "postgres://u@h:not-a-port/db",
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.expected, parsePostgresEnv(tc.env))
		})
	}
}

type fakeIPMetaLookup map[string]*kubemeta.CachedObjMeta

func (f fakeIPMetaLookup) ObjectMetaByIP(ip string) *kubemeta.CachedObjMeta {
	return f[ip]
}

func k8sObj(kind, name, namespace string) *kubemeta.CachedObjMeta {
	return &kubemeta.CachedObjMeta{Meta: &informer.ObjectMeta{
		Kind: kind, Name: name, Namespace: namespace,
	}}
}

func testEnvEnrichment(t *testing.T, store ipMetaLookup) *envEnrichment {
	cache, err := lru.New[svc.UID, []envCandidate](16)
	require.NoError(t, err)
	return &envEnrichment{log: slog.Default(), store: store, cache: cache}
}

func pgClientSpan(host string, port int, env map[string]string) request.Span {
	return request.Span{
		Type:     request.EventTypeSQLClient,
		SubType:  int(request.DBPostgres),
		Host:     host,
		HostPort: port,
		Service: svc.Attrs{
			UID:      svc.UID{Name: "player-api", Namespace: "sunflower", Instance: "i1"},
			EnvVars:  env,
			Metadata: map[attr.Name]string{attr.K8sNamespaceName: "sunflower"},
		},
	}
}

func TestEnvEnrichmentPostgres(t *testing.T) {
	store := fakeIPMetaLookup{
		"10.96.0.10": k8sObj("Service", "pgbouncer", "sunflower"),
		"10.96.0.11": k8sObj("Service", "pgbouncer-ro", "sunflower"),
		"10.96.0.20": k8sObj("Service", "pgbouncer", "other-team"),
		"10.1.2.3":   k8sObj("Pod", "postgres-0", "sunflower"),
	}

	t.Run("literal IP URL matches destination", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.0.0.7", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@10.0.0.7:6432/sunflower",
		})
		d.enrich(&span)
		assert.Equal(t, "sunflower", span.DBNamespace)
	})

	t.Run("port mismatch does not fill", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.0.0.7", 5432, map[string]string{
			"DATABASE_URL": "postgres://u:p@10.0.0.7:6432/sunflower",
		})
		d.enrich(&span)
		assert.Empty(t, span.DBNamespace)
	})

	t.Run("bare service name resolves in client namespace", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.96.0.10", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@pgbouncer:6432/sunflower",
		})
		d.enrich(&span)
		assert.Equal(t, "sunflower", span.DBNamespace)
	})

	t.Run("bare service name does not match a namesake in another namespace", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.96.0.20", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@pgbouncer:6432/sunflower",
		})
		d.enrich(&span)
		assert.Empty(t, span.DBNamespace)
	})

	t.Run("namespace-qualified and FQDN service forms", func(t *testing.T) {
		for _, host := range []string{
			"pgbouncer.sunflower",
			"pgbouncer.sunflower.svc",
			"pgbouncer.sunflower.svc.cluster.local",
		} {
			d := testEnvEnrichment(t, store)
			span := pgClientSpan("10.96.0.10", 6432, map[string]string{
				"DATABASE_URL": "postgres://u:p@" + host + ":6432/sunflower",
			})
			d.enrich(&span)
			assert.Equal(t, "sunflower", span.DBNamespace, "host form %q", host)
		}
	})

	t.Run("statefulset pod DNS form", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.1.2.3", 5432, map[string]string{
			"DATABASE_URL": "postgres://u:p@postgres-0.postgres.sunflower.svc.cluster.local:5432/mydb",
		})
		d.enrich(&span)
		assert.Equal(t, "mydb", span.DBNamespace)
	})

	t.Run("rw and ro URLs fill their own endpoints", func(t *testing.T) {
		env := map[string]string{
			"DATABASE_URL":    "postgres://u:p@pgbouncer:6432/sunflower",
			"DATABASE_RO_URL": "postgres://u:p@pgbouncer-ro:6432/sunflower-ro",
		}
		d := testEnvEnrichment(t, store)

		rw := pgClientSpan("10.96.0.10", 6432, env)
		d.enrich(&rw)
		assert.Equal(t, "sunflower", rw.DBNamespace)

		ro := pgClientSpan("10.96.0.11", 6432, env)
		d.enrich(&ro)
		assert.Equal(t, "sunflower-ro", ro.DBNamespace)
	})

	t.Run("two databases behind one endpoint stay ambiguous", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.96.0.10", 6432, map[string]string{
			"DATABASE_URL":  "postgres://u:p@pgbouncer:6432/sunflower",
			"MIGRATION_URL": "postgres://u:p@pgbouncer.sunflower:6432/sunflower_admin",
		})
		d.enrich(&span)
		assert.Empty(t, span.DBNamespace)
	})

	t.Run("same database via two host spellings still fills", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.96.0.10", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@pgbouncer:6432/sunflower",
			"PRISMA_URL":   "postgres://u:p@pgbouncer.sunflower.svc.cluster.local:6432/sunflower",
		})
		d.enrich(&span)
		assert.Equal(t, "sunflower", span.DBNamespace)
	})

	t.Run("destination unknown to kubernetes does not fill", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("52.10.20.30", 5432, map[string]string{
			"DATABASE_URL": "postgres://u:p@mydb.rds.amazonaws.com:5432/prod",
		})
		d.enrich(&span)
		assert.Empty(t, span.DBNamespace)
	})

	t.Run("no store only matches literal IPs", func(t *testing.T) {
		d := testEnvEnrichment(t, nil)
		named := pgClientSpan("10.96.0.10", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@pgbouncer:6432/sunflower",
		})
		d.enrich(&named)
		assert.Empty(t, named.DBNamespace)

		literal := pgClientSpan("10.0.0.7", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@10.0.0.7:6432/sunflower",
		})
		// candidates are cached per service instance, so a different env needs a different UID
		literal.Service.UID.Instance = "i2"
		d.enrich(&literal)
		assert.Equal(t, "sunflower", literal.DBNamespace)
	})

	t.Run("existing namespace is never overwritten", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.96.0.10", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@pgbouncer:6432/other",
		})
		span.DBNamespace = "from-startup"
		d.enrich(&span)
		assert.Equal(t, "from-startup", span.DBNamespace)
	})

	t.Run("non-postgres spans are untouched", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.96.0.10", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@pgbouncer:6432/sunflower",
		})
		span.SubType = int(request.DBMySQL)
		d.enrich(&span)
		assert.Empty(t, span.DBNamespace)

		server := pgClientSpan("10.96.0.10", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@pgbouncer:6432/sunflower",
		})
		server.Type = request.EventTypeSQLServer
		d.enrich(&server)
		assert.Empty(t, server.DBNamespace)
	})

	t.Run("bare name without client namespace metadata does not fill", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.96.0.10", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@pgbouncer:6432/sunflower",
		})
		span.Service.Metadata = nil
		d.enrich(&span)
		assert.Empty(t, span.DBNamespace)
	})

	t.Run("identical URLs in two variables deduplicate to one candidate", func(t *testing.T) {
		d := testEnvEnrichment(t, store)
		span := pgClientSpan("10.96.0.10", 6432, map[string]string{
			"DATABASE_URL": "postgres://u:p@pgbouncer:6432/sunflower",
			"PRISMA_URL":   "postgres://u:p@pgbouncer:6432/sunflower",
		})
		d.enrich(&span)
		assert.Equal(t, "sunflower", span.DBNamespace)
		assert.Len(t, d.candidatesFor(&span.Service), 1)
	})
}
