// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	pgEnricherName = "postgres"
	pgDefaultPort  = 5432
)

// postgresEnvEnricher fills db.namespace on Postgres client spans whose
// StartupMessage was never observed (connections opened before attach), from
// postgres:// URLs and PG* variables in the owning process environment
var postgresEnvEnricher = envEnricher{
	name:  pgEnricherName,
	parse: parsePostgresEnv,
	applies: func(span *request.Span) bool {
		return span.Type == request.EventTypeSQLClient &&
			span.SubType == int(request.DBPostgres) &&
			span.DBNamespace == ""
	},
	apply: func(span *request.Span, value string) {
		span.DBNamespace = value
	},
}

func parsePostgresEnv(env map[string]string) []envCandidate {
	var out []envCandidate
	for _, v := range env {
		v = strings.TrimSpace(v)
		lv := strings.ToLower(v)
		if strings.HasPrefix(lv, "postgres://") || strings.HasPrefix(lv, "postgresql://") {
			out = append(out, parsePostgresURL(v, env)...)
		}
	}
	return append(out, parsePostgresVars(env)...)
}

func parsePostgresURL(raw string, env map[string]string) []envCandidate {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}

	db := strings.TrimPrefix(u.Path, "/")
	if strings.Contains(db, "/") {
		return nil
	}
	if qdb := u.Query().Get("dbname"); qdb != "" {
		if db != "" && db != qdb {
			return nil
		}
		db = qdb
	}
	// libpq resolution order: URI database, then PGDATABASE, then the user name
	if db == "" {
		db = env["PGDATABASE"]
	}
	if db == "" && u.User != nil {
		db = u.User.Username()
	}
	if db == "" {
		db = env["PGUSER"]
	}
	if db == "" {
		return nil
	}

	var out []envCandidate
	for hostPort := range strings.SplitSeq(u.Host, ",") {
		host, port, ok := splitPgHostPort(hostPort, env)
		if !ok {
			return nil
		}
		out = append(out, envCandidate{enricher: pgEnricherName, host: host, port: port, value: db})
	}
	return out
}

func parsePostgresVars(env map[string]string) []envCandidate {
	db := env["PGDATABASE"]
	if db == "" {
		db = env["PGUSER"]
	}
	if db == "" {
		return nil
	}

	hosts := env["PGHOSTADDR"]
	if hosts == "" {
		hosts = env["PGHOST"]
	}
	// an absolute path means Unix-socket connections, which have no TCP endpoint
	if hosts == "" || strings.HasPrefix(hosts, "/") {
		return nil
	}

	hostList := strings.Split(hosts, ",")
	portList := strings.Split(env["PGPORT"], ",")
	if len(portList) > 1 && len(portList) != len(hostList) {
		return nil
	}

	var out []envCandidate
	for i, h := range hostList {
		p := portList[0]
		if len(portList) > 1 {
			p = portList[i]
		}
		hp := h
		if p != "" {
			hp = net.JoinHostPort(strings.Trim(strings.TrimSpace(h), "[]"), p)
		}
		host, port, ok := splitPgHostPort(hp, nil)
		if !ok {
			return nil
		}
		out = append(out, envCandidate{enricher: pgEnricherName, host: host, port: port, value: db})
	}
	return out
}

// splitPgHostPort normalizes one host[:port] element: hosts are lowercased,
// literal IPs canonicalized, and a missing port falls back to PGPORT then 5432
func splitPgHostPort(hostPort string, env map[string]string) (string, int, bool) {
	hostPort = strings.TrimSpace(hostPort)
	host := hostPort
	port := 0
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return "", 0, false
		}
		host, port = h, n
	}
	if port == 0 {
		port = pgDefaultPort
		if p := env["PGPORT"]; p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > 65535 {
				return "", 0, false
			}
			port = n
		}
	}

	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" {
		return "", 0, false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		host = a.Unmap().String()
	}
	return host, port, true
}
