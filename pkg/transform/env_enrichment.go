// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	kubemeta "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func eelog() *slog.Logger {
	return slog.With("component", "transform.EnvEnrichment")
}

// envCandidate is one endpoint declared in a process environment, together
// with the value it enriches matching spans with
type envCandidate struct {
	enricher string
	host     string
	port     int
	value    string
}

// envEnricher plugs one protocol into the env enrichment node: parse extracts
// declared endpoints from a process environment, applies selects the spans it
// may enrich, and apply sets the enriched field
type envEnricher struct {
	name    string
	parse   func(env map[string]string) []envCandidate
	applies func(span *request.Span) bool
	apply   func(span *request.Span, value string)
}

var envEnrichers = []envEnricher{postgresEnvEnricher}

type ipMetaLookup interface {
	ObjectMetaByIP(ip string) *kubemeta.CachedObjMeta
}

type envEnrichment struct {
	log   *slog.Logger
	store ipMetaLookup
	cache *lru.Cache[svc.UID, []envCandidate]
}

// EnvEnrichmentProvider enriches spans with values declared in the owning
// process environment. A value is only used when its endpoint provably
// denotes the span destination
func EnvEnrichmentProvider(ctxInfo *global.ContextInfo, enabled bool,
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !enabled {
			return swarm.Bypass(input, output)
		}

		var store ipMetaLookup
		if ctxInfo.K8sInformer.IsKubeEnabled() {
			s, err := ctxInfo.K8sInformer.Get(ctx)
			if err != nil {
				return nil, fmt.Errorf("initializing EnvEnrichmentProvider: %w", err)
			}
			store = s
		}

		cache, err := lru.New[svc.UID, []envCandidate](1024)
		if err != nil {
			return nil, fmt.Errorf("initializing EnvEnrichmentProvider cache: %w", err)
		}

		d := &envEnrichment{log: eelog(), store: store, cache: cache}

		in := input.Subscribe(msg.SubscriberName("transform.EnvEnrichment"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, d.log.Debug, func(spans []request.Span) {
				for i := range spans {
					d.enrich(&spans[i])
				}
				output.SendCtx(ctx, spans)
			})
		}, nil
	}
}

func (d *envEnrichment) enrich(span *request.Span) {
	var candidates []envCandidate
	loaded := false
	for i := range envEnrichers {
		p := &envEnrichers[i]
		if !p.applies(span) {
			continue
		}
		if !loaded {
			candidates = d.candidatesFor(&span.Service)
			loaded = true
		}
		if value, ok := d.matchDestination(span, p.name, candidates); ok {
			p.apply(span, value)
			d.log.Debug("enriched span from process environment",
				"enricher", p.name, "value", value, "host", span.Host, "port", span.HostPort)
		}
	}
}

// matchDestination returns the single value of the enricher's candidates whose
// endpoint provably denotes the span destination: same port, and either the
// same literal IP or the Kubernetes object the destination IP belongs to.
// Distinct values behind one destination make it ambiguous: nothing is returned
func (d *envEnrichment) matchDestination(span *request.Span, enricher string, candidates []envCandidate) (string, bool) {
	spanAddr, spanAddrErr := netip.ParseAddr(span.Host)
	var om *kubemeta.CachedObjMeta
	omLoaded := false

	value := ""
	matched := false
	for _, c := range candidates {
		if c.enricher != enricher || c.port != span.HostPort {
			continue
		}
		hostMatch := false
		if a, err := netip.ParseAddr(c.host); err == nil {
			hostMatch = spanAddrErr == nil && a.Unmap() == spanAddr.Unmap()
		} else {
			if !omLoaded {
				om = d.destMeta(span.Host)
				omLoaded = true
			}
			hostMatch = hostMatchesK8sObject(c.host, om, span.Service.Metadata[attr.K8sNamespaceName])
		}
		if !hostMatch {
			continue
		}
		if matched && value != c.value {
			return "", false
		}
		value = c.value
		matched = true
	}
	return value, matched
}

func (d *envEnrichment) destMeta(ip string) *kubemeta.CachedObjMeta {
	if d.store == nil {
		return nil
	}
	return d.store.ObjectMetaByIP(ip)
}

func (d *envEnrichment) candidatesFor(s *svc.Attrs) []envCandidate {
	if cands, ok := d.cache.Get(s.UID); ok {
		return cands
	}
	var cands []envCandidate
	if len(s.EnvVars) > 0 {
		for i := range envEnrichers {
			cands = append(cands, envEnrichers[i].parse(s.EnvVars)...)
		}
		cands = dedupCandidates(cands)
	}
	d.cache.Add(s.UID, cands)
	return cands
}

// hostMatchesK8sObject reports whether a DNS name from the client configuration
// denotes the Kubernetes object the span actually connected to, following
// cluster-DNS name semantics. Bare service names resolve in the client's own
// namespace, so they only match when that namespace is known and equal
func hostMatchesK8sObject(host string, om *kubemeta.CachedObjMeta, clientK8sNs string) bool {
	if om == nil || om.Meta == nil {
		return false
	}
	name, ns, kind := om.Meta.Name, om.Meta.Namespace, om.Meta.Kind
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	switch {
	case len(labels) == 1:
		return kind == "Service" && labels[0] == name && clientK8sNs != "" && ns == clientK8sNs
	case len(labels) == 2:
		return kind == "Service" && labels[0] == name && labels[1] == ns
	case labels[2] == "svc":
		return kind == "Service" && labels[0] == name && labels[1] == ns
	case len(labels) >= 4 && labels[3] == "svc":
		// <pod-hostname>.<service>.<namespace>.svc.<domain>
		return kind == "Pod" && labels[0] == name && labels[2] == ns
	default:
		return false
	}
}

func dedupCandidates(cands []envCandidate) []envCandidate {
	if len(cands) == 0 {
		return nil
	}
	seen := make(map[envCandidate]struct{}, len(cands))
	out := cands[:0]
	for _, c := range cands {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}
