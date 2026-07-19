# Integration test suites

Suites are defined in Go. The base OBI service (`docker.StdOBI`) and the
standard infrastructure — otelcol, prometheus, jaeger and the weaver semconv
validator, fully wired (`docker.StdServices`) — live in
[components/docker/compose.go](components/docker/compose.go). A suite passes
its services to `docker.StdStack`, which merges the standard infrastructure
underneath. A `compose-suite-*.yml` overlay exists only when a suite carries
extra services with heavy parameterization; most suites need no yml at all.
`make lint` enforces this layout (`scripts/lint-compose-layout.sh`).

## Adding a suite

For the common case — one instrumented test server plus the standard
infrastructure — no yml file is needed:

```go
func TestSuite_MyProto(t *testing.T) {
    // log derives from the test name: testoutput/test-suite-my-proto.log
    compose := docker.SuiteStackServices(t, docker.StdStack(map[string]*docker.ServiceDef{
        // shared env skeleton, standard volumes and testserver wiring are
        // filled in; Env carries only the suite-specific keys
        "obi": docker.TestserverOBI("run-myproto", map[string]string{
            "OTEL_EBPF_TRACES_INSTRUMENTATIONS": "myproto",
        }),
        "testserver": docker.Testserver("myproto", "Dockerfile", "hatest-testserver-myproto", "8381:8080"),
    }))
    runSuite(t, compose, nil, true,
        st("my tests", testMyProto))
}
```

Guidelines, in order of preference:

1. **Copy a sibling suite.** If the topology matches an existing suite
   (SQL stores, kafka, mqtt, ...), copy its call site and change the
   parameters (see `pythonSQLSuite` and its three callers).
2. **Backing stores are plain `ServiceDef` entries.** Databases/brokers are
   declared next to the testserver in the same map (see the `sqlserver`
   entries in the SQL suites).
3. **Non-standard infra wiring** (different published ports, no jaeger,
   another collector config): take the standard definition and mutate the
   fields that differ —

   ```go
   vOtelcol := docker.StdServices()["otelcol"]
   vOtelcol.Command = []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"}
   // then in the map: "otelcol": vOtelcol, "jaeger": nil,
   ```

   A `nil` entry removes the service; `StdStack` also drops dangling
   `depends_on` references to it.
4. **Exotic obi needs** (custom obi image/build, entrypoint, cgroup, ...):
   every field is modeled on `docker.OBI` — set `Image`, `BuildContext`,
   `BuildDockerfile`, `Entrypoint`, ... directly (see the javaagent obi in
   `java_vthreads_test.go`). Never declare `obi:` in yml; the lint rejects it.
5. **OBI configuration**: prefer env vars in `OBI.Env`. Inline yaml via
   `OBI.ConfigYAML` is only for structures env cannot express (routes
   patterns, discovery services, attribute selections). Reuse an existing
   config plus env overrides before adding one: env always wins over yaml.

Never add a standalone `docker-compose-*.yml` or shared layer/fragment yml —
the lint rejects both.

## Verifying

Run the suite with:

```bash
go test -v -run '^TestSuite_MyProto$' -timeout 10m --tags=integration ./internal/test/integration/
```
