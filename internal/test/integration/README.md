# Integration test suites

Suites are defined in Go plus one `docker-compose-<suite>.yml` per suite.
The obi service (`docker.NewOBI`) and the standard infrastructure — otelcol,
prometheus, jaeger and the weaver semconv validator, fully wired
(`docker.NewServices`) — live in
[components/docker/compose.go](components/docker/compose.go); the suite's yml
carries only its unique services (test servers, brokers, databases).
`docker.NewStack` merges the standard infrastructure under the suite's Go
services and the yml is layered in by filename. `make lint` enforces this
layout (`scripts/lint-compose-layout.sh`).

## Adding a suite

```go
func TestSuite_MyProto(t *testing.T) {
    // log derives from the test name: testoutput/test-suite-my-proto.log
    compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
        // shared env skeleton, standard volumes and testserver wiring are
        // filled in; Env carries only the suite-specific keys
        "obi": docker.TestserverOBI("run-myproto", map[string]string{
            "OTEL_EBPF_TRACES_INSTRUMENTATIONS": "myproto",
        }),
    }), "docker-compose-myproto.yml")
    runSuite(t, compose, nil, true,
        st("my tests", testMyProto))
}
```

with `docker-compose-myproto.yml` declaring just the test server (and any
backing store):

```yaml
services:
  testserver:
    build:
      context: ../../..
      dockerfile: ./internal/test/integration/components/myproto/Dockerfile
    image: hatest-testserver-myproto
    ports:
      - "8381:8080"
```

Guidelines:

1. **Never declare `obi`, `otelcol`, `prometheus`, `jaeger` or `weaver` in a
   suite yml** — the lint rejects it. Non-standard infra wiring uses Go
   variants:

   ```go
   vOtelcol := docker.NewServices()["otelcol"]
   vOtelcol.Command = []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"}
   // then in the map: "otelcol": vOtelcol, "jaeger": nil,
   ```

   A `nil` entry removes the service and its dangling `depends_on`
   references. Common variants exist as helpers: `OtelcolNoJaeger`,
   `OtelcolAfterOBI`, `JaegerUI`.
2. **Exotic obi needs** (custom image/build, entrypoint, cgroup, ...): every
   field is modeled on `docker.OBI`. `NoDefaultEnv: true` opts out of the
   shared env defaults when the suite owns its complete environment.
3. **OBI configuration**: prefer env vars in `OBI.Env`. Inline yaml via
   `OBI.ConfigYAML` is only for structures env cannot express (routes
   patterns, discovery services, attribute selections).
4. **Env hygiene**: `obiEnv` in compose.go carries the shared defaults (log
   level/format, trace printer, timings). A suite's `Env` holds only its
   real deltas, as literal values. Discovery values (`OTEL_EBPF_OPEN_PORT`,
   `OTEL_EBPF_EXECUTABLE_PATH`) are never defaulted: declare them explicitly.

## Verifying

Run the suite with:

```bash
go test -v -run '^TestSuite_MyProto$' -timeout 10m --tags=integration ./internal/test/integration/
```

`OBI_RENDER_ONLY=1` diverts `compose.Up()` into `docker compose config`,
dumping every suite's rendered stack under `testoutput/render/` for quick
inspection without starting containers.
