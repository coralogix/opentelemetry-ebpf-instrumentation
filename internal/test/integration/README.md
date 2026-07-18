# Integration test suites

Suites are defined in Go and composed from shared docker-compose layers.
There is one OBI definition (`compose-base.yml`), one standard infrastructure
bundle (`compose-infra.yml`: otelcol, prometheus, jaeger, weaver, wired), and
per-suite configuration lives in the test code. `make lint` enforces this
layout (`scripts/lint-compose-layout.sh`).

## Adding a suite

For the common case — one instrumented test server plus the standard
infrastructure — no yml file is needed at all:

```go
func TestSuite_MyProto(t *testing.T) {
    // log file derives from the test name: testoutput/test-suite-my-proto.log
    compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
            "obi": docker.StdOBI(docker.OBI{
                NetworkMode: "service:testserver",
                Pid:         "service:testserver",
                RunDir:      "run-myproto", // expands to the standard volume set
                DependsOn:   map[string]string{"testserver": "service_started"},
                Env: map[string]string{
                    // only the suite-specific keys: StdOBI fills the shared
                    // skeleton (GOCOVERDIR, printer, log level, timeouts, ...)
                    "OTEL_EBPF_OPEN_PORT":               "8080",
                    "OTEL_EBPF_TRACES_INSTRUMENTATIONS": "myproto",
                },
            }),
            "testserver": &docker.ServiceDef{
                BuildContext:    "../../../internal/test/integration/components/myproto/",
                BuildDockerfile: "Dockerfile",
                Image:           "hatest-testserver-myproto",
                Ports:           []string{"8381:8080"},
                DependsOn:       map[string]string{"otelcol": "service_started"},
            },
        },
    }, "compose-base.yml", "compose-infra.yml")
    require.NoError(t, compose.Up())
    t.Run("my tests", testMyProto)
    runWeaverValidation(t)
    require.NoError(t, compose.Close())
}
```

Guidelines, in order of preference:

1. **Reuse a family.** If the topology matches an existing family file
   (`compose-family-sql.yml`, `-kafka-zk.yml`, `-mqtt.yml`, ...), copy one of
   its call sites and change the parameters (see `pythonSQLSuite`).
2. **Add a backing store as a fragment.** Databases/brokers shared between
   suites live in `compose-frag-<store>.yml`. Reuse them; add a new fragment
   only for a store more than one suite will use — otherwise declare it as
   another `ServiceDef` entry.
3. **Non-standard infra wiring** (different published ports, no jaeger, ...):
   use the granular fragments (`compose-frag-otelcol.yml` etc.) instead of
   `compose-infra.yml` and declare ports/depends_on for those services in a
   small `compose-suite-<name>.yml` overlay.
4. **Exotic obi needs** (custom obi image/build, entrypoint, cgroup, ...):
   these are the only reason to declare `obi:` in yml. Keep the stub to
   exactly those keys and add the file to the allowlist in
   `scripts/lint-compose-layout.sh` — consciously.
5. **OBI configuration**: prefer env vars in `OBI.Env`. A
   `configs/obi-config-*.yml` file is only for structures env cannot express
   (routes patterns, discovery services, attribute selections). Reuse an
   existing config plus env overrides before adding a file: env always wins
   over yaml.

Never add a standalone `docker-compose-*.yml` — the lint rejects it.

## Verifying

`docker compose -f compose-base.yml -f compose-infra.yml [...] config` renders
the merged stack. Run the suite with:

```bash
go test -v -run '^TestSuite_MyProto$' -timeout 10m --tags=integration ./internal/test/integration/
```
