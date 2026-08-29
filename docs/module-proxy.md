# Go module proxy assets

OBI is a single Go module rooted at the repository (`go.opentelemetry.io/obi`).
It generates its eBPF bindings (bpf2go outputs) and builds its embedded Java
agent at build time and does **not** commit those artifacts. As a result, the
module as fetched directly from VCS does not compile, so OBI cannot be consumed
as an ordinary `go get`-able dependency straight from the Git tag.

To make OBI consumable as a Go module, each release additionally publishes a
proper, self-contained Go module zip built from the fully generated working
tree. The Go toolchain is pointed at these assets through a `mod`-type vanity
redirector (a separate `mod_proxy` deployment, out of scope for this repo); the
redirector serves the assets as a standard
[Go module proxy](https://go.dev/ref/mod#module-proxy) and falls back to
`proxy.golang.org` for versions released before this mechanism existed.

## Release assets

The `build-artifacts` job of [`release.yml`](../.github/workflows/release.yml)
runs `make release-module` after `make release-source`. It reuses the same fully
generated working tree that `release-source` produced (bpf2go outputs plus the
real embedded Java agent JAR at `pkg/internal/java/embedded/obi-java-agent.jar`)
and writes three files into `dist/`, where `<version>` is the release tag (for
example `v1.2.3`):

| Asset | Purpose |
| --- | --- |
| `obi-<version>.module.zip` | The module zip, built with `golang.org/x/mod/zip.CreateFromDir` for `module.Version{Path: "go.opentelemetry.io/obi", Version: <version>}`. Entries are prefixed `go.opentelemetry.io/obi@<version>/...`; nested module directories and any `vendor/` directory are excluded automatically, exactly as the Go module proxy serves them. |
| `obi-<version>.module.mod` | A copy of the root `go.mod`, served as the proxy `.mod` file. |
| `obi-<version>.module.info` | JSON `{"Version":"<version>","Time":"<RFC3339 UTC>"}`, where `Time` is the committer time of the released revision. |

These three files are attached to the GitHub release alongside the existing
tarballs and SBOMs, and are covered by the release `SHA256SUMS` (the
`release-checksums` make target matches `obi-<version>.module.*`).

The zip is built by the small tool at [`cmd/modzip`](../cmd/modzip/main.go):

```console
go run ./cmd/modzip --version v1.2.3 --source-dir . --dist-dir ./dist
```

> [!IMPORTANT]
> The module zip embeds the real Java agent JAR via `go:embed`. The JAR must be
> the build output (not the committed placeholder) in the working tree when the
> zip is created. `make release-module` therefore must run **after**
> `make release-source` in the same job and must not re-run `docker-generate`.

## Release gate

Before any module zip is published, [`scripts/verify-module-zip.sh`](../scripts/verify-module-zip.sh)
acts as a gate that fails the release if the zip would not compile. It:

1. Lays out a `file://` `GOPROXY` from the `dist/` assets:
   `proxy/go.opentelemetry.io/obi/@v/{list,<version>.info,<version>.mod,<version>.zip}`.
2. Creates a throwaway consumer module in a temp dir that imports the OBI
   Collector entrypoint package, `go.opentelemetry.io/obi/collector`.
3. Resolves and cross-compiles the consumer through that proxy:

   ```console
   GOPROXY="file://<proxy>,https://proxy.golang.org" \
   GONOSUMDB=go.opentelemetry.io/obi GOFLAGS=-mod=mod \
   go get go.opentelemetry.io/obi@<version> \
     && GOOS=linux CGO_ENABLED=0 go build ./...
   ```

The public proxy is kept as a fallback so transitive dependencies resolve
normally. `GONOSUMDB` skips only the checksum-database lookup for the
locally-built OBI module (it is not yet recorded in `sum.golang.org`); the global
sum database stays enabled for everything else. A non-zero exit aborts the
release.

Pass `--skip-build` to verify only the proxy layout and module resolution
without the cross-compile (useful where the generated eBPF code is absent, e.g.
a plain VCS checkout, in which case the full build cannot succeed).

## Version index

The redirector needs a `@v/list` of available module versions. This is stored as
a single `list.txt` asset on a dedicated utility GitHub release tagged
`module-index` ("Utility release holding the Go module proxy version index. Do
not delete.").

- [`.github/workflows/module_index.yml`](../.github/workflows/module_index.yml)
  runs on `release: published`. For any release whose tag matches `^v[0-9]` and
  that carries an `obi-<tag>.module.zip` asset, it downloads `list.txt` from the
  `module-index` release (creating it empty if needed), appends the tag if
  absent, re-sorts with `sort -V -u`, and re-uploads with `--clobber`. A
  workflow-level `concurrency` group serializes updates so concurrent releases do
  not race on the shared asset.
- [`scripts/seed-module-index.sh`](../scripts/seed-module-index.sh) is a one-time
  maintainer helper that seeds `list.txt` from the full history of existing `v*`
  semver tags. Seeding the entire history is correct because pre-cutover versions
  resolve through `proxy.golang.org` passthrough on the redirector, so listing
  them keeps `go list -m -versions go.opentelemetry.io/obi` complete.
