# Pushing internal images (JFrog / ECR)

Two dispatch-triggered workflows build the OBI image from any git ref and
push a multi-arch (amd64 + arm64) image to an internal registry:

| Workflow | Registry | Image |
|---|---|---|
| `cx-build-push-jfrog.yml` | JFrog | `cgx.jfrog.io/coralogix-docker-images/obi-internal` |
| `cx-build-push-ecr.yml` | AWS ECR (tacotaco-research, eu-west-1) | `897729105761.dkr.ecr.eu-west-1.amazonaws.com/obi-internal` |

Both build natively per architecture (no QEMU), then merge a multi-arch
manifest. The final image is tagged with the **short commit hash** of the
built ref — there is no `latest` tag. Per-arch tags
(`<hash>-amd64`, `<hash>-arm64`) also exist as manifest inputs.

Both workflows are `workflow_dispatch`-only. The definitions live on the
`internal/build-push-job` branch and do not need to be on `main`: GitHub
registers a workflow once its file is pushed to any branch, after which it
is dispatchable by filename with `--ref internal/build-push-job`.

## Triggering a build

Dispatch the workflow definition from `internal/build-push-job` and pass the
ref you want built via the `ref` input:

```bash
# build and push branch test-1 to ECR
gh workflow run cx-build-push-ecr.yml --ref internal/build-push-job -f ref=test-1

# same, to JFrog
gh workflow run cx-build-push-jfrog.yml --ref internal/build-push-job -f ref=test-1
```

`ref` accepts a branch, tag, or commit SHA. When omitted, the commit the
workflow definition was dispatched from is built.

## Getting the image name on a PR

Pass `pr_number` and the workflow comments the final image reference on
that PR once the manifest is pushed:

```bash
gh workflow run cx-build-push-ecr.yml --ref internal/build-push-job \
  -f ref=test-1 -f pr_number=123
```

posts on PR #123:

> Pushed `897729105761.dkr.ecr.eu-west-1.amazonaws.com/obi-internal:<hash>` (amd64+arm64)

## Watching progress

```bash
gh run list --workflow=cx-build-push-ecr.yml --limit 3
gh run watch <run-id>
```

## Credentials

- **JFrog**: `JFROG_USER` / `JFROG_PASSWORD` repository secrets.
- **ECR**: GitHub OIDC assuming `arn:aws:iam::897729105761:role/AnemiaAgentRole`;
  no long-lived secrets. The workflow creates the `obi-internal` repository
  on first push if it does not exist.

Both workflows only run in the `coralogix/opentelemetry-ebpf-instrumentation`
repository.
