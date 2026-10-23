# Infisical self-hosted image recipe

This source-only recipe carries the existing Woodpecker `application-release`
flow onto maintained upstream v0.167.1. Central policy owns exact Forge repository
`1422375251`, PR admission to `dev`/`main`, and opt-in protected Main publication.
The qualified application/packaging base is
`faf35374213e8f3802cfae1ffb505241849322cd`. These wrappers do not change that
application, its migrations, or the preserved local image
`sha256:d94dee7e94c929f4c70ee25ea8b094143069433e000e9b769c2f2a7f17330276`.

## Source checks and credential-free build

Both recipes run the existing frontend/backend lint and type checks, backend unit
tests, and `make -C backend-go test-unit`. Node checks use pinned Node 26.12.1 and
npm 11.21.1, matching the maintained release's engine requirements. Dependencies
are installed only in the disposable checkout and removed before building. Unit
workers are bounded to one. The tracked Go source still exists: its existing
`go test -v ./internal/... -count=1 -race -timeout 120s` gate uses pinned Go 1.26.10,
`GOTOOLCHAIN=local` and `/tmp` caches. It does not start testcontainers or a live DB.
Steps execute serially in source order without an explicit DAG.

The PR recipe ends with `sh .woodpecker/scripts/rootless-build.sh qualify`.
`qualify` is also the wrapper's default. It requires the exact admitted checkout
SHA, rejects registry custody, uses an empty Docker config, and writes only
`.ci-artifacts/image.oci.tar` and BuildKit metadata. It does not publish. The OCI
archive still needs image/runtime and complete scan qualification; build success
alone is not a release gate or permission to deploy.

Build context comes from a Git archive of the committed Dockerfile, `.dockerignore`,
`backend`, `frontend`, `docker/lmdb`, and standalone entrypoint. Untracked files,
CI custody and CI artifacts do not enter it. Inputs are:

- `Dockerfile.standalone-infisical`, `linux/amd64`;
- `FRONTEND_BUILD_HEAP_MIB=4096`;
- `INFISICAL_PLATFORM_VERSION=v0.167.1-vd.<short-source-SHA>`;
- `DD_GIT_REPOSITORY_URL=https://github.com/Visiondynamics-ag/infisical`;
- `DD_GIT_COMMIT_SHA=<full-source-SHA>`.

No Contentful, runtime or database secrets are needed. The existing rootless
BuildKit image, UID/GID 1000 mapping-helper posture, native snapshotter and
accounted writable-layer storage are retained. Package security repositories are
resolved at build time: qualify the resulting CI image, not an assumed copy of
the earlier Desktop digest.

## Publishing and scan policy

Publication is a separate explicit invocation:
`sh .woodpecker/scripts/rootless-build.sh publish`. It retains exact repository,
protected Main push/ref, full SHA and scoped Harbor custody checks. The Main
recipe then captures the digest, reads it back through Harbor, scans it, and
uses the existing handoff/evidence helpers. The publisher remains disabled until
the main infra owner activates its central policy and custody. This branch does
not enroll a repository, create robots, deliver credentials or activate publishing.

The scan now includes **all severities, unfixed vulnerabilities and secrets**.
A Trivy template writes the existing report's finding metadata without secret
matches, matched code, or image environment values. Its digest binding comes from
the validated scan input; the separate Harbor readback verifies the manifest.
The handoff gate rejects every High/Critical finding (including unfixed ones) and
any secret finding. Lower severities remain in the report. A successful scanner
process only means the inventory was produced; it does not mean the gate passed.

Two unresolved issues remain explicit:

- `node-forge` 1.4.0 / CVE-2026-85393: the qualified image has one High match and
  no verified official fix. This recipe's strict handoff gate will fail it.
- npm 11.21.1 bundles `http-cache-semantics` 4.3.0 via `make-fetch-happen`.
  The CVE-2026-93748 cache-policy logic remains despite the current advisory range
  ending at 4.2.0. Its absence from the scan is not remediation or a release pass.

No ignore rule, severity filter, feature removal or exception resolves either
issue. Release readiness must retain the known cache issue even if a future scan
reports zero High findings. See the [forge upstream issue](https://github.com/digitalbazaar/forge/issues/1149)
and [cache advisory](https://github.com/advisories/GHSA-ch52-4w7c-c8xp).

## Capacity and central integration handoff

The prior local build took 912.1 seconds with a 66,858,341-byte source context.
Its exported image archive was 536,569,344 bytes; image save took 4.38 seconds.
Peak RAM and build/temp disk were not sampled. The Desktop engine had about
23.4 GiB RAM and 18 CPUs. These observations do not qualify the shared runner's
existing 6-CPU, 8-GiB RAM and 10-GiB ephemeral-storage caps. The frontend heap is
4 GiB; the upstream backend heap ceiling remains 8 GiB, and native/concurrent
stages add overhead. The cluster's 10-GB admission floor is a separate check.

The main infra owner must mirror these recipes into the existing central
`infisical-pr.yml`/`infisical-publish.yml` templates and qualify actual peak RAM,
BuildKit native-snapshotter storage, OCI export and check duration before releasing
the shared slot. Keep limits and security posture unchanged; do not infer fit or
authorize an increase from this source. Full maintained-release lint/type/unit/Go
CI gates and the rootless build have not yet run on that runner.

Proposed registry coordinates remain
`10.43.0.50/infisical/infisical:<full-source-SHA>` and
`infisical/ci-evidence:<full-source-SHA>`. Publishing needs the dedicated project
push/pull robot; readback/scan need a separate pull-only robot and the private CA.
Existing Woodpecker names are `registry_username`, `registry_password`,
`registry_pull_username`, `registry_pull_password`, `registry_ca_cert_base64`.
No admin, OAuth, GitHub token or application secret belongs in this flow.
`woodpeckerRepoId` remains unassigned in the central catalog and the Infisical
publisher opt-in remains off until the owner establishes the route.

The upstream `.github/workflows` still contain hosted PR/tag/manual triggers.
Before any source publication, the owner must check current hook/Actions settings
and those triggers. This change neither dispatches nor disables them.

The v0.161.11 to v0.167.1 interval changes database state. Use
[the database-aware upgrade and recovery instructions](UPGRADE.md), including the
operator-controlled restored-copy rehearsal and coordinated client cutover.
Link these instructions from the central Cherry recovery runbook before treating
this release as rollout-ready. An old image alone is not a database rollback.
