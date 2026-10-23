#!/bin/sh
set -eu
set +x

[ "${CI_REPO:-}" = Visiondynamics-ag/infisical ] || { echo 'Infisical source repository changed' >&2; exit 1; }
case "${CI_PIPELINE_EVENT:-}:${CI_COMMIT_BRANCH:-}:${CI_COMMIT_REF:-}" in
    pull_request:dev:refs/pull/*/head|pull_request:dev:refs/pull/*/merge|pull_request:main:refs/pull/*/head|pull_request:main:refs/pull/*/merge|push:main:refs/heads/main) ;;
    *) echo 'Infisical checks require a Dev/Main PR or Main push' >&2; exit 1 ;;
esac
case "${CI_COMMIT_SHA:-}" in ''|*[!0-9a-f]*) echo 'Infisical source SHA is malformed' >&2; exit 1 ;; esac
[ "${#CI_COMMIT_SHA}" -eq 40 ] || exit 1
[ "$(git rev-parse HEAD)" = "$CI_COMMIT_SHA" ] || { echo "Infisical checkout SHA changed" >&2; exit 1; }
