#!/bin/sh
set -eu
set +x

[ "${CI_PIPELINE_EVENT:-}" = push ] || { echo 'Infisical publication requires a push event' >&2; exit 1; }
[ "${CI_COMMIT_BRANCH:-}" = main ] && [ "${CI_COMMIT_REF:-}" = refs/heads/main ] || { echo 'Infisical publication requires protected Main' >&2; exit 1; }
[ "${CI_REPO:-}" = Visiondynamics-ag/infisical ] || { echo 'Infisical source repository changed' >&2; exit 1; }
[ "${REGISTRY_REPOSITORY:-}" = 10.43.0.50/infisical/infisical ] || { echo 'Infisical registry repository changed' >&2; exit 1; }
case "${CI_COMMIT_SHA:-}" in ''|*[!0-9a-f]*) echo 'Infisical source SHA is malformed' >&2; exit 1 ;; esac
[ "${#CI_COMMIT_SHA}" -eq 40 ] || { echo 'Infisical source SHA is malformed' >&2; exit 1; }
