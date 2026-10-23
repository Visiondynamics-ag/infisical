#!/bin/sh
set -eu
set +x
cd "$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
mode=${1:-qualify}
[ "$#" -le 1 ] || { echo 'expected qualify or publish' >&2; exit 1; }
case "$mode" in
  qualify) . .woodpecker/scripts/validate-source.sh
    [ -z "${REGISTRY_USERNAME:-}${REGISTRY_PASSWORD:-}${REGISTRY_PULL_USERNAME:-}${REGISTRY_PULL_PASSWORD:-}${REGISTRY_CA_CERT_BASE64:-}" ] || { echo 'qualification must not receive registry custody' >&2; exit 1; } ;;
  publish) . .woodpecker/scripts/validate-push.sh ;;
  *) echo 'expected qualify or publish' >&2; exit 1 ;;
esac
fail() { printf '%s\n' "Infisical image build failed: $*" >&2; exit 1; }
[ "$(git rev-parse HEAD)" = "$CI_COMMIT_SHA" ] || fail 'checkout SHA changed'
git diff --quiet HEAD -- Dockerfile.standalone-infisical docker/lmdb backend frontend backend-go standalone-entrypoint.sh || fail 'build sources changed'
umask 077
[ ! -L .ci-artifacts ] || fail 'artifact directory is a symlink'
mkdir -p .ci-artifacts
chmod 700 .ci-artifacts
[ ! -e .ci-artifacts/build-metadata.json ] && [ ! -L .ci-artifacts/build-metadata.json ] || fail 'build metadata already exists'
[ ! -e .ci-artifacts/image.oci.tar ] && [ ! -L .ci-artifacts/image.oci.tar ] || fail 'qualification archive already exists'

build_root=$(mktemp -d /tmp/infisical-build.XXXXXX)
cleanup_build() { rm -rf -- "$build_root"; }
trap cleanup_build EXIT HUP INT TERM
mkdir -p "$build_root/docker" "$build_root/context"
printf '{"auths":{}}\n' > "$build_root/docker/config.json"
export DOCKER_CONFIG="$build_root/docker"
buildkit_config="$build_root/buildkitd.toml"
: > "$buildkit_config"
set --
if [ "$mode" = publish ]; then
  [ -n "${REGISTRY_USERNAME:-}" ] && [ -n "${REGISTRY_PASSWORD:-}" ] || fail 'project publisher robot is missing'
  [ -n "${REGISTRY_CA_CERT_BASE64:-}" ] || fail 'registry CA is missing'
  case "$REGISTRY_CA_CERT_BASE64" in *[!A-Za-z0-9+/=]*|'') fail 'registry CA certificate is not strict base64' ;; esac
  [ "$(( ${#REGISTRY_CA_CERT_BASE64} % 4 ))" -eq 0 ] || fail 'registry CA certificate is not strict base64'
  registry_auth=$(printf '%s' "$REGISTRY_USERNAME:$REGISTRY_PASSWORD" | base64 | tr -d '\n')
  printf '{"auths":{"10.43.0.50":{"auth":"%s"}}}\n' "$registry_auth" > "$build_root/docker/config.json"
  registry_ca_file="$build_root/registry-ca.pem"
  printf '%s' "$REGISTRY_CA_CERT_BASE64" | base64 -d > "$registry_ca_file" || fail 'registry CA certificate could not be decoded'
  [ "$(base64 < "$registry_ca_file" | tr -d '\n')" = "$REGISTRY_CA_CERT_BASE64" ] || fail 'registry CA certificate is not strict base64'
  grep -q '^-----BEGIN CERTIFICATE-----$' "$registry_ca_file" || fail 'registry CA certificate is not PEM'
  grep -q '^-----END CERTIFICATE-----$' "$registry_ca_file" || fail 'registry CA certificate is not PEM'
  ! grep -Eq '^-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----$' "$registry_ca_file" || fail 'registry CA certificate contains private key material'
  printf '[registry."10.43.0.50"]\n  ca = ["%s"]\n' "$registry_ca_file" > "$buildkit_config"
  set -- --registry-auth-tlscontext "host=10.43.0.50,ca=$registry_ca_file"
fi
unset REGISTRY_USERNAME REGISTRY_PASSWORD REGISTRY_PULL_USERNAME REGISTRY_PULL_PASSWORD REGISTRY_CA_CERT_BASE64 registry_auth

# Only committed build inputs enter the context; CI custody and output stay outside it.
git archive "$CI_COMMIT_SHA" Dockerfile.standalone-infisical .dockerignore backend frontend docker/lmdb standalone-entrypoint.sh > "$build_root/context.tar"
tar -xf "$build_root/context.tar" -C "$build_root/context"
rm "$build_root/context.tar"

# The pinned upstream rootless image starts as host UID/GID 1000. Its reviewed
# mapping helpers create a nested user namespace; the build process never
# becomes host root. Admission binds the helper posture to this exact image,
# repository namespace, non-root identity, and tokenless/hostPath-free pod.
[ "$(id -u)" = 1000 ] || fail "rootless BuildKit UID 1000 is required"
[ "$(id -g)" = 1000 ] || fail "rootless BuildKit GID 1000 is required"
grep -Eq '^NoNewPrivs:[[:space:]]+0$' /proc/self/status || fail "rootless mapping helper cannot run"
[ "$(grep -Ec '^Cap(Prm|Eff|Amb):[[:space:]]+0000000000000000$' /proc/self/status)" = 3 ] || fail "rootless BuildKit began with an active capability"


# Keep native-snapshotter state in the bounded container writable layer,
# rather than the upstream image's unaccounted HOME volume.
state_root=$(mktemp -d /tmp/infisical-buildkit-state.XXXXXX)
state_mount=$(awk -v state="$state_root" '$5 == "/" || $5 == state || index(state, $5 "/") == 1 { if (length($5) > length(mount)) mount = $5 } END { print mount }' /proc/self/mountinfo)
[ "$state_mount" = / ] || fail 'BuildKit state is outside the container writable layer'
short_sha=$(printf '%s' "$CI_COMMIT_SHA" | cut -c1-8)
if [ "$mode" = publish ]; then
  output="type=image,name=$REGISTRY_REPOSITORY:$CI_COMMIT_SHA,push=true,name-canonical=true"
else
  output="type=oci,name=infisical-qualification:$CI_COMMIT_SHA,dest=.ci-artifacts/image.oci.tar"
fi
BUILDKITD_FLAGS="--root $state_root --config $buildkit_config --oci-worker-no-process-sandbox --oci-worker-snapshotter=native" \
BUILDCTL_CONNECT_RETRIES_MAX=60 \
buildctl-daemonless.sh build \
    "$@" \
    --frontend dockerfile.v0 \
    --local "context=$build_root/context" \
    --local "dockerfile=$build_root/context" \
    --opt filename=Dockerfile.standalone-infisical \
    --opt platform=linux/amd64 \
    --opt build-arg:FRONTEND_BUILD_HEAP_MIB=4096 \
    --opt "build-arg:INFISICAL_PLATFORM_VERSION=v0.167.1-vd.$short_sha" \
    --opt build-arg:DD_GIT_REPOSITORY_URL=https://github.com/Visiondynamics-ag/infisical \
    --opt "build-arg:DD_GIT_COMMIT_SHA=$CI_COMMIT_SHA" \
    --output "$output" \
    --metadata-file .ci-artifacts/build-metadata.json
chmod 600 .ci-artifacts/build-metadata.json
if [ "$mode" = publish ]; then
  printf '%s\n' 'Infisical standalone image published at its source-SHA tag'
else
  chmod 600 .ci-artifacts/image.oci.tar
  printf '%s\n' 'Infisical qualification archive built locally; no image published'
fi
