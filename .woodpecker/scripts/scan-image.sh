#!/bin/sh
set -eu
set +x

cd "$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

. .woodpecker/scripts/validate-push.sh

fail() {
    printf '%s\n' "Infisical image scan failed closed: $1" >&2
    exit 1
}

artifact_dir=${CI_ARTIFACTS_DIR:-.ci-artifacts}
case "$artifact_dir" in
    /*) ;;
    *) artifact_dir="$PWD/$artifact_dir" ;;
esac
[ -d "$artifact_dir" ] && [ ! -L "$artifact_dir" ] || fail "the CI artifact directory is not safe"
stat_value() {
    field=$1
    file=$2
    case "$field" in
        mode) gnu='%a'; bsd='%A' ;;
        uid) gnu='%u'; bsd='%u' ;;
        gid) gnu='%g'; bsd='%g' ;;
        links) gnu='%h'; bsd='%l' ;;
        *) return 1 ;;
    esac
    stat -c "$gnu" "$file" 2>/dev/null || stat -f "$bsd" "$file"
}
job_owner() {
    [ "$(stat_value uid "$1")" = "$(id -u)" ] || fail "$2 is not owned by the job user"
    [ "$(stat_value gid "$1")" = "$(id -g)" ] || fail "$2 does not have the job group"
}
private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || fail "$2 is not a regular file"
    case "$(stat_value mode "$1")" in 600|660) ;; *) fail "$2 has an unsupported mode" ;; esac
    [ "$(stat_value links "$1")" = 1 ] || fail "$2 has unexpected hard links"
    job_owner "$1" "$2"
}
[ "$(CDPATH= cd -- "$artifact_dir" && pwd -P)" = "$artifact_dir" ] || fail "the CI artifact directory contains a symlink"
case "$(stat_value mode "$artifact_dir")" in 700|2770) ;; *) fail "the CI artifact directory has an unsupported mode" ;; esac
job_owner "$artifact_dir" "CI artifact directory"
private_file "$artifact_dir/images.env" "image digest manifest"
[ -n "${REGISTRY_PULL_USERNAME:-}" ] || fail "the Harbor pull username secret is missing"
[ -n "${REGISTRY_PULL_PASSWORD:-}" ] || fail "the Harbor pull password secret is missing"
[ -n "${REGISTRY_CA_CERT_BASE64:-}" ] || fail "the Harbor CA secret is missing"
[ "${REGISTRY_REPOSITORY:-}" = "10.43.0.50/infisical/infisical" ] || \
    fail "the Harbor repository is outside the custody boundary"

manifest="$artifact_dir/images.env"
read_value() {
    key=$1
    count=$(awk -F= -v wanted="$key" '$1 == wanted {count++} END {print count + 0}' "$manifest")
    [ "$count" -eq 1 ] || fail "the image digest manifest has an unexpected $key entry"
    awk -F= -v wanted="$key" '$1 == wanted {sub(/^[^=]*=/, ""); print; exit}' "$manifest"
}

source_sha=$(read_value SOURCE_SHA)
case "$source_sha" in *[!0-9a-f]*|'') fail "the image source SHA is malformed" ;; esac
[ "${#source_sha}" -eq 40 ] || fail "the image source SHA is malformed"
image_repository=$(read_value IMAGE_REPOSITORY)
[ "$image_repository" = "$REGISTRY_REPOSITORY" ] || fail "the image repository binding changed"
image_tag=$(read_value IMAGE_TAG)
[ "$image_tag" = "$source_sha" ] || fail "the image tag is not the source SHA"
image_digest=$(read_value IMAGE_DIGEST)
digest_hash=${image_digest#sha256:}
[ "$image_digest" != "$digest_hash" ] || fail "the image digest is missing its sha256 prefix"
case "$digest_hash" in *[!0-9a-f]*|'') fail "the image digest is malformed" ;; esac
[ "${#digest_hash}" -eq 64 ] || fail "the image digest is malformed"
[ "$image_digest" = "$(read_value IMAGE_DIGEST)" ] || fail "the image digest manifest changed"
image_ref=$(read_value IMAGE_REF)
[ "$image_ref" = "$REGISTRY_REPOSITORY:$source_sha@$image_digest" ] || fail "the immutable image reference changed"

report="$artifact_dir/trivy-image.json"
[ ! -e "$report" ] && [ ! -L "$report" ] || fail "the Trivy report already exists"

umask 077
auth_root=$(mktemp -d -t infisical-scan-auth.XXXXXX)
cleanup_registry_auth() {
    status=$?
    rm -rf -- "$auth_root"
    unset REGISTRY_PULL_USERNAME REGISTRY_PULL_PASSWORD REGISTRY_CA_CERT_BASE64
    return "$status"
}
trap cleanup_registry_auth EXIT HUP INT TERM
chmod 700 "$auth_root"
mkdir -m 700 "$auth_root/docker"
registry_host=${REGISTRY_REPOSITORY%%/*}
registry_auth=$(printf '%s' "$REGISTRY_PULL_USERNAME:$REGISTRY_PULL_PASSWORD" | base64 | tr -d '\n')
printf '%s\n' "{\"auths\":{\"$registry_host\":{\"auth\":\"$registry_auth\"}}}" > "$auth_root/docker/config.json"
chmod 600 "$auth_root/docker/config.json"
if ! printf '%s' "$REGISTRY_CA_CERT_BASE64" | base64 -d > "$auth_root/ca.crt" 2>/dev/null; then
    fail "the Harbor CA secret is not base64"
fi
chmod 400 "$auth_root/ca.crt"
[ "$(grep -Fxc -- '-----BEGIN CERTIFICATE-----' "$auth_root/ca.crt")" -eq 1 ] || \
    fail "the Harbor CA must contain one public certificate"
[ "$(grep -Fxc -- '-----END CERTIFICATE-----' "$auth_root/ca.crt")" -eq 1 ] || \
    fail "the Harbor CA must contain one public certificate"
if grep -Fq 'PRIVATE KEY' "$auth_root/ca.crt"; then
    fail "the Harbor CA must not contain a private key"
fi

unset REGISTRY_PULL_USERNAME REGISTRY_PULL_PASSWORD REGISTRY_CA_CERT_BASE64 registry_auth
export DOCKER_CONFIG="$auth_root/docker"
export SSL_CERT_FILE="$auth_root/ca.crt"
export TRIVY_CACHE_DIR="$auth_root/trivy-cache"
export INFISICAL_SCAN_IMAGE="$image_ref"
export INFISICAL_SCAN_REPO_DIGEST="$REGISTRY_REPOSITORY@$image_digest"

# The template writes finding metadata only, never secret matches or image env.
# Policy enforcement remains in emit-harbor-handoff.mjs, after the full report exists.
trivy image \
    --quiet \
    --no-progress \
    --config /dev/null \
    --ignorefile /dev/null \
    --scanners vuln,secret \
    --ignore-unfixed=false \
    --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
    --format template \
    --template '@.woodpecker/scripts/trivy-report.tpl' \
    --output "$report" \
    --exit-code 0 \
    "$image_ref"

[ -f "$report" ] && [ ! -L "$report" ] || fail "Trivy did not produce its report"
chmod 600 "$report"
private_file "$report" "Trivy report"
printf '%s\n' 'full digest-pinned vulnerability and redacted secret inventory written; policy gate follows'
