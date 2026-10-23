#!/bin/sh
set -eu
# Ubuntu source and packaging, with the py-lmdb maintainer's corruption guards.
source_version=0.9.31-1build1
local_version=${source_version}+infisical1
mkdir -p /tmp/lmdb-source /out
cd /tmp/lmdb-source
for file in lmdb_0.9.31-1build1.dsc lmdb_0.9.31.orig.tar.gz lmdb_0.9.31-1build1.debian.tar.xz; do
    curl --fail --silent --show-error --location "https://archive.ubuntu.com/ubuntu/pool/main/l/lmdb/$file" --output "$file"
done
sha256sum --check <<'CHECKSUMS'
9b6bd28732d8d15613539301e300207771a8311f615eac721f6c80b9ffe8dadc  lmdb_0.9.31-1build1.dsc
d35d4f6f46313d62fd342c9dcbf574432919ce5e802d2b6cbe2ebd549821e5c4  lmdb_0.9.31.orig.tar.gz
3a855e1feb674c3718b2fa07fa2d8cee017608ce676189550719a45e18d99a09  lmdb_0.9.31-1build1.debian.tar.xz
CHECKSUMS
# Exact source hashes above authenticate the material; no keyserver is consulted.
dpkg-source --no-check -x lmdb_0.9.31-1build1.dsc lmdb
cd lmdb
for patch in /lmdb-backport/cve-*.patch; do
    name=$(basename "$patch")
    cp "$patch" "debian/patches/$name"
    printf '%s\n' "$name" >> debian/patches/series
done
# Require exact contexts: no fuzzy hunk matching in this maintained backport.
QUILT_PATCH_OPTS='--fuzz=0' dpkg-source --before-build .
cp debian/changelog /tmp/lmdb-original-changelog
{
    printf 'lmdb (%s) noble; urgency=high\n\n' "$local_version"
    printf '  * Local backport of py-lmdb PR 429 corruption guards (CVE-2019-16224..16228).\n'
    printf '    Ubuntu packaging, public headers and liblmdb.so.0 ABI are preserved.\n\n'
    printf ' -- Local standalone image backport <noreply@localhost>  Thu, 22 Oct 2026 00:00:00 +0000\n\n'
    cat /tmp/lmdb-original-changelog
} > debian/changelog
# Retain LTO and all distribution hardening, with one LTO/package worker.
# This avoids the GCC 13 jobserver return_token ICE under amd64 emulation.
export DEB_CFLAGS_MAINT_APPEND="-flto=1"
export DEB_LDFLAGS_MAINT_APPEND="-flto=1"
dpkg-buildpackage -B -us -uc -j1
cp ../liblmdb0_"${local_version}"_*.deb /out/
