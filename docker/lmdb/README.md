# System LMDB corruption guards

The standalone Ubuntu 24.04 image rebuilds Ubuntu's `lmdb 0.9.31-1build1`
source package as `0.9.31-1build1+infisical1`. The suffix identifies a local
backport; it does not claim an Ubuntu-issued security update. The source and
packaging archives are SHA-256 pinned in `build-deb.sh`.

The five patches are unchanged from py-lmdb maintainer PR
https://github.com/jnwatson/py-lmdb/pull/429 at commit
`7e532e7df2580233281cf36cc96db08deb1c398b`. They reject malformed database flags,
dirty on-disk pages, out-of-bounds node sizes, missing duplicate cursors and invalid
page sizes (CVE-2019-16224 through CVE-2019-16228). This is a system-library
backport, independent of any LMDB bundled by a language binding. The upstream
OpenLDAP license is included. Patch-file context whitespace is retained verbatim
through the local `.gitattributes`; C source and shell checks are unchanged.

Ubuntu's package rules, hardening, tests and exported-symbol checks remain in
force. LTO and package builds use one worker to avoid the observed GCC 13
jobserver internal compiler error under amd64 emulation. Public headers and the `liblmdb.so.0` SONAME stay unchanged. Only the runtime
shared-library package is installed; no compiler, headers or test fixtures enter
the production stage. The build refuses to replace a newer Ubuntu package with
this older source baseline. Reassess the backport when the vendor package changes;
scanner version matches may not recognize this locally patched package.

Focused qualification must exercise this installed shared library with the
maintainer corruption tests and ordinary LDB/Samba consumers. It does not prove
that arbitrary malformed databases are safe or that an app remotely reaches
these paths. App source, migrations and LMDB data format remain unchanged.
