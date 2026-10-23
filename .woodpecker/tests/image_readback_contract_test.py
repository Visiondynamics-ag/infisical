#!/usr/bin/env python3
"""Offline contract checks for the Harbor image manifest readback producer."""

from __future__ import annotations

import base64
import importlib.util
import os
import ssl
import stat
import tempfile
from unittest import mock
import json
from pathlib import Path


# Exercise the real job-group projection on Linux; this macOS filesystem
# strips setgid. Keep the same protocol tests on owner-only directories there.
with tempfile.TemporaryDirectory(prefix="infisical-mode-probe-") as temporary:
    mode_probe = Path(temporary)
    mode_probe.chmod(0o2770)
    CI_DIRECTORY_MODE = 0o2770 if stat.S_IMODE(mode_probe.stat().st_mode) == 0o2770 else 0o700
if CI_DIRECTORY_MODE != 0o2770:
    print("Group-directory projection unavailable here; owner-only protocol fixtures exercised")

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / ".woodpecker" / "scripts" / "readback-image.py"
spec = importlib.util.spec_from_file_location("infisical_image_readback", HELPER)
assert spec is not None and spec.loader is not None
readback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readback)

SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "a" * 64
IMAGE_REF = f"{readback.REGISTRY_REPOSITORY}:{SOURCE_SHA}@{DIGEST}"

env_raw = (
    f"SOURCE_REPOSITORY={readback.SOURCE_REPOSITORY}\n"
    f"SOURCE_SHA={SOURCE_SHA}\n"
    f"IMAGE_REPOSITORY={readback.REGISTRY_REPOSITORY}\n"
    f"IMAGE_TAG={SOURCE_SHA}\n"
    f"IMAGE_DIGEST={DIGEST}\n"
    f"IMAGE_REF={IMAGE_REF}\n"
).encode("ascii")
assert readback.parse_env(env_raw, SOURCE_SHA)["IMAGE_REF"] == IMAGE_REF

manifest_raw = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": DIGEST, "size": 2},
        "layers": [],
    },
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
manifest_digest = "sha256:" + readback.sha256_bytes(manifest_raw)


class FakeTransport:
    def __init__(self, body: bytes, header_digest: str) -> None:
        self.body = body
        self.header_digest = header_digest

    def request(self, method: str, request_path: str, headers=None, body: bytes = b"") -> readback.Response:
        del headers, body
        assert method == "GET"
        assert request_path == f"/v2/{readback.IMAGE_PATH}/manifests/{SOURCE_SHA}"
        return readback.Response(
            200,
            {
                "Content-Type": "application/vnd.oci.image.manifest.v1+json",
                "Docker-Content-Digest": self.header_digest,
            },
            self.body,
        )


body, media_type = readback.readback(FakeTransport(manifest_raw, manifest_digest), "offline-token", SOURCE_SHA, manifest_digest)
assert body == manifest_raw
assert media_type == "application/vnd.oci.image.manifest.v1+json"

for label, transport in (
    ("tampered header", FakeTransport(manifest_raw, DIGEST)),
    ("tampered bytes", FakeTransport(manifest_raw + b"x", manifest_digest)),
):
    try:
        readback.readback(transport, "offline-token", SOURCE_SHA, manifest_digest)
    except readback.Refusal:
        pass
    else:
        raise AssertionError(f"{label} must fail closed")

try:
    readback.parse_env(env_raw.replace(DIGEST.encode("ascii"), b"sha256:not-a-digest"), SOURCE_SHA)
except readback.Refusal:
    pass
else:
    raise AssertionError("malformed image digest must fail closed")

# Drive the real entry point; only registry I/O is replaced by the existing
# offline response fixture. Certificate and artifact checks remain active.
class MainTransport(FakeTransport):
    def request(self, method, request_path, headers=None, body=b""):
        if method == "HEAD":
            return readback.Response(401, {"WWW-Authenticate": f'Bearer realm="https://{readback.REGISTRY_HOST}/service/token",service="harbor-registry",scope="repository:{readback.IMAGE_PATH}:pull"'}, b"")
        if request_path.startswith("/service/token?"):
            return readback.Response(200, {}, b'{"token":"offline-token"}')
        return super().request(method, request_path, headers, body)


with tempfile.TemporaryDirectory(prefix="infisical-readback-fsgroup-") as temporary:
    artifact = Path(temporary).resolve() / ".ci-artifacts"
    artifact.mkdir(mode=0o700)
    artifact.chmod(CI_DIRECTORY_MODE)
    manifest_file = artifact / "images.env"
    manifest_file.write_bytes(env_raw.replace(DIGEST.encode(), manifest_digest.encode()))
    manifest_file.chmod(0o660)
    roots = ssl.create_default_context().get_ca_certs(binary_form=True)
    assert roots, "the standard Python image must include public CA roots"
    ca = base64.b64encode(ssl.DER_cert_to_PEM_cert(roots[0]).encode()).decode()
    environment = {
        "CI_PIPELINE_EVENT": "push", "CI_COMMIT_BRANCH": "main", "CI_COMMIT_REF": "refs/heads/main",
        "CI_REPO": readback.SOURCE_REPOSITORY, "CI_COMMIT_SHA": SOURCE_SHA,
        "REGISTRY_REPOSITORY": readback.REGISTRY_REPOSITORY, "CI_ARTIFACTS_DIR": str(artifact),
        "REGISTRY_PULL_USERNAME": "offline-fixture", "REGISTRY_PULL_PASSWORD": "offline-fixture-no-provider-access",
        "REGISTRY_CA_CERT_BASE64": ca,
    }
    with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(readback, "Transport", return_value=MainTransport(manifest_raw, manifest_digest)) as transport:
        assert readback.main() == 0
        output = artifact / "image-readback.json"
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert json.loads(output.read_text())["manifestDigest"] == manifest_digest
        output.unlink()
        for target, safe_mode in [(artifact, CI_DIRECTORY_MODE), (manifest_file, 0o660)]:
            target.chmod(0o777 if target == artifact else 0o666)
            transport.reset_mock()
            try:
                readback.main()
            except readback.Refusal as error:
                assert "unsupported mode" in str(error)
            else:
                raise AssertionError("world-accessible custody must fail at the entry point")
            assert not transport.called
            target.chmod(safe_mode)
            alternate = next((group for group in os.getgroups() if group != os.getegid()), None)
            if alternate is not None:
                os.chown(target, os.geteuid(), alternate)
                target.chmod(safe_mode)
                try:
                    readback.main()
                except readback.Refusal as error:
                    assert "job group" in str(error)
                else:
                    raise AssertionError("different-group custody must fail at the entry point")
                os.chown(target, os.geteuid(), os.getegid())
                target.chmod(safe_mode)
        # Always exercise the GID predicate, including single-group CI users.
        wrong_group = list(manifest_file.stat())
        wrong_group[5] = os.getegid() + 1
        try:
            readback.owner_only(os.stat_result(wrong_group), "wrong-group fixture", regular=True)
        except readback.Refusal as error:
            assert "job group" in str(error)
        else:
            raise AssertionError("a non-job GID must be rejected")


# Exercise the shipped HTTP transport with connection I/O replaced, including
# failures after a request was sent. No provider or network is contacted.
roots = ssl.create_default_context().get_ca_certs(binary_form=True)
assert roots, "the standard Python image must include public CA roots"
transport = readback.Transport(ssl.DER_cert_to_PEM_cert(roots[0]).encode())
failures = [ConnectionRefusedError, OSError, readback.socket.timeout, readback.http.client.HTTPException, ssl.SSLError]
for method in ["GET", "HEAD"]:
    for failure in failures:
        for phase in ["request", "read"]:
            first, second = mock.MagicMock(), mock.MagicMock()
            if phase == "request":
                first.request.side_effect = failure("private-fixture-value")
            else:
                first.getresponse.return_value.read.side_effect = failure("private-fixture-value")
            response = second.getresponse.return_value
            response.status = 200
            response.read.return_value = b"ok"
            response.getheaders.return_value = [("Content-Type", "application/json")]
            with mock.patch.object(readback.http.client, "HTTPSConnection", side_effect=[first, second]) as factory, mock.patch.object(readback.time, "sleep") as sleep:
                assert transport.request(method, "/v2/", {"Authorization": "Bearer private-fixture-value"}).body == b"ok"
                assert factory.call_count == 2
                assert sleep.call_args_list == [mock.call(1)]
                for call in factory.call_args_list:
                    assert call.args == (readback.REGISTRY_HOST, 443)
                    assert call.kwargs["context"] is transport.context
            first.close.assert_called_once()
            second.close.assert_called_once()
    for failure in failures:
        connections = [mock.MagicMock() for _ in range(3)]
        for connection in connections:
            connection.getresponse.side_effect = failure("private-fixture-value")
        with mock.patch.object(readback.http.client, "HTTPSConnection", side_effect=connections) as factory, mock.patch.object(readback.time, "sleep") as sleep:
            try:
                transport.request(method, "/v2/")
            except readback.Refusal as error:
                assert str(error) == f"Harbor request failed safely ({failure.__name__})"
                assert "private-fixture-value" not in str(error)
            else:
                raise AssertionError("exhausted transport reads must refuse")
            assert factory.call_count == 3
            assert sleep.call_args_list == [mock.call(1), mock.call(2)]
        for connection in connections:
            connection.close.assert_called_once()
# Certificate rejection is a trust failure, not a transient read failure.
for method in ["GET", "HEAD"]:
    connection = mock.MagicMock()
    connection.request.side_effect = ssl.SSLCertVerificationError("private-fixture-value")
    with mock.patch.object(readback.http.client, "HTTPSConnection", return_value=connection) as factory, mock.patch.object(readback.time, "sleep") as sleep:
        try:
            transport.request(method, "/v2/")
        except readback.Refusal as error:
            assert str(error) == "Harbor request failed safely (SSLCertVerificationError)"
        else:
            raise AssertionError("certificate verification failures must stop immediately")
        assert factory.call_count == 1
        sleep.assert_not_called()
    connection.close.assert_called_once()
with mock.patch.object(readback.http.client, "HTTPSConnection") as factory, mock.patch.object(readback.time, "sleep") as sleep:
    try:
        transport.request("DELETE", "/v2/")
    except readback.Refusal:
        pass
    else:
        raise AssertionError("DELETE must remain unapproved")
    factory.assert_not_called()
    sleep.assert_not_called()
# Semantic response failures and HTTP statuses are never transport retries.
for status, headers, body in [(302, [], b""), (200, [("X-Test", "a"), ("X-Test", "b")], b""), (200, [], b"xx")]:
    connection = mock.MagicMock()
    response = connection.getresponse.return_value
    response.status, response.getheaders.return_value, response.read.return_value = status, headers, body
    with mock.patch.object(readback.http.client, "HTTPSConnection", return_value=connection) as factory, mock.patch.object(readback, "MAX_RESPONSE_BYTES", 1), mock.patch.object(readback.time, "sleep") as sleep:
        try:
            transport.request("GET", "/v2/")
        except readback.Refusal:
            pass
        else:
            raise AssertionError("semantic transport refusal must stop immediately")
        assert factory.call_count == 1
        sleep.assert_not_called()
    connection.close.assert_called_once()

for operation, status, headers in [
    (lambda: readback.token_for_image(transport, "fixture-user", "fixture-password", SOURCE_SHA), 403, []),
    (lambda: readback.readback(transport, "fixture-token", SOURCE_SHA, DIGEST), 200,
     [("Content-Type", "application/vnd.oci.image.manifest.v1+json"), ("Docker-Content-Digest", DIGEST)]),
]:
    connection = mock.MagicMock()
    response = connection.getresponse.return_value
    response.status, response.getheaders.return_value, response.read.return_value = status, headers, b"{}"
    with mock.patch.object(readback.http.client, "HTTPSConnection", return_value=connection) as factory, mock.patch.object(readback.time, "sleep") as sleep:
        try:
            operation()
        except readback.Refusal:
            pass
        else:
            raise AssertionError("authentication or digest refusal must not retry")
        assert factory.call_count == 1
        sleep.assert_not_called()
    connection.close.assert_called_once()

print("offline image readback contract tests passed")
