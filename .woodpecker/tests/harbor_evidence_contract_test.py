#!/usr/bin/env python3
"""Offline refusal and custody checks for the Harbor evidence publisher."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import ssl
from unittest import mock
import subprocess
import sys
import tempfile


# Exercise the real job-group projection on Linux; this macOS filesystem
# strips setgid. Keep the same protocol tests on owner-only directories there.
with tempfile.TemporaryDirectory(prefix="infisical-mode-probe-") as temporary:
    mode_probe = Path(temporary)
    mode_probe.chmod(0o2770)
    CI_DIRECTORY_MODE = 0o2770 if stat.S_IMODE(mode_probe.stat().st_mode) == 0o2770 else 0o700
if CI_DIRECTORY_MODE != 0o2770:
    print("Group-directory projection unavailable here; owner-only protocol fixtures exercised")

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / ".woodpecker" / "scripts" / "harbor_evidence.py"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
REGISTRY = "10.43.0.50/infisical/infisical"
CA = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n").decode("ascii")

module_spec = importlib.util.spec_from_file_location("infisical_harbor_evidence", HELPER)
assert module_spec is not None and module_spec.loader is not None
evidence = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(evidence)



# Exercise the shipped HTTP transport with connection I/O replaced, including
# failures after a request was sent. No provider or network is contacted.
roots = ssl.create_default_context().get_ca_certs(binary_form=True)
assert roots, "the standard Python image must include public CA roots"
transport = evidence.HarborTransport(ssl.DER_cert_to_PEM_cert(roots[0]).encode())
failures = [ConnectionRefusedError, OSError, evidence.socket.timeout, evidence.http.client.HTTPException, ssl.SSLError]
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
            with mock.patch.object(evidence.http.client, "HTTPSConnection", side_effect=[first, second]) as factory, mock.patch.object(evidence.time, "sleep") as sleep:
                assert transport.request(method, "/v2/", {"Authorization": "Bearer private-fixture-value"}).body == b"ok"
                assert factory.call_count == 2
                assert sleep.call_args_list == [mock.call(1)]
                for call in factory.call_args_list:
                    assert call.args == (evidence.REGISTRY_HOST, 443)
                    assert call.kwargs["context"] is transport.context
            first.close.assert_called_once()
            second.close.assert_called_once()
    for failure in failures:
        connections = [mock.MagicMock() for _ in range(3)]
        for connection in connections:
            connection.getresponse.side_effect = failure("private-fixture-value")
        with mock.patch.object(evidence.http.client, "HTTPSConnection", side_effect=connections) as factory, mock.patch.object(evidence.time, "sleep") as sleep:
            try:
                transport.request(method, "/v2/")
            except evidence.Refusal as error:
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
    with mock.patch.object(evidence.http.client, "HTTPSConnection", return_value=connection) as factory, mock.patch.object(evidence.time, "sleep") as sleep:
        try:
            transport.request(method, "/v2/")
        except evidence.Refusal as error:
            assert str(error) == "Harbor request failed safely (SSLCertVerificationError)"
        else:
            raise AssertionError("certificate verification failures must stop immediately")
        assert factory.call_count == 1
        sleep.assert_not_called()
    connection.close.assert_called_once()
with mock.patch.object(evidence.http.client, "HTTPSConnection") as factory, mock.patch.object(evidence.time, "sleep") as sleep:
    try:
        transport.request("DELETE", "/v2/")
    except evidence.Refusal:
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
    with mock.patch.object(evidence.http.client, "HTTPSConnection", return_value=connection) as factory, mock.patch.object(evidence, "MAX_RESPONSE_BYTES", 1), mock.patch.object(evidence.time, "sleep") as sleep:
        try:
            transport.request("GET", "/v2/")
        except evidence.Refusal:
            pass
        else:
            raise AssertionError("semantic transport refusal must stop immediately")
        assert factory.call_count == 1
        sleep.assert_not_called()
    connection.close.assert_called_once()

for operation, status, headers in [
    (lambda: evidence.access_token(transport, "fixture-user", "fixture-password", SOURCE_SHA), 403, []),
    (lambda: evidence.check_blob(transport, "fixture-token", "sha256:" + "a" * 64), 200,
     [("Docker-Content-Digest", "sha256:" + "b" * 64)]),
]:
    connection = mock.MagicMock()
    response = connection.getresponse.return_value
    response.status, response.getheaders.return_value, response.read.return_value = status, headers, b""
    with mock.patch.object(evidence.http.client, "HTTPSConnection", return_value=connection) as factory, mock.patch.object(evidence.time, "sleep") as sleep:
        try:
            operation()
        except evidence.Refusal:
            pass
        else:
            raise AssertionError("authentication or digest refusal must not retry")
        assert factory.call_count == 1
        sleep.assert_not_called()
    connection.close.assert_called_once()
for method in ["POST", "PUT", "PATCH"]:
    connection = mock.MagicMock()
    # The write was sent; the response was lost. Retrying could duplicate it.
    connection.getresponse.side_effect = OSError("private-fixture-value")
    with mock.patch.object(evidence.http.client, "HTTPSConnection", return_value=connection) as factory, mock.patch.object(evidence.time, "sleep") as sleep:
        try:
            transport.request(method, "/v2/", body=b"fixture-write")
        except evidence.Refusal as error:
            assert str(error) == "Harbor request failed safely (OSError)"
        else:
            raise AssertionError("ambiguous writes must fail without retry")
        assert factory.call_count == 1
        sleep.assert_not_called()
    connection.request.assert_called_once()
    connection.close.assert_called_once()

MANIFEST_DIGEST = "sha256:" + "a" * 64
IMAGE_REFERENCE = f"{REGISTRY}:{SOURCE_SHA}@{MANIFEST_DIGEST}"


def json_bytes(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def valid_report_document() -> dict[str, object]:
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "ArtifactName": IMAGE_REFERENCE,
        "Metadata": {"RepoDigests": [f"{REGISTRY}@{MANIFEST_DIGEST}"]},
        "Results": [],
    }


def readback_document() -> dict[str, object]:
    return {
        "apiVersion": "infisical.visiondynamics.ch/v1alpha1",
        "kind": "InfisicalImageManifestReadback",
        "version": 1,
        "state": "verified",
        "sourceRepository": "Visiondynamics-ag/infisical",
        "sourceSha": SOURCE_SHA,
        "repository": REGISTRY,
        "tag": SOURCE_SHA,
        "imageReference": IMAGE_REFERENCE,
        "manifestDigest": MANIFEST_DIGEST,
        "manifestBytesSha256": "a" * 64,
        "contentDigestHeader": MANIFEST_DIGEST,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
    }


def handoff_document(report_raw: bytes, readback_raw: bytes) -> dict[str, object]:
    return {
        "apiVersion": "infisical.visiondynamics.ch/v1alpha1",
        "kind": "InfisicalHarborImageHandoff",
        "version": 1,
        "state": "verified",
        "sourceRepository": "Visiondynamics-ag/infisical",
        "sourceSha": SOURCE_SHA,
        "repository": REGISTRY,
        "imageReference": IMAGE_REFERENCE,
        "manifestDigest": MANIFEST_DIGEST,
        "imageReadback": {"path": ".ci-artifacts/image-readback.json", "sha256": evidence.sha256_bytes(readback_raw)},
        "report": {"path": ".ci-artifacts/trivy-image.json", "sha256": evidence.sha256_bytes(report_raw)},
        "scanner": {
            "image": evidence.SCANNER_IMAGE,
            "scanners": ["vuln", "secret"],
            "ignoreUnfixed": False,
            "severities": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        },
        "verification": {
            "vulnerabilityPolicyPassed": True,
            "sourceProvenance": False,
            "remoteManifestReadback": True,
            "secretScanPerformed": True,
            "secretValuesPrinted": False,
            "gitopsMutation": False,
            "dnsMutation": False,
            "deploymentMutation": False,
        },
        "verifiedAt": "2026-09-21T00:00:00Z",
    }


valid_report_raw = json_bytes(valid_report_document())
valid_readback_raw = json_bytes(readback_document())
valid_handoff_raw = json_bytes(handoff_document(valid_report_raw, valid_readback_raw))
assert evidence.validate_handoff(SOURCE_SHA, valid_handoff_raw, valid_report_raw, valid_readback_raw)["imageReference"] == IMAGE_REFERENCE

mismatched_readback = readback_document()
mismatched_readback["manifestBytesSha256"] = "b" * 64
mismatched_readback_raw = json_bytes(mismatched_readback)
try:
    evidence.validate_handoff(
        SOURCE_SHA,
        json_bytes(handoff_document(valid_report_raw, mismatched_readback_raw)),
        valid_report_raw,
        mismatched_readback_raw,
    )
except evidence.Refusal:
    pass
else:
    raise AssertionError("readback byte digest mismatch must fail closed")

for label, mutate in (
    ("missing ArtifactName", lambda document: document.pop("ArtifactName")),
    ("wrong ArtifactName", lambda document: document.update({"ArtifactName": f"{REGISTRY}@{MANIFEST_DIGEST}"})),
    ("missing Metadata", lambda document: document.pop("Metadata")),
    ("missing ImageID", lambda document: document.update({"Metadata": {}})),
    ("malformed ImageID", lambda document: document.update({"Metadata": {"ImageID": "sha256:" + "0" * 64}})),
):
    candidate = json.loads(valid_report_raw)
    mutate(candidate)
    candidate_raw = json_bytes(candidate)
    try:
        evidence.validate_handoff(SOURCE_SHA, json_bytes(handoff_document(candidate_raw, valid_readback_raw)), candidate_raw, valid_readback_raw)
    except evidence.Refusal:
        pass
    else:
        raise AssertionError(f"{label} must fail closed")


def run(artifact: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "CI_PIPELINE_EVENT": "push",
            "CI_COMMIT_BRANCH": "main",
            "CI_COMMIT_REF": "refs/heads/main",
            "CI_REPO": "Visiondynamics-ag/infisical",
            "CI_COMMIT_SHA": SOURCE_SHA,
            "REGISTRY_REPOSITORY": REGISTRY,
            "CI_ARTIFACTS_DIR": str(artifact),
            **overrides,
        }
    )
    return subprocess.run([sys.executable, str(HELPER), "--project", "infisical"], cwd=ROOT, env=environment, text=True, capture_output=True)


with tempfile.TemporaryDirectory(prefix="infisical-evidence-contract-") as temporary:
    artifact = Path(temporary) / ".ci-artifacts"
    artifact.mkdir(mode=0o700)
    artifact.chmod(0o700)
    artifact = artifact.resolve()

    custody_file = artifact / "custody-fixture.json"
    evidence.write_exclusive(custody_file, b"{}\n", "offline custody fixture")
    assert stat.S_IMODE(custody_file.stat().st_mode) == 0o600
    try:
        evidence.write_exclusive(custody_file, b"changed\n", "offline custody fixture")
    except evidence.Refusal:
        pass
    else:
        raise AssertionError("owner-only custody output must not be overwritten")

    missing = run(artifact, REGISTRY_PUSH_PASSWORD="sentinel-password")
    assert missing.returncode != 0
    assert "sentinel-password" not in missing.stdout + missing.stderr
    assert not (artifact / "harbor-evidence-publication.json").exists()

    wrong_registry = run(artifact, REGISTRY_REPOSITORY="10.43.0.50/other/image", REGISTRY_PUSH_USERNAME="push-user", REGISTRY_PUSH_PASSWORD="sentinel-password", REGISTRY_CA_CERT_BASE64=CA)
    assert wrong_registry.returncode != 0
    assert "sentinel-password" not in wrong_registry.stdout + wrong_registry.stderr

    malformed_sha = run(artifact, CI_COMMIT_SHA="bad", REGISTRY_PUSH_USERNAME="push-user", REGISTRY_PUSH_PASSWORD="sentinel-password", REGISTRY_CA_CERT_BASE64=CA)
    assert malformed_sha.returncode != 0
    assert "sentinel-password" not in malformed_sha.stdout + malformed_sha.stderr

    handoff = handoff_document(valid_report_raw, valid_readback_raw)
    handoff["manifestDigest"] = "sha256:not-a-digest"
    handoff["imageReference"] = f"{REGISTRY}:{SOURCE_SHA}@sha256:not-a-digest"
    (artifact / "trivy-image.json").write_bytes(valid_report_raw)
    (artifact / "trivy-image.json").chmod(stat.S_IRUSR | stat.S_IWUSR)
    (artifact / "image-readback.json").write_bytes(valid_readback_raw)
    (artifact / "image-readback.json").chmod(stat.S_IRUSR | stat.S_IWUSR)
    (artifact / "infisical-harbor-image-handoff.json").write_bytes(json_bytes(handoff))
    (artifact / "infisical-harbor-image-handoff.json").chmod(stat.S_IRUSR | stat.S_IWUSR)
    malformed_digest = run(artifact, REGISTRY_PUSH_USERNAME="push-user", REGISTRY_PUSH_PASSWORD="sentinel-password", REGISTRY_CA_CERT_BASE64=CA)
    assert malformed_digest.returncode != 0
    assert "sentinel-password" not in malformed_digest.stdout + malformed_digest.stderr
    assert not (artifact / "harbor-evidence-publication.json").exists()

    manifest_raw, layers = evidence.build_manifest(SOURCE_SHA, valid_handoff_raw, valid_report_raw, valid_readback_raw)

    class FakeTransport:
        def __init__(self, manifest: bytes, blobs: dict[str, bytes]):
            self.manifest = manifest
            self.blobs = blobs

        def request(self, method: str, request_path: str, headers=None, body: bytes = b"") -> evidence.Response:
            del headers, body
            if method == "GET" and request_path == f"/v2/{evidence.EVIDENCE_REPOSITORY}/manifests/{SOURCE_SHA}":
                digest = "sha256:" + evidence.sha256_bytes(self.manifest)
                return evidence.Response(
                    200,
                    {"Content-Type": evidence.MANIFEST_MEDIA_TYPE, "Docker-Content-Digest": digest},
                    self.manifest,
                )
            prefix = f"/v2/{evidence.EVIDENCE_REPOSITORY}/blobs/"
            if method == "GET" and request_path.startswith(prefix):
                digest = request_path[len(prefix):]
                if digest in self.blobs:
                    return evidence.Response(200, {"Docker-Content-Digest": digest}, self.blobs[digest])
            return evidence.Response(404, {}, b"")

    blobs = {
        evidence.EMPTY_CONFIG_DIGEST: evidence.EMPTY_CONFIG_BYTES,
        layers[0]["digest"]: valid_handoff_raw,
        layers[1]["digest"]: valid_report_raw,
        layers[2]["digest"]: valid_readback_raw,
    }
    expected_readback_digest = "sha256:" + evidence.sha256_bytes(manifest_raw)
    readback = evidence.readback_artifact(
        FakeTransport(manifest_raw, blobs),
        "token",
        SOURCE_SHA,
        manifest_raw,
        [(layers[0], valid_handoff_raw), (layers[1], valid_report_raw), (layers[2], valid_readback_raw)],
    )
    assert readback == expected_readback_digest

    tampered_manifest_document = json.loads(manifest_raw)
    tampered_manifest_document["artifactType"] = "application/vnd.visiondynamics.ci-evidence.tampered+json"
    tampered_manifest = json.dumps(tampered_manifest_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        evidence.readback_artifact(
            FakeTransport(tampered_manifest, blobs),
            "token",
            SOURCE_SHA,
            manifest_raw,
            [(layers[0], valid_handoff_raw), (layers[1], valid_report_raw), (layers[2], valid_readback_raw)],
        )
    except evidence.Refusal:
        pass
    else:
        raise AssertionError("tampered manifest must fail readback")

    tampered_config = dict(blobs)
    tampered_config[evidence.EMPTY_CONFIG_DIGEST] = b"[]"
    try:
        evidence.readback_artifact(
            FakeTransport(manifest_raw, tampered_config),
            "token",
            SOURCE_SHA,
            manifest_raw,
            [(layers[0], valid_handoff_raw), (layers[1], valid_report_raw), (layers[2], valid_readback_raw)],
        )
    except evidence.Refusal:
        pass
    else:
        raise AssertionError("tampered config must fail readback")

    tampered_layer = dict(blobs)
    tampered_layer[layers[0]["digest"]] = b"tampered handoff"
    try:
        evidence.readback_artifact(
            FakeTransport(manifest_raw, tampered_layer),
            "token",
            SOURCE_SHA,
            manifest_raw,
            [(layers[0], valid_handoff_raw), (layers[1], valid_report_raw), (layers[2], valid_readback_raw)],
        )
    except evidence.Refusal:
        pass
    else:
        raise AssertionError("tampered layer must fail readback")

    # Run the shipped entry point with the existing registry response fixture.
    # Blobs/manifests already exist in this offline registry; no live I/O occurs.
    class MainTransport(FakeTransport):
        def request(self, method, request_path, headers=None, body=b""):
            if method == "HEAD":
                if not headers or "Authorization" not in headers:
                    return evidence.Response(401, {"WWW-Authenticate": f'Bearer realm="https://{evidence.REGISTRY_HOST}/service/token",service="harbor-registry",scope="repository:{evidence.EVIDENCE_REPOSITORY}:pull"'}, b"")
                if "/blobs/" in request_path:
                    return evidence.Response(200, {}, b"")
                return evidence.Response(200, {"Docker-Content-Digest": expected_readback_digest}, b"")
            if request_path.startswith("/service/token?"):
                return evidence.Response(200, {}, b'{"token":"offline-token"}')
            return super().request(method, request_path, headers, body)

    artifact.chmod(CI_DIRECTORY_MODE)
    for name, raw in [("trivy-image.json", valid_report_raw), ("image-readback.json", valid_readback_raw), ("infisical-harbor-image-handoff.json", valid_handoff_raw)]:
        (artifact / name).write_bytes(raw)
        (artifact / name).chmod(0o660)
    roots = ssl.create_default_context().get_ca_certs(binary_form=True)
    assert roots, "the standard Python image must include public CA roots"
    public_ca = base64.b64encode(ssl.DER_cert_to_PEM_cert(roots[0]).encode()).decode()
    environment = {
        "CI_PIPELINE_EVENT": "push", "CI_COMMIT_BRANCH": "main", "CI_COMMIT_REF": "refs/heads/main",
        "CI_REPO": evidence.SOURCE_REPOSITORY, "CI_COMMIT_SHA": SOURCE_SHA,
        "REGISTRY_REPOSITORY": REGISTRY, "CI_ARTIFACTS_DIR": str(artifact),
        "REGISTRY_PUSH_USERNAME": "offline-fixture", "REGISTRY_PUSH_PASSWORD": "offline-fixture-no-provider-access",
        "REGISTRY_CA_CERT_BASE64": public_ca,
    }
    with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(sys, "argv", [str(HELPER)]), mock.patch.object(evidence, "HarborTransport", return_value=MainTransport(manifest_raw, blobs)) as transport:
        assert evidence.main() == 0
        output = artifact / "harbor-evidence-publication.json"
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert json.loads(output.read_text())["manifestDigest"] == expected_readback_digest
        output.unlink()
        for target, safe_mode in [(artifact, CI_DIRECTORY_MODE), (artifact / "infisical-harbor-image-handoff.json", 0o660)]:
            target.chmod(0o777 if target == artifact else 0o666)
            transport.reset_mock()
            try:
                evidence.main()
            except evidence.Refusal as error:
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
                    evidence.main()
                except evidence.Refusal as error:
                    assert "job group" in str(error)
                else:
                    raise AssertionError("different-group custody must fail at the entry point")
                os.chown(target, os.geteuid(), os.getegid())
                target.chmod(safe_mode)
        wrong_group = list((artifact / "trivy-image.json").stat())
        wrong_group[5] = os.getegid() + 1
        try:
            evidence._owner_only(os.stat_result(wrong_group), "wrong-group fixture")
        except evidence.Refusal as error:
            assert "job group" in str(error)
        else:
            raise AssertionError("a non-job GID must be rejected")

print("offline Harbor evidence contract tests passed")
