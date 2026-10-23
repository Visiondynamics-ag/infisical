#!/usr/bin/env python3
"""Publish the fixed Infisical CI evidence artifact to Harbor.

The helper is intentionally a narrow OCI registry client.  Registry host,
source repository, evidence repository, tag, layer names, and manifest shape
are constants.  It accepts only the push robot and public Harbor CA supplied
to this trusted main-push step.  It never prints credential values, embeds
them in URLs, or writes them into a custody artifact.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import time
from typing import Any, Mapping
from urllib.parse import parse_qsl, quote, urlsplit


REGISTRY_HOST = "10.43.0.50"
REGISTRY_REPOSITORY = "10.43.0.50/infisical/infisical"
EVIDENCE_REPOSITORY = "infisical/ci-evidence"
SOURCE_REPOSITORY = "Visiondynamics-ag/infisical"
HANDOFF_NAME = "infisical-harbor-image-handoff.json"
REPORT_NAME = "trivy-image.json"
READBACK_NAME = "image-readback.json"
SOURCE_SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
EVIDENCE_ARTIFACT_TYPE = "application/vnd.visiondynamics.ci-evidence.v1+json"
JSON_MEDIA_TYPE = "application/json"
EMPTY_CONFIG_BYTES = b"{}"
EMPTY_CONFIG_DIGEST = "sha256:" + hashlib.sha256(EMPTY_CONFIG_BYTES).hexdigest()
SCANNER_IMAGE = "aquasec/trivy@sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c"
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_HANDOFF_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
REQUEST_TIMEOUT = 30.0


class Refusal(RuntimeError):
    pass


class DuplicateJSONKey(ValueError):
    pass


def fail(message: str) -> None:
    raise Refusal(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey(key)
        result[key] = value
    return result


def strict_json(raw: bytes, label: str, maximum: int) -> Any:
    require(len(raw) <= maximum, f"{label} is oversized")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_pairs,
            parse_constant=lambda value: fail(f"{label} contains a non-finite number {value}"),
        )
    except Refusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJSONKey):
        fail(f"{label} is not valid non-duplicated JSON")


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == expected, f"{label} schema changed")
    return value


def exact_digest(value: Any, label: str, *, nonzero: bool = False) -> str:
    require(isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None, f"{label} is malformed")
    if nonzero:
        require(value != "sha256:" + "0" * 64, f"{label} is zero")
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _no_symlink_path(path: Path, label: str, *, must_exist: bool = True) -> None:
    try:
        if must_exist:
            resolved = path.resolve(strict=True)
        else:
            resolved = path.parent.resolve(strict=True) / path.name
    except OSError:
        fail(f"{label} cannot be inspected safely")
    require(resolved == path, f"{label} resolves through a symlink")


def _owner_only(info: os.stat_result, label: str, *, hard_link: bool = False) -> None:
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), f"{label} has an invalid type")
    require(info.st_uid == os.geteuid(), f"{label} is not owned by the job user")
    require(info.st_gid == os.getegid(), f"{label} does not have the job group")
    allowed_modes = (0o700, 0o2770) if stat.S_ISDIR(info.st_mode) else (0o600, 0o660)
    require(stat.S_IMODE(info.st_mode) in allowed_modes, f"{label} has an unsupported mode")
    if hard_link:
        require(info.st_nlink == 1, f"{label} has unexpected hard links")


def read_owner_only(path_value: Path, label: str, maximum: int) -> bytes:
    path = path_value if path_value.is_absolute() else path_value.resolve()
    _no_symlink_path(path, label)
    try:
        initial = path.lstat()
        _owner_only(initial, label, hard_link=True)
        require(stat.S_ISREG(initial.st_mode), f"{label} is not a regular file")
        require(initial.st_size <= maximum, f"{label} is oversized")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            _owner_only(opened, label, hard_link=True)
            require(
                opened.st_dev == initial.st_dev
                and opened.st_ino == initial.st_ino
                and opened.st_size == initial.st_size
                and opened.st_nlink == initial.st_nlink,
                f"{label} changed while opening",
            )
            data = b""
            while len(data) <= maximum:
                chunk = os.read(fd, min(1024 * 1024, maximum + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
            require(len(data) <= maximum, f"{label} is oversized")
            after = os.fstat(fd)
            _owner_only(after, label, hard_link=True)
            require(
                after.st_dev == opened.st_dev
                and after.st_ino == opened.st_ino
                and after.st_size == opened.st_size
                and after.st_mtime_ns == opened.st_mtime_ns
                and after.st_ctime_ns == opened.st_ctime_ns,
                f"{label} changed while reading",
            )
        finally:
            os.close(fd)
        final = path.lstat()
        _owner_only(final, label, hard_link=True)
        require(
            final.st_dev == initial.st_dev
            and final.st_ino == initial.st_ino
            and final.st_size == len(data)
            and final.st_mtime_ns == initial.st_mtime_ns
            and final.st_ctime_ns == initial.st_ctime_ns,
            f"{label} changed after reading",
        )
        return data
    except Refusal:
        raise
    except OSError:
        fail(f"{label} could not be read safely")


def write_exclusive(path: Path, data: bytes, label: str) -> None:
    _no_symlink_path(path, label, must_exist=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, data)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
    except FileExistsError:
        fail(f"{label} already exists")
    except OSError:
        fail(f"{label} could not be written safely")


def artifact_directory() -> Path:
    configured = Path(os.environ.get("CI_ARTIFACTS_DIR", ".ci-artifacts"))
    directory = configured if configured.is_absolute() else (Path.cwd() / configured)
    _no_symlink_path(directory, "CI artifact directory")
    try:
        info = directory.lstat()
    except OSError:
        fail("CI artifact directory is missing")
    require(stat.S_ISDIR(info.st_mode), "CI artifact path is not a directory")
    _owner_only(info, "CI artifact directory")
    return directory


def validate_context() -> str:
    require(os.environ.get("CI_PIPELINE_EVENT") == "push", "a protected push event is required")
    require(os.environ.get("CI_COMMIT_BRANCH") == "main", "the protected main branch is required")
    require(os.environ.get("CI_COMMIT_REF") == "refs/heads/main", "the protected main ref is required")
    require(os.environ.get("CI_REPO") == SOURCE_REPOSITORY, "source repository is outside the custody boundary")
    source_sha = os.environ.get("CI_COMMIT_SHA", "")
    require(SOURCE_SHA_RE.fullmatch(source_sha) is not None, "source commit must be a lowercase full SHA")
    require(os.environ.get("REGISTRY_REPOSITORY") == REGISTRY_REPOSITORY, "Harbor repository is outside the custody boundary")
    return source_sha


def validate_certificate(encoded: str) -> bytes:
    require(isinstance(encoded, str) and encoded != "", "Harbor CA secret is missing")
    require(re.fullmatch(r"[A-Za-z0-9+/=]+", encoded) is not None, "Harbor CA secret is not strict base64")
    require(len(encoded) % 4 == 0, "Harbor CA secret is not strict base64")
    try:
        decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        fail("Harbor CA secret is not strict base64")
    require(base64.b64encode(decoded).decode("ascii") == encoded, "Harbor CA secret is not canonical base64")
    require(len(decoded) <= 256 * 1024, "Harbor CA secret is oversized")
    require(b"PRIVATE KEY" not in decoded, "Harbor CA must not contain a private key")
    require(decoded.count(b"-----BEGIN CERTIFICATE-----") == 1 and decoded.count(b"-----END CERTIFICATE-----") == 1, "Harbor CA must contain one public certificate")
    try:
        pem = decoded.decode("ascii")
        ssl.PEM_cert_to_DER_cert(pem)
        context = ssl.create_default_context(cadata=pem)
    except (UnicodeDecodeError, ValueError, ssl.SSLError):
        fail("Harbor CA is not a valid public certificate")
    del context
    return decoded


def validate_handoff(source_sha: str, handoff_raw: bytes, report_raw: bytes,
                     readback_raw: bytes | None = None) -> dict[str, Any]:
    handoff = strict_json(handoff_raw, "Harbor image handoff", MAX_HANDOFF_BYTES)
    handoff = exact_keys(
        handoff,
        {
            "apiVersion", "kind", "version", "state", "sourceRepository", "sourceSha",
            "repository", "imageReference", "manifestDigest", "imageReadback", "report", "scanner",
            "verification", "verifiedAt",
        },
        "Harbor image handoff",
    )
    require(handoff["apiVersion"] == "infisical.visiondynamics.ch/v1alpha1", "Harbor handoff API version changed")
    require(handoff["kind"] == "InfisicalHarborImageHandoff" and handoff["version"] == 1, "Harbor handoff identity changed")
    require(handoff["state"] == "verified", "Harbor handoff state changed")
    require(handoff["sourceRepository"] == SOURCE_REPOSITORY and handoff["sourceSha"] == source_sha, "Harbor handoff source binding changed")
    manifest_digest = exact_digest(handoff["manifestDigest"], "Harbor handoff manifest digest", nonzero=True)
    require(handoff["repository"] == REGISTRY_REPOSITORY, "Harbor handoff repository changed")
    require(handoff["imageReference"] == f"{REGISTRY_REPOSITORY}:{source_sha}@{manifest_digest}", "Harbor handoff image reference changed")

    readback_binding = exact_keys(handoff["imageReadback"], {"path", "sha256"}, "Harbor image readback binding")
    require(readback_binding["path"] == f".ci-artifacts/{READBACK_NAME}", "Harbor image readback path changed")
    require(isinstance(readback_binding["sha256"], str) and HEX64_RE.fullmatch(readback_binding["sha256"]) is not None, "Harbor image readback digest is malformed")
    if readback_raw is not None:
        require(readback_binding["sha256"] == sha256_bytes(readback_raw), "Harbor image readback digest is not bound")
        readback = strict_json(readback_raw, "Harbor image readback", 64 * 1024)
        require(isinstance(readback, dict), "Harbor image readback is malformed")
        require(readback.get("apiVersion") == "infisical.visiondynamics.ch/v1alpha1", "Harbor image readback API version changed")
        require(readback.get("kind") == "InfisicalImageManifestReadback" and readback.get("version") == 1 and readback.get("state") == "verified", "Harbor image readback identity changed")
        require(readback.get("sourceRepository") == SOURCE_REPOSITORY and readback.get("sourceSha") == source_sha, "Harbor image readback source binding changed")
        require(readback.get("repository") == REGISTRY_REPOSITORY and readback.get("tag") == source_sha, "Harbor image readback repository binding changed")
        require(readback.get("imageReference") == handoff["imageReference"] and readback.get("manifestDigest") == manifest_digest, "Harbor image readback image binding changed")
        require(isinstance(readback.get("manifestBytesSha256"), str) and HEX64_RE.fullmatch(readback["manifestBytesSha256"]) is not None, "Harbor image readback byte digest is malformed")
        require(readback["manifestBytesSha256"] == manifest_digest[len("sha256:"):], "Harbor image readback byte digest does not match the manifest digest")
        exact_digest(readback.get("contentDigestHeader"), "Harbor image readback content digest", nonzero=True)
        require(readback["contentDigestHeader"] == manifest_digest, "Harbor image readback content digest changed")

    report_binding = exact_keys(handoff["report"], {"path", "sha256"}, "Harbor handoff report")
    require(report_binding["path"] == ".ci-artifacts/trivy-image.json", "Harbor handoff report path changed")
    require(isinstance(report_binding["sha256"], str) and HEX64_RE.fullmatch(report_binding["sha256"]) is not None, "Harbor handoff report digest is malformed")
    require(report_binding["sha256"] == sha256_bytes(report_raw), "Harbor handoff report digest is not bound")

    scanner = exact_keys(handoff["scanner"], {"image", "scanners", "ignoreUnfixed", "severities"}, "Harbor handoff scanner")
    require(
        scanner == {
            "image": SCANNER_IMAGE,
            "scanners": ["vuln", "secret"],
            "ignoreUnfixed": False,
            "severities": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        },
        "Harbor handoff scanner policy changed",
    )
    verification = exact_keys(
        handoff["verification"],
        {
            "vulnerabilityPolicyPassed", "sourceProvenance", "remoteManifestReadback",
            "secretScanPerformed", "secretValuesPrinted", "gitopsMutation", "dnsMutation",
            "deploymentMutation",
        },
        "Harbor handoff verification",
    )
    require(
        verification == {
            "vulnerabilityPolicyPassed": True,
            "sourceProvenance": False,
            "remoteManifestReadback": True,
            "secretScanPerformed": True,
            "secretValuesPrinted": False,
            "gitopsMutation": False,
            "dnsMutation": False,
            "deploymentMutation": False,
        },
        "Harbor handoff verification policy changed",
    )
    require(isinstance(handoff["verifiedAt"], str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", handoff["verifiedAt"]) is not None, "Harbor handoff verification time is malformed")

    report = strict_json(report_raw, "Trivy report", MAX_REPORT_BYTES)
    require(isinstance(report, dict) and report.get("SchemaVersion") == 2 and report.get("ArtifactType") == "container_image", "Trivy report schema changed")
    require(isinstance(report.get("Results"), list), "Trivy report does not contain a Results array")
    require(report.get("ArtifactName") == handoff["imageReference"], "Trivy report image binding changed")
    metadata = report.get("Metadata")
    require(isinstance(metadata, dict), "Trivy report metadata is malformed")
    require(metadata.get("RepoDigests") == [f"{REGISTRY_REPOSITORY}@{manifest_digest}"], "Trivy report digest binding changed")
    for result in report["Results"]:
        require(isinstance(result, dict), "Trivy result is malformed")
        vulnerabilities = result.get("Vulnerabilities") or []
        require(isinstance(vulnerabilities, list), "Trivy vulnerabilities are malformed")
        for vulnerability in vulnerabilities:
            require(isinstance(vulnerability, dict), "Trivy vulnerability is malformed")
            require(vulnerability.get("Severity") not in {"HIGH", "CRITICAL"}, "Trivy report contains an unsafe finding")
        secrets = result.get("Secrets")
        require(isinstance(secrets, list) and not secrets, "Trivy report contains secret findings")
    return handoff


class Response:
    def __init__(self, status: int, headers: Mapping[str, str], body: bytes) -> None:
        self.status = status
        self.headers = {str(key).lower(): str(value).strip() for key, value in headers.items()}
        self.body = body


class HarborTransport:
    def __init__(self, ca_bytes: bytes) -> None:
        try:
            self.context = ssl.create_default_context(cadata=ca_bytes.decode("ascii"))
        except (UnicodeDecodeError, ssl.SSLError):
            fail("Harbor CA could not initialize TLS safely")
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.check_hostname = True

    def request(self, method: str, request_path: str, headers: Mapping[str, str] | None = None, body: bytes = b"") -> Response:
        require(method in {"GET", "HEAD", "POST", "PUT", "PATCH"}, "Harbor transport method is not approved")
        require(request_path.startswith("/") and "\\" not in request_path and "\x00" not in request_path, "Harbor transport path is malformed")
        parts = request_path.split("?", 1)[0].split("/")
        require(".." not in parts and "." not in parts, "Harbor transport path escapes its fixed root")
        request_headers = {"Host": REGISTRY_HOST, "Connection": "close"}
        if headers:
            for key, value in headers.items():
                require("\r" not in key + value and "\n" not in key + value, "Harbor transport header is malformed")
                require(key.lower() not in {"host", "connection", "content-length"}, "Harbor transport header is reserved")
                request_headers[key] = value
        # Retry only transport failures of idempotent reads; registry writes
        # may already have succeeded when their response is lost.
        attempts = 3 if method in {"GET", "HEAD"} else 1
        for attempt in range(attempts):
            connection: http.client.HTTPSConnection | None = None
            try:
                connection = http.client.HTTPSConnection(REGISTRY_HOST, 443, context=self.context, timeout=REQUEST_TIMEOUT)
                connection.request(method, request_path, body=body, headers=request_headers)
                response = connection.getresponse()
                response_body = response.read(MAX_RESPONSE_BYTES + 1)
                require(len(response_body) <= MAX_RESPONSE_BYTES, "Harbor response is oversized")
                output_headers: dict[str, str] = {}
                for key, value in response.getheaders():
                    lowered = key.lower()
                    require(lowered not in output_headers or lowered in {"content-length", "docker-content-digest"}, "Harbor response framing is ambiguous")
                    output_headers[lowered] = value.strip()
                require(not 300 <= response.status < 400, "Harbor redirects are forbidden")
                return Response(response.status, output_headers, response_body)
            except Refusal:
                raise
            except ssl.SSLCertVerificationError as error:
                fail(f"Harbor request failed safely ({type(error).__name__})")
            except (OSError, socket.timeout, http.client.HTTPException, ssl.SSLError) as error:
                if attempt == attempts - 1:
                    fail(f"Harbor request failed safely ({type(error).__name__})")
            finally:
                if connection is not None:
                    connection.close()
            time.sleep(attempt + 1)


def _header(response: Response, name: str) -> str | None:
    return response.headers.get(name.lower())


def access_token(transport: HarborTransport, username: str, password: str, source_sha: str) -> str:
    manifest_path = f"/v2/{EVIDENCE_REPOSITORY}/manifests/{source_sha}"
    challenge = transport.request("HEAD", manifest_path, {"Accept": MANIFEST_MEDIA_TYPE})
    require(challenge.status == 401, "Harbor registry did not issue an authentication challenge")
    challenge_value = _header(challenge, "www-authenticate") or ""
    match = re.fullmatch(r'Bearer realm="([^"]+)",service="([^"]+)",scope="([^"]+)"', challenge_value)
    require(match is not None, "Harbor registry challenge is malformed")
    realm, service, scope = match.groups()
    require(realm == f"https://{REGISTRY_HOST}/service/token", "Harbor token realm is foreign")
    require(service == "harbor-registry", "Harbor token service is foreign")
    require(scope in {
        f"repository:{EVIDENCE_REPOSITORY}:pull",
        f"repository:{EVIDENCE_REPOSITORY}:push,pull",
        f"repository:{EVIDENCE_REPOSITORY}:pull,push",
    }, "Harbor token scope is foreign")
    token_path = "/service/token?service=harbor-registry&scope=" + quote(f"repository:{EVIDENCE_REPOSITORY}:push,pull", safe="")
    basic = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    response = transport.request("GET", token_path, {"Authorization": f"Basic {basic}", "Accept": "application/json"})
    require(response.status == 200, "Harbor token request failed")
    document = strict_json(response.body, "Harbor token response", 32 * 1024)
    require(isinstance(document, dict), "Harbor token response is malformed")
    token = document.get("token") or document.get("access_token")
    require(isinstance(token, str) and token and not re.search(r"[\x00\r\n]", token), "Harbor token response is malformed")
    return token


def check_blob(transport: HarborTransport, token: str, digest: str) -> bool:
    response = transport.request(
        "HEAD",
        f"/v2/{EVIDENCE_REPOSITORY}/blobs/{digest}",
        {"Authorization": f"Bearer {token}"},
    )
    if response.status == 404:
        return False
    require(response.status == 200, "Harbor blob check failed")
    header_digest = _header(response, "docker-content-digest")
    require(header_digest in {None, digest}, "Harbor blob digest changed")
    return True


def upload_blob(transport: HarborTransport, token: str, data: bytes, digest: str) -> None:
    if check_blob(transport, token, digest):
        return
    start = transport.request(
        "POST",
        f"/v2/{EVIDENCE_REPOSITORY}/blobs/uploads/",
        {"Authorization": f"Bearer {token}"},
    )
    require(start.status == 202, "Harbor blob upload did not start")
    location = _header(start, "location")
    require(location is not None, "Harbor blob upload location is missing")
    parsed = urlsplit(location)
    if parsed.scheme or parsed.netloc:
        require(parsed.scheme == "https" and parsed.netloc == REGISTRY_HOST, "Harbor blob upload location is foreign")
        location = parsed.path + (("?" + parsed.query) if parsed.query else "")
    require(location.startswith(f"/v2/{EVIDENCE_REPOSITORY}/blobs/uploads/"), "Harbor blob upload location is foreign")
    separator = "&" if "?" in location else "?"
    complete = transport.request(
        "PUT",
        f"{location}{separator}digest={quote(digest, safe=':')}",
        {"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"},
        data,
    )
    require(complete.status in {201, 202}, "Harbor blob upload failed")
    returned = _header(complete, "docker-content-digest")
    require(returned in {None, digest}, "Harbor blob upload digest changed")


def publish_manifest(transport: HarborTransport, token: str, source_sha: str, manifest: bytes) -> str:
    manifest_digest = "sha256:" + sha256_bytes(manifest)
    existing = transport.request(
        "HEAD",
        f"/v2/{EVIDENCE_REPOSITORY}/manifests/{source_sha}",
        {"Authorization": f"Bearer {token}", "Accept": MANIFEST_MEDIA_TYPE},
    )
    if existing.status == 200:
        existing_digest = _header(existing, "docker-content-digest")
        require(existing_digest == manifest_digest, "Harbor evidence tag is already bound to different bytes")
        return manifest_digest
    require(existing.status == 404, "Harbor evidence tag readback failed")
    response = transport.request(
        "PUT",
        f"/v2/{EVIDENCE_REPOSITORY}/manifests/{source_sha}",
        {"Authorization": f"Bearer {token}", "Content-Type": MANIFEST_MEDIA_TYPE},
        manifest,
    )
    require(response.status in {200, 201}, "Harbor evidence manifest publication failed")
    returned = _header(response, "docker-content-digest")
    require(returned in {None, manifest_digest}, "Harbor evidence manifest digest changed")
    return manifest_digest


def readback_blob(transport: HarborTransport, token: str, descriptor: Mapping[str, Any], expected: bytes, label: str) -> None:
    digest_value = exact_digest(descriptor.get("digest"), f"{label} digest")
    size = descriptor.get("size")
    require(type(size) is int and size >= 0, f"{label} size is malformed")
    media_type = descriptor.get("mediaType")
    require(isinstance(media_type, str) and media_type != "", f"{label} media type is malformed")
    response = transport.request(
        "GET",
        f"/v2/{EVIDENCE_REPOSITORY}/blobs/{digest_value}",
        {"Authorization": f"Bearer {token}", "Accept": "application/octet-stream"},
    )
    require(response.status == 200, f"{label} readback failed")
    returned = _header(response, "docker-content-digest")
    require(returned in {None, digest_value}, f"{label} digest header changed")
    require(
        len(response.body) == size
        and response.body == expected
        and "sha256:" + sha256_bytes(response.body) == digest_value,
        f"{label} bytes failed readback",
    )


def readback_artifact(
    transport: HarborTransport,
    token: str,
    source_sha: str,
    manifest_raw: bytes,
    layers: list[tuple[Mapping[str, Any], bytes]],
) -> str:
    """Read back the published manifest, empty config, and every evidence layer."""
    require(SOURCE_SHA_RE.fullmatch(source_sha) is not None, "Harbor evidence source tag is malformed")
    expected_manifest = strict_json(manifest_raw, "local Harbor evidence manifest", MAX_MANIFEST_BYTES)
    require(isinstance(expected_manifest, dict), "local Harbor evidence manifest is malformed")
    manifest_digest = "sha256:" + sha256_bytes(manifest_raw)
    response = transport.request(
        "GET",
        f"/v2/{EVIDENCE_REPOSITORY}/manifests/{source_sha}",
        {"Authorization": f"Bearer {token}", "Accept": MANIFEST_MEDIA_TYPE},
    )
    require(response.status == 200, "Harbor evidence manifest readback failed")
    require(_header(response, "content-type") == MANIFEST_MEDIA_TYPE, "Harbor evidence manifest media type changed")
    content_digest = _header(response, "docker-content-digest")
    require(content_digest == "sha256:" + sha256_bytes(response.body), "Harbor evidence manifest digest header changed")
    require(content_digest == manifest_digest, "Harbor evidence manifest digest does not match the publication")
    remote_manifest = strict_json(response.body, "Harbor evidence manifest readback", MAX_MANIFEST_BYTES)
    require(remote_manifest == expected_manifest, "Harbor evidence manifest bytes changed")

    config = expected_manifest.get("config")
    require(isinstance(config, dict), "Harbor evidence config descriptor is malformed")
    readback_blob(transport, token, config, EMPTY_CONFIG_BYTES, "Harbor evidence config")
    for index, (descriptor, expected) in enumerate(layers):
        readback_blob(transport, token, descriptor, expected, f"Harbor evidence layer {index}")
    return manifest_digest


def build_manifest(source_sha: str, handoff_raw: bytes, report_raw: bytes,
                   readback_raw: bytes | None = None) -> tuple[bytes, list[dict[str, Any]]]:
    handoff_digest = "sha256:" + sha256_bytes(handoff_raw)
    report_digest = "sha256:" + sha256_bytes(report_raw)
    layers = [
        {
            "mediaType": JSON_MEDIA_TYPE,
            "digest": handoff_digest,
            "size": len(handoff_raw),
            "annotations": {"org.opencontainers.image.title": f".ci-artifacts/{HANDOFF_NAME}"},
        },
        {
            "mediaType": JSON_MEDIA_TYPE,
            "digest": report_digest,
            "size": len(report_raw),
            "annotations": {"org.opencontainers.image.title": f".ci-artifacts/{REPORT_NAME}"},
        },
    ]
    if readback_raw is not None:
        layers.append({
            "mediaType": JSON_MEDIA_TYPE,
            "digest": "sha256:" + sha256_bytes(readback_raw),
            "size": len(readback_raw),
            "annotations": {"org.opencontainers.image.title": f".ci-artifacts/{READBACK_NAME}"},
        })
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "artifactType": EVIDENCE_ARTIFACT_TYPE,
        "config": {
            "mediaType": EMPTY_CONFIG_MEDIA_TYPE,
            "digest": EMPTY_CONFIG_DIGEST,
            "size": len(EMPTY_CONFIG_BYTES),
        },
        "layers": layers,
        "annotations": {
            "org.opencontainers.image.revision": source_sha,
            "org.opencontainers.image.source": f"https://github.com/{SOURCE_REPOSITORY}",
        },
    }
    raw = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    require(len(raw) <= MAX_MANIFEST_BYTES, "Harbor evidence manifest is oversized")
    return raw, layers


def main() -> int:
    parser = argparse.ArgumentParser(description="publish the fixed Infisical Harbor evidence artifact")
    parser.add_argument("--project", choices=("infisical",), default="infisical")
    args = parser.parse_args()
    del args
    source_sha = validate_context()
    username = os.environ.get("REGISTRY_PUSH_USERNAME", "")
    password = os.environ.get("REGISTRY_PUSH_PASSWORD", "")
    require(username != "", "Harbor push username secret is missing")
    require(password != "", "Harbor push password secret is missing")
    ca_bytes = validate_certificate(os.environ.get("REGISTRY_CA_CERT_BASE64", ""))
    artifact_root = artifact_directory()
    handoff_path = artifact_root / HANDOFF_NAME
    report_path = artifact_root / REPORT_NAME
    readback_path = artifact_root / READBACK_NAME
    handoff_raw = read_owner_only(handoff_path, "Harbor image handoff", MAX_HANDOFF_BYTES)
    report_raw = read_owner_only(report_path, "Trivy report", MAX_REPORT_BYTES)
    readback_raw = read_owner_only(readback_path, "Harbor image readback", 64 * 1024)
    handoff = validate_handoff(source_sha, handoff_raw, report_raw, readback_raw)
    manifest_raw, layers = build_manifest(source_sha, handoff_raw, report_raw, readback_raw)

    transport = HarborTransport(ca_bytes)
    token = access_token(transport, username, password, source_sha)
    # Do not retain the robot password beyond the token request.
    password = "\x00" * len(password)
    upload_blob(transport, token, EMPTY_CONFIG_BYTES, EMPTY_CONFIG_DIGEST)
    upload_blob(transport, token, handoff_raw, layers[0]["digest"])
    upload_blob(transport, token, report_raw, layers[1]["digest"])
    upload_blob(transport, token, readback_raw, layers[2]["digest"])
    published_manifest_digest = publish_manifest(transport, token, source_sha, manifest_raw)
    manifest_digest = readback_artifact(
        transport,
        token,
        source_sha,
        manifest_raw,
        [(layers[0], handoff_raw), (layers[1], report_raw), (layers[2], readback_raw)],
    )
    require(manifest_digest == published_manifest_digest, "Harbor evidence manifest digest changed during readback")

    publication = {
        "apiVersion": "infisical.visiondynamics.ch/v1alpha1",
        "kind": "InfisicalHarborEvidencePublication",
        "version": 1,
        "state": "published",
        "sourceRepository": SOURCE_REPOSITORY,
        "sourceSha": source_sha,
        "repository": f"{REGISTRY_HOST}/{EVIDENCE_REPOSITORY}",
        "tag": source_sha,
        "manifestDigest": manifest_digest,
        "manifestBytesSha256": sha256_bytes(manifest_raw),
        "layers": [
            {"path": f".ci-artifacts/{HANDOFF_NAME}", "digest": layers[0]["digest"], "size": layers[0]["size"]},
            {"path": f".ci-artifacts/{REPORT_NAME}", "digest": layers[1]["digest"], "size": layers[1]["size"]},
            {"path": f".ci-artifacts/{READBACK_NAME}", "digest": layers[2]["digest"], "size": layers[2]["size"]},
        ],
        "handoffImageReference": handoff["imageReference"],
        "secretValuesPrinted": False,
        "gitopsMutation": False,
        "dnsMutation": False,
        "deploymentMutation": False,
    }
    write_exclusive(artifact_root / "harbor-evidence-publication.json", (json.dumps(publication, sort_keys=True) + "\n").encode("utf-8"), "Harbor evidence publication")
    print("Harbor evidence published for the immutable commit tag")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"Harbor evidence failed closed: {error}", file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, TypeError, ssl.SSLError):
        print("Harbor evidence failed closed: external or malformed input was rejected", file=sys.stderr)
        raise SystemExit(1)
