#!/usr/bin/env python3
"""Read back the pushed Infisical image manifest at its immutable source tag.

This step is deliberately separate from the BuildKit metadata producer. It
proves that Harbor returned the same manifest digest for the source commit
tag before Trivy and evidence custody consume the image.
"""

from __future__ import annotations

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
from typing import Any
from urllib.parse import quote


REGISTRY_HOST = "10.43.0.50"
REGISTRY_REPOSITORY = "10.43.0.50/infisical/infisical"
IMAGE_PATH = "infisical/infisical"
SOURCE_REPOSITORY = "Visiondynamics-ag/infisical"
SOURCE_SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
MAX_ENV_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class Refusal(RuntimeError):
    pass


def fail(message: str) -> None:
    raise Refusal(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exact_digest(value: Any, label: str) -> str:
    require(isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None, f"{label} is malformed")
    require(value != "sha256:" + "0" * 64, f"{label} is zero")
    return value


def no_symlink(path: Path, label: str, *, must_exist: bool = True) -> None:
    try:
        if must_exist:
            resolved = path.resolve(strict=True)
        else:
            resolved = path.parent.resolve(strict=True) / path.name
    except OSError:
        fail(f"{label} cannot be inspected safely")
    require(resolved == path, f"{label} resolves through a symlink")


def owner_only(info: os.stat_result, label: str, *, regular: bool = False) -> None:
    require(stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode), f"{label} has an invalid type")
    require(info.st_uid == os.geteuid(), f"{label} is not owned by the job user")
    require(info.st_gid == os.getegid(), f"{label} does not have the job group")
    allowed_modes = (0o600, 0o660) if regular else (0o700, 0o2770)
    require(stat.S_IMODE(info.st_mode) in allowed_modes, f"{label} has an unsupported mode")
    if regular:
        require(info.st_nlink == 1, f"{label} has unexpected hard links")


def artifact_directory() -> Path:
    configured = Path(os.environ.get("CI_ARTIFACTS_DIR", ".ci-artifacts"))
    directory = configured if configured.is_absolute() else Path.cwd() / configured
    no_symlink(directory, "CI artifact directory")
    try:
        info = directory.lstat()
    except OSError:
        fail("CI artifact directory is missing")
    owner_only(info, "CI artifact directory")
    return directory


def read_private(path: Path, label: str) -> bytes:
    no_symlink(path, label)
    try:
        before = path.lstat()
        owner_only(before, label, regular=True)
        require(before.st_size <= MAX_ENV_BYTES, f"{label} is oversized")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            owner_only(opened, label, regular=True)
            require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), f"{label} changed while opening")
            chunks: list[bytes] = []
            total = 0
            while total <= MAX_ENV_BYTES:
                chunk = os.read(fd, min(64 * 1024, MAX_ENV_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            data = b"".join(chunks)
            after = os.fstat(fd)
            owner_only(after, label, regular=True)
            require(after.st_size == before.st_size and after.st_mtime_ns == before.st_mtime_ns, f"{label} changed while reading")
        finally:
            os.close(fd)
        final = path.lstat()
        owner_only(final, label, regular=True)
        require((final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) ==
                (before.st_dev, before.st_ino, len(data), before.st_mtime_ns), f"{label} changed after reading")
        require(len(data) <= MAX_ENV_BYTES, f"{label} is oversized")
        return data
    except Refusal:
        raise
    except OSError:
        fail(f"{label} could not be read safely")


def write_exclusive(path: Path, data: bytes, label: str) -> None:
    no_symlink(path, label, must_exist=False)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
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


def parse_env(raw: bytes, source_sha: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        require("=" in line and "\r" not in line, "image digest manifest is malformed")
        key, value = line.split("=", 1)
        require(key and key not in values, "image digest manifest contains duplicate entries")
        values[key] = value
    expected = {"SOURCE_REPOSITORY", "SOURCE_SHA", "IMAGE_REPOSITORY", "IMAGE_TAG", "IMAGE_DIGEST", "IMAGE_REF"}
    require(set(values) == expected, "image digest manifest schema changed")
    require(values["SOURCE_REPOSITORY"] == SOURCE_REPOSITORY, "image source repository changed")
    require(values["SOURCE_SHA"] == source_sha and values["IMAGE_TAG"] == source_sha, "image source tag changed")
    require(values["IMAGE_REPOSITORY"] == REGISTRY_REPOSITORY, "image repository changed")
    digest = exact_digest(values["IMAGE_DIGEST"], "image manifest digest")
    require(values["IMAGE_REF"] == f"{REGISTRY_REPOSITORY}:{source_sha}@{digest}", "immutable image reference changed")
    return values


class Response:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = {key.lower(): value.strip() for key, value in headers.items()}
        self.body = body


class Transport:
    def __init__(self, ca_bytes: bytes) -> None:
        try:
            self.context = ssl.create_default_context(cadata=ca_bytes.decode("ascii"))
        except (UnicodeDecodeError, ssl.SSLError):
            fail("Harbor CA could not initialize TLS safely")
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.check_hostname = True

    def request(self, method: str, request_path: str, headers: dict[str, str] | None = None, body: bytes = b"") -> Response:
        require(method in {"GET", "HEAD"}, "registry method is not approved")
        require(request_path.startswith("/") and "\\" not in request_path and "\x00" not in request_path, "registry path is malformed")
        require(".." not in request_path.split("?", 1)[0].split("/"), "registry path escapes its fixed root")
        request_headers = {"Host": REGISTRY_HOST, "Connection": "close"}
        for key, value in (headers or {}).items():
            require("\r" not in key + value and "\n" not in key + value, "registry header is malformed")
            require(key.lower() not in {"host", "connection", "content-length"}, "registry header is reserved")
            request_headers[key] = value
        # Retry only transport failures of idempotent reads; registry writes
        # may already have succeeded when their response is lost.
        attempts = 3 if method in {"GET", "HEAD"} else 1
        for attempt in range(attempts):
            connection: http.client.HTTPSConnection | None = None
            try:
                connection = http.client.HTTPSConnection(REGISTRY_HOST, 443, context=self.context, timeout=30.0)
                connection.request(method, request_path, body=body, headers=request_headers)
                response = connection.getresponse()
                response_body = response.read(MAX_RESPONSE_BYTES + 1)
                require(len(response_body) <= MAX_RESPONSE_BYTES, "registry response is oversized")
                output: dict[str, str] = {}
                for key, value in response.getheaders():
                    lowered = key.lower()
                    require(lowered not in output, "registry response headers are ambiguous")
                    output[lowered] = value.strip()
                require(not 300 <= response.status < 400, "registry redirects are forbidden")
                return Response(response.status, output, response_body)
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


def validate_ca(encoded: str) -> bytes:
    require(encoded != "", "Harbor CA secret is missing")
    require(re.fullmatch(r"[A-Za-z0-9+/=]+", encoded) is not None and len(encoded) % 4 == 0, "Harbor CA secret is not strict base64")
    try:
        decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
        pem = decoded.decode("ascii")
        require(base64.b64encode(decoded).decode("ascii") == encoded, "Harbor CA secret is not canonical base64")
        require(decoded.count(b"-----BEGIN CERTIFICATE-----") == 1 and decoded.count(b"-----END CERTIFICATE-----") == 1, "Harbor CA must contain one public certificate")
        require(b"PRIVATE KEY" not in decoded, "Harbor CA must not contain a private key")
        ssl.PEM_cert_to_DER_cert(pem)
        ssl.create_default_context(cadata=pem)
    except (UnicodeDecodeError, binascii.Error, ValueError, ssl.SSLError):
        fail("Harbor CA is not a valid public certificate")
    return decoded


def token_for_image(transport: Transport, username: str, password: str, source_sha: str) -> str:
    manifest_path = f"/v2/{IMAGE_PATH}/manifests/{source_sha}"
    challenge = transport.request("HEAD", manifest_path, {"Accept": ", ".join(sorted(MANIFEST_MEDIA_TYPES))})
    require(challenge.status == 401, "Harbor registry did not issue an image authentication challenge")
    challenge_value = challenge.headers.get("www-authenticate", "")
    match = re.fullmatch(r'Bearer realm="([^"]+)",service="([^"]+)",scope="([^"]+)"', challenge_value)
    require(match is not None, "Harbor image authentication challenge is malformed")
    realm, service, scope = match.groups()
    require(realm == f"https://{REGISTRY_HOST}/service/token", "Harbor token realm is foreign")
    require(service == "harbor-registry", "Harbor token service is foreign")
    require(scope in {f"repository:{IMAGE_PATH}:pull", f"repository:{IMAGE_PATH}:pull,push", f"repository:{IMAGE_PATH}:push,pull"}, "Harbor token scope is foreign")
    encoded_scope = quote(f"repository:{IMAGE_PATH}:pull", safe="")
    token_path = f"/service/token?service=harbor-registry&scope={encoded_scope}"
    basic = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    response = transport.request("GET", token_path, {"Authorization": f"Basic {basic}", "Accept": "application/json"})
    require(response.status == 200, "Harbor image token request failed")
    try:
        document = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Harbor image token response is malformed")
    require(isinstance(document, dict), "Harbor image token response is malformed")
    token = document.get("token") or document.get("access_token")
    require(isinstance(token, str) and token and not re.search(r"[\x00\r\n]", token), "Harbor image token response is malformed")
    return token


def readback(transport: Transport, token: str, source_sha: str, expected_digest: str) -> tuple[bytes, str]:
    response = transport.request(
        "GET",
        f"/v2/{IMAGE_PATH}/manifests/{source_sha}",
        {"Authorization": f"Bearer {token}", "Accept": ", ".join(sorted(MANIFEST_MEDIA_TYPES))},
    )
    require(response.status == 200, "Harbor image manifest readback failed")
    media_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
    require(media_type in MANIFEST_MEDIA_TYPES, "Harbor image manifest media type changed")
    content_digest = exact_digest(response.headers.get("docker-content-digest"), "Harbor image digest header")
    body_digest = "sha256:" + sha256_bytes(response.body)
    require(content_digest == expected_digest and body_digest == expected_digest, "Harbor image manifest digest changed")
    try:
        manifest = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Harbor image manifest is malformed")
    require(isinstance(manifest, dict) and manifest.get("schemaVersion") == 2, "Harbor image manifest schema changed")
    require(isinstance(manifest.get("config"), dict), "Harbor image config descriptor is missing")
    require(isinstance(manifest.get("layers"), list), "Harbor image layer descriptors are missing")
    descriptors = [manifest["config"], *manifest["layers"]]
    for index, descriptor in enumerate(descriptors):
        require(isinstance(descriptor, dict), f"Harbor image descriptor {index} is malformed")
        exact_digest(descriptor.get("digest"), f"Harbor image descriptor {index} digest")
        require(type(descriptor.get("size")) is int and descriptor["size"] >= 0, f"Harbor image descriptor {index} size is malformed")
    return response.body, media_type


def main() -> int:
    source_sha = os.environ.get("CI_COMMIT_SHA", "")
    require(SOURCE_SHA_RE.fullmatch(source_sha) is not None, "source commit must be a lowercase full SHA")
    require(os.environ.get("CI_PIPELINE_EVENT") == "push", "a protected push event is required")
    require(os.environ.get("CI_COMMIT_BRANCH") == "main", "the protected main branch is required")
    require(os.environ.get("CI_COMMIT_REF") == "refs/heads/main", "the protected main ref is required")
    require(os.environ.get("CI_REPO") == SOURCE_REPOSITORY, "source repository is outside the custody boundary")
    require(os.environ.get("REGISTRY_REPOSITORY") == REGISTRY_REPOSITORY, "Harbor image repository is outside the custody boundary")
    username = os.environ.get("REGISTRY_PULL_USERNAME", "")
    password = os.environ.get("REGISTRY_PULL_PASSWORD", "")
    require(username != "" and password != "", "Harbor pull credentials are missing")
    artifact_root = artifact_directory()
    values = parse_env(read_private(artifact_root / "images.env", "image digest manifest"), source_sha)
    ca = validate_ca(os.environ.get("REGISTRY_CA_CERT_BASE64", ""))
    transport = Transport(ca)
    token = token_for_image(transport, username, password, source_sha)
    password = "\x00" * len(password)
    raw, media_type = readback(transport, token, source_sha, values["IMAGE_DIGEST"])
    document = {
        "apiVersion": "infisical.visiondynamics.ch/v1alpha1",
        "kind": "InfisicalImageManifestReadback",
        "version": 1,
        "state": "verified",
        "sourceRepository": SOURCE_REPOSITORY,
        "sourceSha": source_sha,
        "repository": REGISTRY_REPOSITORY,
        "tag": source_sha,
        "imageReference": values["IMAGE_REF"],
        "manifestDigest": values["IMAGE_DIGEST"],
        "manifestBytesSha256": sha256_bytes(raw),
        "contentDigestHeader": values["IMAGE_DIGEST"],
        "mediaType": media_type,
    }
    write_exclusive(artifact_root / "image-readback.json", (json.dumps(document, sort_keys=True) + "\n").encode("utf-8"), "image readback")
    print("Harbor image manifest read back at the immutable source tag")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"Harbor image readback failed closed: {error}", file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, TypeError, ssl.SSLError):
        print("Harbor image readback failed closed: external or malformed input was rejected", file=sys.stderr)
        raise SystemExit(1)
