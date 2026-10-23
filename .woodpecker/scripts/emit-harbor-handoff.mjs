import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const SOURCE_REPOSITORY = 'Visiondynamics-ag/infisical';
const REGISTRY_REPOSITORY = '10.43.0.50/infisical/infisical';
const SOURCE_SHA_RE = /^[0-9a-f]{40}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const MAX_REPORT_BYTES = 64 * 1024 * 1024;
const MAX_READBACK_BYTES = 64 * 1024;

function fail(message) {
  process.stderr.write(`Harbor handoff failed closed: ${message}\n`);
  process.exit(1);
}

function requireCondition(condition, message) {
  if (!condition) fail(message);
}

function assertNoSymlinkComponents(target, label) {
  let current = path.resolve(target);
  const root = path.parse(current).root;
  while (current !== root) {
    try {
      if (fs.lstatSync(current).isSymbolicLink()) fail(`${label} contains a symlink`);
    } catch (error) {
      if (error?.code !== 'ENOENT') fail(`${label} cannot be inspected safely`);
    }
    current = path.dirname(current);
  }
}

function ownerOnlyDirectory(directory) {
  assertNoSymlinkComponents(directory, 'CI artifact directory');
  let stat;
  try {
    stat = fs.lstatSync(directory);
  } catch {
    fail('CI artifact directory is missing');
  }
  requireCondition(stat.isDirectory(), 'CI artifact path is not a directory');
  requireCondition([0o700, 0o2770].includes(stat.mode & 0o7777), 'CI artifact directory has an unsupported mode');
  if (typeof process.getgid === 'function') requireCondition(stat.gid === process.getgid(), 'CI artifact directory does not have the job group');
  if (typeof process.getuid === 'function') requireCondition(stat.uid === process.getuid(), 'CI artifact directory is not owned by the job user');
}

function readOwnerOnly(file, label, maximum) {
  assertNoSymlinkComponents(file, label);
  let before;
  try {
    before = fs.lstatSync(file);
  } catch {
    fail(`${label} is missing`);
  }
  requireCondition(before.isFile(), `${label} is not a regular file`);
  requireCondition([0o600, 0o660].includes(before.mode & 0o7777), `${label} has an unsupported mode`);
  if (typeof process.getgid === 'function') requireCondition(before.gid === process.getgid(), `${label} does not have the job group`);
  requireCondition(before.nlink === 1, `${label} has unexpected hard links`);
  if (typeof process.getuid === 'function') requireCondition(before.uid === process.getuid(), `${label} is not owned by the job user`);
  requireCondition(before.size <= maximum, `${label} is oversized`);
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(fd);
    requireCondition(opened.ino === before.ino && opened.dev === before.dev && opened.uid === before.uid && opened.gid === before.gid && opened.mode === before.mode && opened.nlink === before.nlink, `${label} changed while opening`);
    const data = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    requireCondition(data.length <= maximum, `${label} is oversized`);
    requireCondition(after.ino === before.ino && after.dev === before.dev && after.size === before.size && after.mtimeMs === before.mtimeMs && after.uid === before.uid && after.gid === before.gid && after.mode === before.mode && after.nlink === before.nlink && after.ctimeMs === before.ctimeMs, `${label} changed while reading`);
    const final = fs.lstatSync(file);
    requireCondition(final.ino === before.ino && final.dev === before.dev && final.size === before.size && final.mtimeMs === before.mtimeMs && final.uid === before.uid && final.gid === before.gid && final.mode === before.mode && final.nlink === before.nlink && final.ctimeMs === before.ctimeMs, `${label} changed after reading`);
    return data;
  } catch (error) {
    if (error?.message?.includes('failed closed')) throw error;
    fail(`${label} could not be read safely`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function parseJson(raw, label) {
  try {
    const value = JSON.parse(raw.toString('utf8'));
    requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value), `${label} is not a JSON object`);
    return value;
  } catch (error) {
    if (error?.message?.includes('failed closed')) throw error;
    fail(`${label} is not valid JSON`);
  }
}

function digest(value, label) {
  requireCondition(typeof value === 'string' && DIGEST_RE.test(value), `${label} is malformed`);
  requireCondition(value !== `sha256:${'0'.repeat(64)}`, `${label} is zero`);
  return value;
}

function readManifest(artifactDirectory) {
  const file = path.join(artifactDirectory, 'images.env');
  const raw = readOwnerOnly(file, 'image digest manifest', 16 * 1024).toString('utf8');
  const values = new Map();
  for (const line of raw.split('\n')) {
    if (line === '') continue;
    const separator = line.indexOf('=');
    requireCondition(separator > 0 && !line.includes('\r'), 'image digest manifest contains malformed data');
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    requireCondition(!values.has(key), 'image digest manifest contains duplicate data');
    values.set(key, value);
  }
  const expected = ['IMAGE_DIGEST', 'IMAGE_REF', 'IMAGE_REPOSITORY', 'IMAGE_TAG', 'SOURCE_REPOSITORY', 'SOURCE_SHA'];
  requireCondition(values.size === expected.length && expected.every((key) => values.has(key)), 'image digest manifest schema changed');
  return Object.fromEntries(values);
}

function writeExclusive(file, bytes, label) {
  assertNoSymlinkComponents(file, label);
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fchmodSync(fd, 0o600);
    fs.fsyncSync(fd);
  } catch (error) {
    if (error?.code === 'EEXIST') fail(`${label} already exists`);
    if (error?.code === 'ELOOP') fail(`${label} is a symlink`);
    fail(`${label} could not be written safely`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

const sourceSha = process.env.CI_COMMIT_SHA ?? '';
requireCondition(SOURCE_SHA_RE.test(sourceSha), 'source commit must be a lowercase full SHA');
requireCondition(process.env.CI_REPO === SOURCE_REPOSITORY, 'source repository is outside the custody boundary');
requireCondition(process.env.CI_PIPELINE_EVENT === 'push', 'a protected push event is required');
requireCondition(process.env.CI_COMMIT_BRANCH === 'main', 'the protected main branch is required');
requireCondition(process.env.CI_COMMIT_REF === 'refs/heads/main', 'the protected main ref is required');
requireCondition(process.env.REGISTRY_REPOSITORY === REGISTRY_REPOSITORY, 'Harbor repository is outside the custody boundary');

const artifactDirectory = path.resolve(process.env.CI_ARTIFACTS_DIR ?? '.ci-artifacts');
ownerOnlyDirectory(artifactDirectory);
const values = readManifest(artifactDirectory);
requireCondition(values.SOURCE_REPOSITORY === SOURCE_REPOSITORY, 'image source repository binding changed');
requireCondition(values.SOURCE_SHA === sourceSha && values.IMAGE_TAG === sourceSha, 'image source tag binding changed');
requireCondition(values.IMAGE_REPOSITORY === REGISTRY_REPOSITORY, 'image repository binding changed');
const manifestDigest = digest(values.IMAGE_DIGEST, 'image manifest digest');
requireCondition(values.IMAGE_REF === `${REGISTRY_REPOSITORY}:${sourceSha}@${manifestDigest}`, 'immutable image reference changed');

const reportPath = path.join(artifactDirectory, 'trivy-image.json');
const reportBytes = readOwnerOnly(reportPath, 'Trivy report', MAX_REPORT_BYTES);
const report = parseJson(reportBytes, 'Trivy report');
requireCondition(report.SchemaVersion === 2 && report.ArtifactType === 'container_image', 'Trivy report schema changed');
requireCondition(Array.isArray(report.Results), 'Trivy report does not contain a Results array');
requireCondition(report.ArtifactName === values.IMAGE_REF, 'Trivy report image binding changed');
requireCondition(report.Metadata !== null && typeof report.Metadata === 'object' && !Array.isArray(report.Metadata), 'Trivy report metadata is malformed');
requireCondition(Array.isArray(report.Metadata.RepoDigests) && report.Metadata.RepoDigests.length === 1 && report.Metadata.RepoDigests[0] === `${REGISTRY_REPOSITORY}@${manifestDigest}`, 'Trivy report digest binding changed');
for (const result of report.Results) {
  requireCondition(result !== null && typeof result === 'object', 'Trivy result is malformed');
  const vulnerabilities = result.Vulnerabilities ?? [];
  requireCondition(Array.isArray(vulnerabilities), 'Trivy vulnerabilities are malformed');
  for (const vulnerability of vulnerabilities) {
    const severity = vulnerability?.Severity;
    requireCondition(severity !== 'HIGH' && severity !== 'CRITICAL', 'Trivy report contains an unsafe finding');
  }
  requireCondition(Array.isArray(result.Secrets) && result.Secrets.length === 0, 'Trivy report contains secret findings or missing secret inventory');
}

const readbackPath = path.join(artifactDirectory, 'image-readback.json');
const readbackBytes = readOwnerOnly(readbackPath, 'Harbor image readback', MAX_READBACK_BYTES);
const readback = parseJson(readbackBytes, 'Harbor image readback');
requireCondition(readback.apiVersion === 'infisical.visiondynamics.ch/v1alpha1', 'Harbor image readback API version changed');
requireCondition(readback.kind === 'InfisicalImageManifestReadback' && readback.version === 1 && readback.state === 'verified', 'Harbor image readback identity changed');
requireCondition(readback.sourceRepository === SOURCE_REPOSITORY && readback.sourceSha === sourceSha, 'Harbor image readback source binding changed');
requireCondition(readback.repository === REGISTRY_REPOSITORY && readback.tag === sourceSha, 'Harbor image readback repository binding changed');
requireCondition(readback.imageReference === values.IMAGE_REF && readback.manifestDigest === manifestDigest, 'Harbor image readback image binding changed');
requireCondition(typeof readback.manifestBytesSha256 === 'string' && /^[0-9a-f]{64}$/.test(readback.manifestBytesSha256), 'Harbor image readback byte digest is malformed');
requireCondition(readback.manifestBytesSha256 === manifestDigest.slice('sha256:'.length), 'Harbor image readback byte digest does not match the manifest digest');
requireCondition(readback.contentDigestHeader === manifestDigest, 'Harbor image readback content digest changed');

const verifiedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
const handoff = {
  apiVersion: 'infisical.visiondynamics.ch/v1alpha1',
  kind: 'InfisicalHarborImageHandoff',
  version: 1,
  state: 'verified',
  sourceRepository: SOURCE_REPOSITORY,
  sourceSha,
  repository: REGISTRY_REPOSITORY,
  imageReference: values.IMAGE_REF,
  manifestDigest,
  imageReadback: {
    path: '.ci-artifacts/image-readback.json',
    sha256: crypto.createHash('sha256').update(readbackBytes).digest('hex'),
  },
  report: {
    path: '.ci-artifacts/trivy-image.json',
    sha256: crypto.createHash('sha256').update(reportBytes).digest('hex'),
  },
  scanner: {
    image: 'aquasec/trivy@sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c',
    scanners: ['vuln', 'secret'],
    ignoreUnfixed: false,
    severities: ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
  },
  verification: {
    vulnerabilityPolicyPassed: true,
    sourceProvenance: false,
    remoteManifestReadback: true,
    secretScanPerformed: true,
    secretValuesPrinted: false,
    gitopsMutation: false,
    dnsMutation: false,
    deploymentMutation: false,
  },
  verifiedAt,
};
const handoffBytes = Buffer.from(`${JSON.stringify(handoff)}\n`, 'utf8');
writeExclusive(path.join(artifactDirectory, 'infisical-harbor-image-handoff.json'), handoffBytes, 'Harbor image handoff');
process.stdout.write('verified Harbor image handoff emitted\n');
