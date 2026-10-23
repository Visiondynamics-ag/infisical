import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const SOURCE_REPOSITORY = 'Visiondynamics-ag/infisical';
const REGISTRY_REPOSITORY = '10.43.0.50/infisical/infisical';
const SOURCE_SHA_RE = /^[0-9a-f]{40}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const MAX_METADATA_BYTES = 128 * 1024;

function fail(message) {
  process.stderr.write(`image metadata failed closed: ${message}\n`);
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
  try {
    const stat = fs.lstatSync(directory);
    requireCondition(stat.isDirectory(), 'CI artifact path is not a directory');
    requireCondition([0o700, 0o2770].includes(stat.mode & 0o7777), 'CI artifact directory has an unsupported mode');
    if (typeof process.getgid === 'function') requireCondition(stat.gid === process.getgid(), 'CI artifact directory does not have the job group');
    if (typeof process.getuid === 'function') {
      requireCondition(stat.uid === process.getuid(), 'CI artifact directory is not owned by the job user');
    }
  } catch (error) {
    if (error?.code === 'ENOENT') fail('CI artifact directory is missing');
    throw error;
  }
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
  if (typeof process.getuid === 'function') {
    requireCondition(before.uid === process.getuid(), `${label} is not owned by the job user`);
  }
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
    if (error?.code === 'ELOOP') fail(`${label} is a symlink`);
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
const metadataPath = path.join(artifactDirectory, 'build-metadata.json');
const metadata = parseJson(readOwnerOnly(metadataPath, 'BuildKit metadata', MAX_METADATA_BYTES), 'BuildKit metadata');
const manifestDigest = digest(metadata['containerimage.digest'], 'BuildKit manifest digest');
const imageReference = `${REGISTRY_REPOSITORY}:${sourceSha}@${manifestDigest}`;
const imageDocument = {
  schemaVersion: 1,
  sourceRepository: SOURCE_REPOSITORY,
  sourceSha,
  repository: REGISTRY_REPOSITORY,
  tag: sourceSha,
  manifestDigest,
  imageReference,
};
const envBytes = Buffer.from([
  `SOURCE_REPOSITORY=${SOURCE_REPOSITORY}`,
  `SOURCE_SHA=${sourceSha}`,
  `IMAGE_REPOSITORY=${REGISTRY_REPOSITORY}`,
  `IMAGE_TAG=${sourceSha}`,
  `IMAGE_DIGEST=${manifestDigest}`,
  `IMAGE_REF=${imageReference}`,
  '',
].join('\n'), 'utf8');
const documentBytes = Buffer.from(`${JSON.stringify(imageDocument)}\n`, 'utf8');
writeExclusive(path.join(artifactDirectory, 'images.env'), envBytes, 'image digest manifest');
try {
  writeExclusive(path.join(artifactDirectory, 'image-digest.json'), documentBytes, 'image digest document');
} catch (error) {
  try { fs.unlinkSync(path.join(artifactDirectory, 'images.env')); } catch {}
  throw error;
}

// The digest is intentionally the only build value printed.  Credentials and
// raw BuildKit metadata remain in the owner-only artifact directory.
process.stdout.write('immutable commit-SHA image digest captured\n');
