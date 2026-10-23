import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sha = '0123456789abcdef0123456789abcdef01234567';
const digest = `sha256:${'a'.repeat(64)}`;
const repository = '10.43.0.50/infisical/infisical';
const image = `${repository}:${sha}@${digest}`;
const artifact = fs.mkdtempSync(path.join(os.tmpdir(), 'infisical-publisher-'));
fs.chmodSync(artifact, 0o700);
const environment = {
  ...process.env,
  CI_REPO: 'Visiondynamics-ag/infisical',
  CI_PIPELINE_EVENT: 'push', CI_COMMIT_BRANCH: 'main', CI_COMMIT_REF: 'refs/heads/main',
  CI_COMMIT_SHA: sha, REGISTRY_REPOSITORY: repository, CI_ARTIFACTS_DIR: artifact,
};
const run = (script, overrides = {}) => spawnSync(process.execPath,
  [path.join(root, '.woodpecker/scripts', script)],
  {cwd: root, env: {...environment, ...overrides}, encoding: 'utf8'});
const write = (name, value) => fs.writeFileSync(path.join(artifact, name), JSON.stringify(value), {mode: 0o600});
try {
  write('build-metadata.json', {'containerimage.digest': digest});
  for (const wrong of [
    {CI_PIPELINE_EVENT: 'pull_request'}, {CI_COMMIT_BRANCH: 'dev'},
    {CI_COMMIT_REF: 'refs/tags/v1'}, {CI_REPO: 'foreign/infisical'},
    {REGISTRY_REPOSITORY: '10.43.0.50/visioncr/infisical'}, {CI_COMMIT_SHA: 'bad'},
  ]) assert.notEqual(run('record-image.mjs', wrong).status, 0);
  assert.equal(fs.existsSync(path.join(artifact, 'images.env')), false);
  let result = run('record-image.mjs');
  assert.equal(result.status, 0, result.stderr);
  assert.ok(fs.readFileSync(path.join(artifact, 'images.env'), 'utf8').includes(`IMAGE_REF=${image}`));
  assert.notEqual(run('record-image.mjs').status, 0, 'metadata must not overwrite an existing result');

  const report = {SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: image,
    Metadata: {RepoDigests: [`${repository}@${digest}`]}, Results: []};
  const readback = {apiVersion: 'infisical.visiondynamics.ch/v1alpha1', kind: 'InfisicalImageManifestReadback',
    version: 1, state: 'verified', sourceRepository: environment.CI_REPO, sourceSha: sha,
    repository, tag: sha, imageReference: image, manifestDigest: digest,
    manifestBytesSha256: digest.slice(7), contentDigestHeader: digest};
  write('image-readback.json', readback);
  write('trivy-image.json', {...report, ArtifactName: 'foreign/image'});
  assert.notEqual(run('emit-harbor-handoff.mjs').status, 0, 'a scan for another image must fail');
  write('trivy-image.json', {...report, Results: [{Vulnerabilities: [{Severity: 'CRITICAL'}]}]});
  assert.notEqual(run('emit-harbor-handoff.mjs').status, 0, 'unsafe findings must fail');
  write('trivy-image.json', {...report, Results: [{Vulnerabilities: [{Severity: 'HIGH', FixedVersion: ''}], Secrets: []}]});
  assert.notEqual(run('emit-harbor-handoff.mjs').status, 0, 'unfixed High findings must fail');
  write('trivy-image.json', {...report, Results: [{Vulnerabilities: [], Secrets: [{RuleID: 'synthetic', Severity: 'LOW'}]}]});
  assert.notEqual(run('emit-harbor-handoff.mjs').status, 0, 'secret metadata must fail regardless of severity');
  write('trivy-image.json', {...report, Results: [{Vulnerabilities: []}]});
  assert.notEqual(run('emit-harbor-handoff.mjs').status, 0, 'missing secret inventory must fail');
  write('trivy-image.json', {...report, Metadata: {RepoDigests: ['foreign/image@' + digest]}});
  assert.notEqual(run('emit-harbor-handoff.mjs').status, 0, 'changed report digest must fail');
  write('trivy-image.json', report);
  result = run('emit-harbor-handoff.mjs');
  assert.equal(result.status, 0, result.stderr);
  const handoff = JSON.parse(fs.readFileSync(path.join(artifact, 'infisical-harbor-image-handoff.json')));
  assert.equal(handoff.imageReference, image);
  assert.equal(handoff.report.sha256, crypto.createHash('sha256').update(fs.readFileSync(path.join(artifact, 'trivy-image.json'))).digest('hex'));
  assert.equal(handoff.verification.sourceProvenance, false);
  assert.equal(handoff.verification.remoteManifestReadback, true);
  assert.equal(handoff.verification.secretScanPerformed, true);
  assert.notEqual(run('emit-harbor-handoff.mjs').status, 0);

  const fixture = path.join(artifact, 'checkout');
  const bin = path.join(artifact, 'bin');
  fs.mkdirSync(path.join(fixture, '.woodpecker/scripts'), {recursive: true});
  fs.mkdirSync(bin);
  for (const name of ['rootless-build.sh', 'validate-source.sh', 'validate-push.sh']) {
    fs.copyFileSync(path.join(root, '.woodpecker/scripts', name), path.join(fixture, '.woodpecker/scripts', name));
  }
  for (const name of ['Dockerfile.standalone-infisical', '.dockerignore', 'backend/package.json', 'frontend/package.json', 'docker/lmdb/README', 'standalone-entrypoint.sh']) {
    const file = path.join(fixture, name);
    fs.mkdirSync(path.dirname(file), {recursive: true});
    fs.writeFileSync(file, 'synthetic build input\n');
  }
  const git = (...args) => {
    const result = spawnSync('git', args, {cwd: fixture, encoding: 'utf8', env: {...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1'}});
    assert.equal(result.status, 0, result.stderr || result.error?.message || "git fixture failed");
    return result.stdout.trim();
  };
  git('init', '-q');
  git('add', '.');
  git('-c', 'user.name=Offline test', '-c', 'user.email=offline@example.invalid', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'synthetic fixture');
  const fixtureSha = git('rev-parse', 'HEAD');
  fs.writeFileSync(path.join(fixture, 'frontend/untracked.fixture'), 'synthetic untracked content');
  const stub = (name, code) => fs.writeFileSync(path.join(bin, name), `#!${process.execPath}\n${code}\n`, {mode: 0o700});
  // Only this offline fixture simulates Linux admission; the builder is never executed.
  stub('id', "process.stdout.write('1000\\n');");
  stub('grep', `if (!process.argv.includes('/proc/self/status')) process.exit(2); if (process.argv.includes('-Ec')) process.stdout.write('3\\n');`);
  stub('awk', "if (!process.argv.includes('/proc/self/mountinfo')) process.exit(2); process.stdout.write('/\\n');");
  stub('buildctl-daemonless.sh', `
    const fs = require('node:fs'); const path = require('node:path');
    const args = process.argv.slice(2);
    const context = args.find(x => x.startsWith('context=')).slice(8);
    if (fs.existsSync(path.join(context, 'frontend/untracked.fixture')) || fs.existsSync(path.join(context, '.woodpecker')) || fs.existsSync(path.join(context, '.ci-artifacts'))) process.exit(2);
    if (JSON.stringify(JSON.parse(fs.readFileSync(path.join(process.env.DOCKER_CONFIG, 'config.json')))) !== '{"auths":{}}') process.exit(3);
    if (args.some(x => x.includes('push=true') || x.includes('registry-auth'))) process.exit(4);
    if (process.env.REGISTRY_PASSWORD || process.env.REGISTRY_PULL_PASSWORD) process.exit(5);
    const output = args[args.indexOf('--output') + 1];
    if (!output.startsWith('type=oci,') || !output.includes('dest=.ci-artifacts/image.oci.tar')) process.exit(6);
    fs.writeFileSync('.ci-artifacts/build-metadata.json', '{}');
    fs.writeFileSync('.ci-artifacts/image.oci.tar', 'synthetic archive, not an image');
    fs.writeFileSync(process.env.FIXTURE_ARGS, JSON.stringify(args));
    fs.rmdirSync(process.env.BUILDKITD_FLAGS.split(' ')[1]);
  `);
  const sourceEnv = {
    PATH: `${bin}:${process.env.PATH}`, TMPDIR: os.tmpdir(), FIXTURE_ARGS: path.join(artifact, 'build-args.json'),
    CI_REPO: 'Visiondynamics-ag/infisical', CI_COMMIT_SHA: fixtureSha,
    CI_PIPELINE_EVENT: 'pull_request', CI_COMMIT_BRANCH: 'dev', CI_COMMIT_REF: 'refs/pull/1/head',
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
  };
  const build = (args = [], overrides = {}) => spawnSync('sh', ['.woodpecker/scripts/rootless-build.sh', ...args],
    {cwd: fixture, encoding: 'utf8', env: {...sourceEnv, ...overrides}});
  assert.notEqual(build(['publish']).status, 0, 'PR cannot enter publication');
  assert.notEqual(build([], {REGISTRY_PASSWORD: 'synthetic-custody'}).status, 0, 'qualification rejects custody');
  assert.notEqual(build([], {CI_REPO: 'foreign/infisical'}).status, 0, 'qualification requires exact repository');
  assert.notEqual(build([], {CI_COMMIT_SHA: sha}).status, 0, 'qualification requires exact checkout SHA');
  assert.equal(fs.existsSync(sourceEnv.FIXTURE_ARGS), false, 'rejected inputs must not reach the fake builder');
  const qualified = build();
  assert.equal(qualified.status, 0, qualified.stderr);
  const buildArgs = JSON.parse(fs.readFileSync(sourceEnv.FIXTURE_ARGS));
  assert.ok(buildArgs.includes('platform=linux/amd64'));
  assert.ok(buildArgs.includes('build-arg:FRONTEND_BUILD_HEAP_MIB=4096'));
  assert.ok(buildArgs.includes(`build-arg:INFISICAL_PLATFORM_VERSION=v0.167.1-vd.${fixtureSha.slice(0, 8)}`));
  assert.notEqual(build().status, 0, 'qualification must not overwrite an archive');

  console.log('Infisical publisher binding and digest/scan handoff contracts passed');
} finally {
  fs.rmSync(artifact, {recursive: true, force: true});
}
