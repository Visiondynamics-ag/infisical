import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
assert.equal(process.platform, "linux", "Qualification is Linux-only");
assert.ok(["x64", "arm64"].includes(process.arch), "Unsupported qualification architecture");
const pkg = require("@infisical/quic/package.json");
assert.equal(pkg.version, "1.0.8");
const nativePkg = require(`@infisical/quic-linux-${process.arch}/package.json`);
assert.equal(nativePkg.version, "1.0.8");
assert.deepEqual(nativePkg.os, ["linux"]);
assert.deepEqual(nativePkg.cpu, [process.arch]);
const quic = require("@infisical/quic");
assert.equal(typeof quic.QUICClient, "function");
assert.equal(typeof quic.QUICServer, "function");
assert.equal(typeof quic.QUICSocket, "function");
assert.ok(quic.native);
console.log(
  JSON.stringify({
    state: "REAL_NATIVE_LOAD_PASS",
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    quic: pkg.version,
    networkConnections: 0
  })
);
