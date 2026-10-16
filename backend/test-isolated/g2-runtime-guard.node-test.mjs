import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const config = JSON.parse(readFileSync(new URL("./g2-test-runtime.json", import.meta.url), "utf8"));
test("qualification runtime pin is exact", () => {
  assert.equal(config.node, "v22.22.0");
  assert.equal(config.platform, "linux");
  assert.equal(config.arch, "x64");
  assert.equal(config.image, "node@sha256:b5977249434bca5b2efaf4eee25317ad8aecfa7ccf5168e3bcd5f179ba345e1c");
});
for (const args of [["toString"], ["unknown"], ["http", "extra"], []])
  test("closed runner refuses args " + JSON.stringify(args), () => {
    const result = spawnSync(process.execPath, ["test-isolated/run-g2-qualification.mjs", ...args], {
      encoding: "utf8",
      env: { PATH: process.env.PATH },
      timeout: 5000
    });
    assert.equal(result.status, 3);
    assert.match(result.stderr, /G2_TEST_(MODE|RUNTIME)_REFUSED/);
    assert.equal(result.stdout, "");
  });
