import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
const text = readFileSync(new URL("../package-lock.json", import.meta.url), "utf8");
const manifest = readFileSync(new URL("../package.json", import.meta.url), "utf8");
const sha = (s) => createHash("sha256").update(s).digest("hex");
const upstream = "d58fb27f0b5ef3e52fa6c6d3b87f6d741e2fc62b81cba96b05e403d70b76074a";
const missing = '        "@infisical/quic-linux-arm": "1.0.8",\n';
const next = '        "@infisical/quic-linux-arm64": "1.0.8",\n';
function exactCorrection(candidate) {
  assert.equal(candidate.includes(missing), false);
  assert.equal(candidate.split(next).length, 2);
  // Reinsert the single removed edge; every other byte must match the pinned upstream lock.
  assert.equal(sha(candidate.replace(next, missing + next)), upstream);
}
test("only the unresolved optional linux-arm edge differs from the pinned upstream lock", () => exactCorrection(text));
test("direct dependency declaration and every other package manifest byte are unchanged", () =>
  assert.equal(sha(manifest), "5096bba2c300022cbea0b9e141beba3fc80dfe41b57344d56154cd701dedbb43"));
test("all 2260 package records and Linux x64/arm64 native dependencies stay pinned", () => {
  const p = JSON.parse(text).packages;
  assert.equal(Object.keys(p).length, 2260);
  assert.equal(p["node_modules/@infisical/quic"].version, "1.0.8");
  for (const arch of ["x64", "arm64"]) {
    const n = "@infisical/quic-linux-" + arch;
    assert.equal(p["node_modules/@infisical/quic"].optionalDependencies[n], "1.0.8");
    assert.equal(p["node_modules/" + n].optional, true);
    assert.deepEqual(p["node_modules/" + n].cpu, [arch]);
    assert.deepEqual(p["node_modules/" + n].os, ["linux"]);
    assert.match(p["node_modules/" + n].integrity, /^sha512-/);
  }
});
for (const [name, transform] of [
  ["quic downgrade", (s) => s.replace('"version": "1.0.8"', '"version": "1.0.7"')],
  ["different platform omission", (s) => s.replace(next, "")],
  ["integrity mutation", (s) => s.replace("sha512-ozgGkVdLP", "sha512-zzgGkVdLP")],
  ["unrelated mutation", (s) => s.replace('"lockfileVersion": 3', '"lockfileVersion": 2')],
  ["edge silently restored", (s) => s.replace(next, missing + next)]
])
  test("refuses " + name, () => assert.throws(() => exactCorrection(transform(text))));
