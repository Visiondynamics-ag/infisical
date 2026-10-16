import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const runtime = JSON.parse(readFileSync(new URL("./g2-test-runtime.json", import.meta.url), "utf8"));
if (process.version !== runtime.node || process.platform !== runtime.platform || process.arch !== runtime.arch) {
  console.error("G2_TEST_RUNTIME_REFUSED: use the pinned Linux x64 Node 22.22.0 fixture image");
  process.exit(3);
}
const stages = {
  contracts: [
    "--test",
    "test-isolated/g2-snapshot-contract.node-test.mjs",
    "test-isolated/g2-snapshot-mfa.node-test.mjs",
    "test-isolated/quic-lock-policy.node-test.mjs",
    "test-isolated/g2-runtime-guard.node-test.mjs"
  ],
  unit: [
    "node_modules/vitest/vitest.mjs",
    "run",
    "-c",
    "vitest.unit.config.mts",
    "src/ee/services/permission/permission-snapshot.test.ts",
    "src/services/g2-reconciliation/g2-snapshot-dal.test.ts",
    "src/server/plugins/auth/verify-auth.test.ts",
    "src/server/plugins/auth/inject-identity.test.ts",
    "--maxWorkers=1",
    "--no-file-parallelism"
  ],
  build: ["node_modules/tsup/dist/cli-default.js", "--sourcemap"],
  types: ["--max-old-space-size=8192", "node_modules/typescript/bin/tsc", "--noEmit"],
  http: ["node_modules/vitest/vitest.mjs", "run", "-c", "vitest.g2-http.config.mts"]
};
const mode = process.argv[2];
if (process.argv.length !== 3 || !(Object.hasOwn(stages, mode) || mode === "aggregate")) {
  console.error("G2_TEST_MODE_REFUSED");
  process.exit(3);
}
for (const stage of mode === "aggregate" ? ["contracts", "unit", "build", "types", "http"] : [mode]) {
  console.log(JSON.stringify({ stage, node: process.version, platform: process.platform, arch: process.arch }));
  const result = spawnSync(process.execPath, stages[stage], {
    stdio: "inherit",
    env: process.env,
    timeout: stage === "http" ? 300000 : 600000
  });
  if (result.error || result.status !== 0) {
    console.error("G2_TEST_STAGE_FAILED: " + stage);
    process.exit(result.status || 1);
  }
}
