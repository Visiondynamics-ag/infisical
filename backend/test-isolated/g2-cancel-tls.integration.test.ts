import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { createSecureContext, TLSSocket } from "node:tls";
import pg from "pg";
import { afterAll, beforeAll, expect, test } from "vitest";
import { cancelOwnedQuery, type CancelDriver } from "@app/services/g2-reconciliation/g2-snapshot-cancel";

// Only the existing isolated network-none fixture. Certificates/keys stay in
// its /tmp tmpfs. Never use inherited config, credentials, or endpoints.
if (process.platform !== "linux" || process.arch !== "x64" || process.version !== "v22.22.0" ||
    !existsSync("/g2-fixture-socket/.g2-test-only") ||
    !/^g2-fixture-[0-9a-f]{32}$/.test(readFileSync("/g2-fixture-socket/.g2-test-only", "utf8").trim()))
  throw new Error("FIXTURE_REQUIRED");
let directory: string;
const file = (name: string) => `${directory}/${name}`;
const openssl = (...args: string[]) => {
  const result = spawnSync("/usr/bin/openssl", args, {
    cwd: directory, env: { PATH: "/usr/bin:/bin", HOME: directory, OPENSSL_CONF: file("empty.cnf") },
    stdio: "ignore", timeout: 10000
  });
  if (result.error || result.status !== 0) throw new Error("SYNTHETIC_CERT_GENERATION_REFUSED");
  for (const entry of readdirSync(directory, { withFileTypes: true }))
    if (entry.isFile()) chmodSync(file(entry.name), 0o600);
};
beforeAll(() => {
  if (!existsSync("/usr/bin/openssl")) throw new Error("FIXED_OPENSSL_UNAVAILABLE");
  directory = mkdtempSync("/tmp/g2-tls-"); chmodSync(directory, 0o700);
  const mask = process.umask(0o077);
  try {
    writeFileSync(file("empty.cnf"), "", { mode: 0o600 });
    for (const ca of ["trusted", "other"])
      openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", `/CN=g2-synthetic-${ca}`,
        "-keyout", `${ca}.key`, "-out", `${ca}.crt`, "-addext", "basicConstraints=critical,CA:TRUE");
    for (const [name, ca, san] of [["valid", "trusted", "localhost"], ["wrong", "trusted", "wrong.invalid"], ["untrusted", "other", "localhost"]]) {
      openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", `/CN=${san}`, "-keyout", `${name}.key`, "-out", `${name}.csr`);
      writeFileSync(file(`${name}.ext`), `subjectAltName=DNS:${san}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n`, { mode: 0o600 });
      openssl("x509", "-req", "-in", `${name}.csr`, "-CA", `${ca}.crt`, "-CAkey", `${ca}.key`, "-set_serial", "2",
        "-days", "1", "-extfile", `${name}.ext`, "-out", `${name}.crt`);
    }
  } finally { process.umask(mask); }
});
afterAll(() => {
  if (directory) { rmSync(directory, { recursive: true, force: true }); expect(existsSync(directory)).toBe(false); }
});
const sslRequest = Buffer.from([0, 0, 0, 8, 4, 210, 22, 47]);
const int = (value: number) => { const result = Buffer.alloc(4); result.writeInt32BE(value); return result; };
const frame = (type: string, payload: Buffer) => Buffer.concat([Buffer.from(type), int(payload.length + 4), payload]);
type Scenario = "valid" | "wrong" | "untrusted" | "refused" | "stalled";

async function exercise(scenario: Scenario, numeric: boolean) {
  const sockets = new Set<Socket>();
  const events: string[] = [];
  let connections = 0, cancels = 0, cancelApplicationBytes = 0, rawPostSslBytes = 0, protocolInvalid = false;
  let auxiliaryClosed!: () => void;
  const auxiliaryClose = new Promise<void>((resolve) => { auxiliaryClosed = resolve; });
  let querySeen!: () => void;
  const queryReady = new Promise<void>((resolve) => { querySeen = resolve; });
  const contexts = Object.fromEntries(["valid", "wrong", "untrusted"].map((name) => [name,
    createSecureContext({ key: readFileSync(file(`${name}.key`)), cert: readFileSync(file(`${name}.crt`)) })]));
  const server = createServer((socket) => {
    sockets.add(socket); socket.on("close", () => sockets.delete(socket)); socket.on("error", () => {});
    socket.setTimeout(3000, () => socket.destroy());
    const ordinal = ++connections;
    if (ordinal === 2) socket.once("close", auxiliaryClosed);
    if (ordinal > 2) { protocolInvalid = true; socket.destroy(); return; }
    let request = Buffer.alloc(0);
    const negotiate = (chunk: Buffer) => {
      request = Buffer.concat([request, chunk]);
      if (request.length > 8) { protocolInvalid = true; socket.destroy(); return; }
      if (request.length < 8) return;
      socket.removeListener("data", negotiate);
      if (!request.equals(sslRequest)) { protocolInvalid = true; socket.destroy(); return; }
      if (ordinal === 2 && (scenario === "refused" || scenario === "stalled")) {
        // Observe raw bytes until closure: a same-socket plaintext fallback
        // must fail, even though no TLS application-data listener exists.
        socket.on("data", (extra: Buffer) => { rawPostSslBytes += extra.length; });
        if (scenario === "refused") socket.write("N");
        return;
      }
      socket.write("S");
      const secure = new TLSSocket(socket, { isServer: true, secureContext: contexts[ordinal === 1 ? "valid" : scenario] });
      sockets.add(secure); secure.on("close", () => sockets.delete(secure)); secure.on("error", () => {});
      let bytes = Buffer.alloc(0), started = false;
      secure.on("data", (chunk: Buffer) => {
        bytes = Buffer.concat([bytes, chunk]);
        if (ordinal === 2) {
          cancelApplicationBytes += chunk.length;
          // Exactly one CancelRequest, never Startup/auth/password/SQL. All
          // synthetic capability bytes remain in RAM, with boolean assertions.
          if (bytes.length > 16) { protocolInvalid = true; secure.destroy(); return; }
          if (bytes.length === 16) {
            const expected = Buffer.concat([int(16), int(80877102), int(1234), int(5678)]);
            if (!bytes.equals(expected) || cancels !== 0) protocolInvalid = true;
            else { cancels++; events.push("server-cancel"); }
            secure.end();
          }
          return;
        }
        if (bytes.length > 4096) { protocolInvalid = true; secure.destroy(); return; }
        if (!started) {
          if (bytes.length < 4) return;
          const length = bytes.readInt32BE(0);
          if (length < 8 || length > 1024) { protocolInvalid = true; secure.destroy(); return; }
          if (bytes.length < length) return;
          if (bytes.readInt32BE(4) !== 196608) { protocolInvalid = true; secure.destroy(); return; }
          bytes = bytes.subarray(length); started = true;
          secure.write(Buffer.concat([frame("R", int(0)), frame("K", Buffer.concat([int(1234), int(5678)])), frame("Z", Buffer.from("I"))]));
        }
        if (bytes.length >= 5) {
          const length = bytes.readInt32BE(1);
          if (length < 4 || length > 128 || bytes[0] !== 81) { protocolInvalid = true; secure.destroy(); return; }
          if (bytes.length >= length + 1) {
            if (bytes.length !== length + 1 || bytes.subarray(5).toString() !== "SELECT 1\0") protocolInvalid = true;
            bytes = Buffer.alloc(0); querySeen(); // Hold the synthetic query response.
          }
        }
      });
    };
    socket.on("data", negotiate);
  });
  let client: pg.Client | undefined;
  let queryTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("FIXTURE_ADDRESS");
    client = new pg.Client({ host: numeric ? "127.0.0.1" : "localhost", port: address.port,
      user: "g2_synthetic", database: "g2_synthetic", password: "synthetic-unused", connectionTimeoutMillis: 2000,
      ssl: { ca: readFileSync(file("trusted.crt")), rejectUnauthorized: true, servername: numeric ? "localhost" : "conflicting.invalid" } });
    client.on("error", () => {});
    await client.connect();
    const originalAuthorized = (client.connection.stream as TLSSocket).authorized;
    const pendingQuery = client.query("SELECT 1").catch(() => undefined);
    await Promise.race([queryReady, new Promise<never>((_, reject) => { queryTimer = setTimeout(() => reject(new Error("FIXTURE_QUERY_TIMEOUT")), 2500); })]);
    clearTimeout(queryTimer);
    class ObservedClient extends pg.Client {
      constructor(options: ConstructorParameters<typeof pg.Client>[0]) {
        super(options);
        // Per-instance observers only: actual pg/TLS/serialization untouched.
        if (options?.host !== "127.0.0.1") throw new Error("CANCEL_PEER_NOT_PINNED");
        this.connection.on("sslconnect", () => {
          this.connection.stream.once("secureConnect", () => {
            if ((this.connection.stream as TLSSocket).authorized !== true) protocolInvalid = true;
            events.push("authorized-secure-connect");
          });
        });
      }
    }
    const start = performance.now();
    await cancelOwnedQuery({ Client: ObservedClient } as unknown as CancelDriver, client);
    const elapsed = performance.now() - start;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("AUXILIARY_CLOSE_TIMEOUT")), 1000);
      void auxiliaryClose.then(() => { clearTimeout(timer); resolve(); });
    });
    await client.end(); await pendingQuery;
    expect(originalAuthorized).toBe(true);
    expect(protocolInvalid).toBe(false);
    expect(connections).toBe(2);
    expect(elapsed).toBeLessThan(1500); // Scheduling allowance; production cap remains 500ms.
    expect(cancels).toBe(scenario === "valid" ? 1 : 0);
    expect(cancelApplicationBytes).toBe(scenario === "valid" ? 16 : 0);
    expect(rawPostSslBytes).toBe(0);
    expect(events).toEqual(scenario === "valid" ? ["authorized-secure-connect", "server-cancel"] : []);
  } finally {
    clearTimeout(queryTimer);
    client?.connection.stream.destroy();
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
test("actual pg DNS host overrides conflicting configured TLS name before cancel", () => exercise("valid", false));
test("actual pg numeric host preserves explicit TLS name before cancel", () => exercise("valid", true));
for (const scenario of ["wrong", "untrusted", "refused", "stalled"] as const)
  test(`actual pg cancel ${scenario} sends no capability or fallback`, () => exercise(scenario, false));
