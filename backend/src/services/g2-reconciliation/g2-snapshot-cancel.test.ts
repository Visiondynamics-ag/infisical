import { EventEmitter } from "node:events";
import { afterEach, expect, test, vi } from "vitest";

import { cancelOwnedQuery, type CancelDriver, type OwnedPgConnection } from "./g2-snapshot-cancel";

const fixture = (ssl: unknown = false) => {
  const stream = Object.assign(new EventEmitter(), { destroy: vi.fn() });
  const transport = Object.assign(new EventEmitter(), {
    stream, connect: vi.fn(), requestSsl: vi.fn(), cancel: vi.fn()
  });
  const config = vi.fn();
  class Client { connection = transport; constructor(c: unknown) { config(c); } }
  const driver: CancelDriver = { Client };
  const owned: OwnedPgConnection = { activeQuery: {}, processID: 123, secretKey: 987, host: ssl ? "fixture.invalid" : "/g2-fixture-socket", port: 5432, ssl, connection: { stream: { destroy: vi.fn(), remoteAddress: "192.0.2.9", remotePort: 5432 } } };
  return { stream, transport, config, driver, owned };
};
afterEach(() => vi.useRealTimers());

test("exact connected destination and backend capability only; no startup/auth/password API", async () => {
  const f = fixture();
  const done = cancelOwnedQuery(f.driver, f.owned);
  expect(f.config).toHaveBeenCalledExactlyOnceWith({ host: "/g2-fixture-socket", port: 5432, ssl: false });
  expect(f.transport.connect).toHaveBeenCalledExactlyOnceWith("/g2-fixture-socket/.s.PGSQL.5432");
  f.transport.emit("connect");
  expect(f.transport.cancel).toHaveBeenCalledExactlyOnceWith(123, 987);
  f.transport.emit("end");
  await done;
  expect(f.stream.destroy).toHaveBeenCalledTimes(1);
});
test("TLS keeps exact policy and sends only after secureConnect", async () => {
  const ssl = { rejectUnauthorized: true, ca: "SYNTHETIC_CA" };
  const f = fixture(ssl);
  const done = cancelOwnedQuery(f.driver, f.owned);
  expect(f.config.mock.calls[0][0].ssl).toEqual({ ...ssl, servername: "fixture.invalid" });
  expect(f.transport.connect).toHaveBeenCalledExactlyOnceWith(5432, "192.0.2.9");
  f.transport.emit("connect");
  expect(f.transport.requestSsl).toHaveBeenCalledTimes(1);
  expect(f.transport.cancel).not.toHaveBeenCalled();
  f.transport.emit("sslconnect");
  expect(f.transport.cancel).not.toHaveBeenCalled();
  f.stream.emit("secureConnect");
  expect(f.transport.cancel).toHaveBeenCalledTimes(1);
  f.transport.emit("end");
  await done;
});
for (const event of ["error", "errorMessage"] as const) test(event + " refuses and cannot send after late connect/TLS events", async () => {
  const f = fixture({ rejectUnauthorized: true });
  const done = cancelOwnedQuery(f.driver, f.owned);
  f.transport.emit(event, new Error("SYNTHETIC_SECRET_CANARY"));
  await done;
  f.transport.emit("connect"); f.transport.emit("sslconnect"); f.stream.emit("secureConnect");
  expect(f.transport.cancel).not.toHaveBeenCalled();
  expect(f.transport.requestSsl).not.toHaveBeenCalled();
});
test("500ms timer destroys a stalled connect; late events do not cancel", async () => {
  vi.useFakeTimers();
  const f = fixture();
  const done = cancelOwnedQuery(f.driver, f.owned);
  await vi.advanceTimersByTimeAsync(499);
  expect(f.stream.destroy).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);
  await done;
  expect(f.stream.destroy).toHaveBeenCalledTimes(1);
  f.transport.emit("connect");
  expect(f.transport.cancel).not.toHaveBeenCalled();
});
test("stalled TLS handshake is bounded without plaintext fallback", async () => {
  vi.useFakeTimers();
  const f = fixture({ rejectUnauthorized: true });
  const done = cancelOwnedQuery(f.driver, f.owned);
  f.transport.emit("connect"); f.transport.emit("sslconnect");
  await vi.advanceTimersByTimeAsync(500); await done;
  f.stream.emit("secureConnect");
  expect(f.transport.cancel).not.toHaveBeenCalled();
  expect(f.transport.connect).toHaveBeenCalledTimes(1);
});
test("query changed before transport connect: never cancel its successor", async () => {
  const f = fixture();
  const done = cancelOwnedQuery(f.driver, f.owned);
  f.owned.activeQuery = {};
  f.transport.emit("connect");
  await done;
  expect(f.transport.cancel).not.toHaveBeenCalled();
});
test("no query or malformed destination/capability never opens transport", async () => {
  for (const change of [{ activeQuery: null }, { processID: undefined }, { secretKey: NaN }, { host: "" }, { port: undefined }]) {
    const f = fixture(); Object.assign(f.owned, change);
    await cancelOwnedQuery(f.driver, f.owned);
    expect(f.config).not.toHaveBeenCalled();
  }
});
test("Unix socket path remains exact", async () => {
  const f = fixture(); f.owned.host = "/g2-fixture-socket";
  const done = cancelOwnedQuery(f.driver, f.owned);
  expect(f.transport.connect).toHaveBeenCalledExactlyOnceWith("/g2-fixture-socket/.s.PGSQL.5432");
  f.transport.emit("end"); await done;
});
test("constructor or connect failure stays value-free and settles", async () => {
  const f = fixture();
  f.transport.connect.mockImplementation(() => { throw new Error("SYNTHETIC_CAPABILITY_CANARY"); });
  await expect(cancelOwnedQuery(f.driver, f.owned)).resolves.toBeUndefined();
  expect(f.transport.cancel).not.toHaveBeenCalled();
});

for (const method of ["requestSsl", "cancel"] as const) test(method + " event-time write failure is sanitized", async () => {
  const f = fixture(method === "requestSsl" ? { rejectUnauthorized: true } : false);
  f.transport[method].mockImplementation(() => { throw new Error("SYNTHETIC_WRITE_CANARY"); });
  const done = cancelOwnedQuery(f.driver, f.owned);
  expect(() => f.transport.emit("connect")).not.toThrow();
  await expect(done).resolves.toBeUndefined();
  expect(f.stream.destroy).toHaveBeenCalledTimes(1);
});

for (const change of ["plaintext", "unverified", "custom-check", "missing-peer", "wrong-port"] as const) test("TCP " + change + " declines capability before transport", async () => {
  const f = fixture({ rejectUnauthorized: true });
  if (change === "plaintext") f.owned.ssl = false;
  if (change === "unverified") f.owned.ssl = { rejectUnauthorized: false };
  if (change === "custom-check") f.owned.ssl = { checkServerIdentity: () => undefined };
  if (change === "missing-peer") f.owned.connection.stream.remoteAddress = undefined;
  if (change === "wrong-port") f.owned.connection.stream.remotePort = 1234;
  await cancelOwnedQuery(f.driver, f.owned);
  expect(f.config).not.toHaveBeenCalled();
});
test("duplicate connect events cannot send a second capability packet", async () => {
  const f = fixture(); const done = cancelOwnedQuery(f.driver, f.owned);
  f.transport.emit("connect"); f.transport.emit("connect");
  expect(f.transport.cancel).toHaveBeenCalledTimes(1);
  f.transport.emit("end"); await done;
});

test("Unix plus SSL is unsupported and refuses before opening transport", async () => {
  const f = fixture({ rejectUnauthorized: true }); f.owned.host = "/g2-fixture-socket";
  await cancelOwnedQuery(f.driver, f.owned);
  expect(f.config).not.toHaveBeenCalled();
  expect(f.transport.connect).not.toHaveBeenCalled();
});

test("DNS host overrides conflicting configured TLS name exactly as pinned pg", async () => {
  const f = fixture({ rejectUnauthorized: true, servername: "different.fixture.invalid" });
  const done = cancelOwnedQuery(f.driver, f.owned);
  expect(f.config.mock.calls[0][0].ssl.servername).toBe("fixture.invalid");
  expect(f.transport.connect).toHaveBeenCalledExactlyOnceWith(5432, "192.0.2.9");
  f.transport.emit("end"); await done;
});
test("numeric original host retains explicit configured TLS name", async () => {
  const f = fixture({ rejectUnauthorized: true, servername: "explicit.fixture.invalid" });
  f.owned.host = "192.0.2.9";
  const done = cancelOwnedQuery(f.driver, f.owned);
  expect(f.config.mock.calls[0][0].ssl.servername).toBe("explicit.fixture.invalid");
  expect(f.transport.connect).toHaveBeenCalledExactlyOnceWith(5432, "192.0.2.9");
  f.transport.emit("end"); await done;
});
test("numeric original host without proven explicit TLS name declines transport", async () => {
  for (const host of ["192.0.2.9", "2001:db8::9"]) for (const ssl of [true, { rejectUnauthorized: true }, { servername: "" }]) {
    const f = fixture(ssl); f.owned.host = host;
    await cancelOwnedQuery(f.driver, f.owned);
    expect(f.config).not.toHaveBeenCalled();
  }
});
