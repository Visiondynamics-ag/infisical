import { performance } from "node:perf_hooks";
import type { Knex } from "knex";
import { afterEach, describe, expect, test, vi } from "vitest";

import { SnapshotRefusal } from "./g2-snapshot-contract";
import { withSnapshotConnection } from "./g2-snapshot-connection";

const deferred = <T>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
};
const fixture = () => {
  const acquire = deferred<Connection>();
  const closed = deferred<void>();
  const connection = { __knex__disposed: undefined as unknown, connection: { stream: { destroy: vi.fn(() => closed.resolve()) } } };
  const abort = vi.fn(() => acquire.reject(new Error("SYNTHETIC_ABORT")));
  const release = vi.fn(() => true);
  const db = { client: { config: { client: "pg" }, pool: { acquire: () => ({ promise: acquire.promise, abort }), release } } } as unknown as Knex;
  return { acquire, closed, connection, abort, release, db };
};
type Connection = { __knex__disposed?: unknown; connection: { stream: { destroy: () => unknown } } };
afterEach(() => vi.useRealTimers());

describe("endpoint-owned pinned pool lifecycle", () => {
  test("success releases once only after transaction completion", async () => {
    const f = fixture(), done = deferred<string>();
    f.acquire.resolve(f.connection);
    const p = withSnapshotConnection(f.db, performance.now() + 1000, () => {}, () => done.promise);
    await Promise.resolve();
    expect(f.release).not.toHaveBeenCalled();
    done.resolve("projection");
    expect(await p).toBe("projection");
    expect(f.release).toHaveBeenCalledExactlyOnceWith(f.connection);
    expect(f.connection.connection.stream.destroy).not.toHaveBeenCalled();
  });
  test("abort cancels waiter without beginning or releasing an unowned connection", async () => {
    const f = fixture(), work = vi.fn();
    const p = withSnapshotConnection(f.db, performance.now() + 10, () => {}, work);
    await expect(p).rejects.toMatchObject({ code: "DEADLINE" });
    expect(f.abort).toHaveBeenCalledTimes(1);
    expect(work).not.toHaveBeenCalled();
    expect(f.release).not.toHaveBeenCalled();
  });
  test("resolved grant racing cancellation is still disposed/released exactly once without BEGIN", async () => {
    const f = fixture(), work = vi.fn();
    let calls = 0;
    f.acquire.resolve(f.connection);
    await expect(withSnapshotConnection(f.db, performance.now() + 1000, () => {
      if (++calls > 1) throw new SnapshotRefusal("DEADLINE");
    }, work)).rejects.toMatchObject({ code: "DEADLINE" });
    expect(work).not.toHaveBeenCalled();
    expect(f.release).toHaveBeenCalledExactlyOnceWith(f.connection);
    expect(f.connection.connection.stream.destroy).toHaveBeenCalledTimes(1);
  });
  test("cancellation closes socket but waits for transaction settlement before release", async () => {
    const f = fixture(), done = deferred<string>();
    f.acquire.resolve(f.connection);
    const p = withSnapshotConnection(f.db, performance.now() + 10, () => {}, () => done.promise);
    const rejected = expect(p).rejects.toMatchObject({ code: "DEADLINE" });
    await f.closed.promise;
    expect(f.release).not.toHaveBeenCalled();
    done.reject(new Error("SYNTHETIC_SOCKET_CLOSED"));
    await rejected;
    expect(f.release).toHaveBeenCalledTimes(1);
    expect(f.connection.__knex__disposed).toBe("G2_SNAPSHOT_CANCELLED");
  });
  test("uncertain rollback rejection discards before release, never reuse", async () => {
    const f = fixture();
    f.acquire.resolve(f.connection);
    await expect(withSnapshotConnection(f.db, performance.now() + 1000, () => {}, async () => {
      throw new Error("SYNTHETIC_ROLLBACK_TIMEOUT");
    })).rejects.toThrow("SYNTHETIC_ROLLBACK_TIMEOUT");
    expect(f.connection.connection.stream.destroy).toHaveBeenCalledTimes(1);
    expect(f.release).toHaveBeenCalledTimes(1);
    expect(f.connection.__knex__disposed).toBeTruthy();
    expect(f.connection.connection.stream.destroy.mock.invocationCallOrder[0]).toBeLessThan(f.release.mock.invocationCallOrder[0]);
  });
  test("expired actor closes in-flight work and preserves AUTH refusal", async () => {
    const f = fixture();
    f.acquire.resolve(f.connection);
    let expired = false;
    const p = withSnapshotConnection(f.db, performance.now() + 1000, () => { if (expired) throw new SnapshotRefusal("AUTH"); }, async () => {
      expired = true;
      await f.closed.promise;
      throw new Error("SYNTHETIC_CLOSED");
    });
    await expect(p).rejects.toMatchObject({ code: "AUTH" });
    expect(f.release).toHaveBeenCalledTimes(1);
  });
  test("post-COMMIT cancellation discards projection", async () => {
    const f = fixture();
    f.acquire.resolve(f.connection);
    let cancelled = false;
    await expect(withSnapshotConnection(f.db, performance.now() + 1000, () => { if (cancelled) throw new SnapshotRefusal("DEADLINE"); }, async () => {
      cancelled = true; return "MUST_NOT_ESCAPE";
    })).rejects.toMatchObject({ code: "DEADLINE" });
    expect(f.release).toHaveBeenCalledTimes(1);
  });
  test("unsupported driver refuses before acquisition", async () => {
    const f = fixture();
    f.db.client.config.client = "sqlite3";
    await expect(withSnapshotConnection(f.db, performance.now() + 1000, () => {}, vi.fn())).rejects.toMatchObject({ code: "TRANSACTION" });
    expect(f.release).not.toHaveBeenCalled();
  });
});

test("stopped work guard prevents subsequent application statements even if work catches a query error", async () => {
  const f = fixture(); f.acquire.resolve(f.connection);
  let submitted = false;
  const p = withSnapshotConnection(f.db, performance.now() + 10, () => {}, async (_connection, guard) => {
    await f.closed.promise;
    guard(); submitted = true;
  });
  await expect(p).rejects.toMatchObject({ code: "DEADLINE" });
  expect(submitted).toBe(false);
  expect(f.release).toHaveBeenCalledTimes(1);
});
