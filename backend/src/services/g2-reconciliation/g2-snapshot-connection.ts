import { performance } from "node:perf_hooks";

import type { Knex } from "knex";

import { cancelOwnedQuery, type CancelDriver, type OwnedPgConnection } from "./g2-snapshot-cancel";
import { requireSnapshot, SnapshotRefusal } from "./g2-snapshot-contract";

// Endpoint-local adapter for the pinned Knex/Tarn/node-postgres closure. No global
// pool configuration changes or detached transaction race. Cancellation owns a
// separate bounded protocol-only socket; it never obtains another pool lease.
type Connection = OwnedPgConnection;
type Pool = {
  acquire: () => { promise: Promise<Connection>; abort: () => void };
  release: (connection: Connection) => boolean;
};

export const withSnapshotConnection = async <T>(
  db: Knex,
  deadline: number,
  check: () => void,
  work: (connection: Connection, guard: () => void) => Promise<T>
): Promise<T> => {
  const client = db.client as { config?: { client?: string }; pool?: Pool; driver: CancelDriver };
  requireSnapshot(client.config?.client === "pg" && !!client.pool, "TRANSACTION");
  const pool = client.pool!;
  check();
  const pending = pool.acquire(); // Keep the abort handle Knex.acquireConnection discards.
  let connection: Connection | undefined;
  let stopped: SnapshotRefusal | undefined;
  let socketClosed = false;
  let cancellation: Promise<void> | undefined;
  const close = () => {
    if (connection && !socketClosed) {
      socketClosed = true;
      // Knex's pinned pool validator rejects this before reuse. Closing the
      // owned socket interrupts BEGIN/query/COMMIT/ROLLBACK, including a SQL wait.
      connection.__knex__disposed = "G2_SNAPSHOT_CANCELLED";
      connection.connection.stream.destroy();
    }
  };
  const stop = (error: unknown) => {
    if (stopped) return;
    stopped = new SnapshotRefusal(error instanceof SnapshotRefusal ? error.code : "INTERNAL");
    pending.abort();
    if (connection) cancellation = cancelOwnedQuery(client.driver, connection).finally(close);
  };
  const poll = () => {
    try { check(); } catch (error) { stop(error); }
  };
  const timer = setTimeout(() => stop(new SnapshotRefusal("DEADLINE")), Math.max(0, deadline - performance.now()));
  // Existing route supplies a cancellation predicate. Bound detection latency
  // without changing its authentication/transport interfaces.
  const interval = setInterval(poll, 20);
  try {
    connection = await pending.promise;
    requireSnapshot(typeof connection.connection?.stream?.destroy === "function", "TRANSACTION");
    // A grant may win before abort but reach this continuation afterwards.
    // We still own/release it; no transaction may begin after cancellation.
    poll();
    if (stopped) throw stopped;
    const guard = () => { if (stopped) throw stopped; check(); };
    const result = await work(connection, guard);
    poll();
    if (stopped) throw stopped;
    return result;
  } catch (error) {
    // Never return an ambiguously completed/rolled-back transaction to reuse.
    // Await work's settlement before the finally release; no orphaned Promise.race.
    if (cancellation) await cancellation;
    if (connection?.connection?.stream?.destroy) close();
    throw stopped || error;
  } finally {
    clearTimeout(timer);
    clearInterval(interval);
    if (cancellation) await cancellation;
    if (connection) pool.release(connection); // Exactly once; external Knex tx does not release.
  }
};
