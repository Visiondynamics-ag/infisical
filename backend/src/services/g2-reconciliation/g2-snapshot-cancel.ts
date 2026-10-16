// Pinned node-postgres protocol adapter. The cancel capability stays in RAM and
// is never serialized/logged. No new session, SQL, pool slot, or fallback.
import type { EventEmitter } from "node:events";
import { isIP } from "node:net";

type Stream = EventEmitter & { destroy: () => unknown };
type Protocol = EventEmitter & {
  stream: Stream;
  connect: (portOrPath: number | string, host?: string) => void;
  requestSsl: () => void;
  cancel: (processId: number, secret: number) => void;
};
export type OwnedPgConnection = {
  __knex__disposed?: unknown;
  activeQuery?: unknown;
  processID?: number;
  secretKey?: number;
  host?: string;
  port?: number;
  ssl?: unknown;
  connection: { stream: { destroy: () => unknown; remoteAddress?: string; remotePort?: number } };
};
export type CancelDriver = { Client: new (config: { host: string; port: number; ssl: unknown }) => { connection: Protocol } };

export const cancelOwnedQuery = (driver: CancelDriver, owned: OwnedPgConnection): Promise<void> => {
  const query = owned.activeQuery;
  if (!query || !Number.isInteger(owned.processID) || owned.processID! <= 0 || owned.processID! > 2147483647 ||
      !Number.isInteger(owned.secretKey) || owned.secretKey! < -2147483648 || owned.secretKey! > 2147483647 ||
      typeof owned.host !== "string" || !owned.host || !Number.isInteger(owned.port) || owned.port! < 1 || owned.port! > 65535) return Promise.resolve();
  const host = owned.host;
  const port = owned.port!;
  const unix = host.startsWith("/");
  let peer = host;
  let ssl: unknown = owned.ssl || false;
  if (unix && ssl) return Promise.resolve(); // pg TLS setup requires a TCP host; no fallback.
  if (!unix) {
    // Never re-resolve DNS or send a backend capability over unverified TCP.
    // Unsupported policies decline cancellation; the owned socket is still discarded.
    const remote = owned.connection.stream.remoteAddress;
    if (!remote || !isIP(remote) || owned.connection.stream.remotePort !== port || !ssl) return Promise.resolve();
    if (ssl !== true && (typeof ssl !== "object" || ssl === null)) return Promise.resolve();
    const options = ssl === true ? {} : ssl as Record<string, unknown>;
    if (options.rejectUnauthorized === false || options.checkServerIdentity !== undefined) return Promise.resolve();
    peer = remote;
    ssl = { ...options, rejectUnauthorized: true, servername: options.servername || host };
    // pg deliberately hides private key properties; preserve without exporting.
    if ("key" in options) (ssl as Record<string, unknown>).key = options.key;
  }
  return new Promise((resolve) => {
    let transport: Protocol | undefined;
    let finished = false;
    let sent = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      transport?.stream.destroy();
      resolve();
    };
    const timer = setTimeout(finish, 500);
    try {
      // Retain the exact connected client's destination/TLS policy. No password,
      // user/database session, DNS fallback, pg environment destination or SQL.
      transport = new driver.Client({ host: peer, port, ssl }).connection;
      const send = () => {
        if (finished || sent) return;
        if (owned.activeQuery !== query) { finish(); return; }
        sent = true;
        try { transport!.cancel(owned.processID!, owned.secretKey!); } catch { finish(); }
      };
      transport.on("error", finish);
      transport.on("errorMessage", finish);
      transport.on("end", finish);
      transport.on("connect", () => {
        if (finished) return;
        try { if (ssl) transport!.requestSsl(); else send(); } catch { finish(); }
      });
      // Unlike pg.Client.cancel, preserve SSL negotiation and await certificate
      // validation before sending the capability. Never retry without TLS.
      transport.on("sslconnect", () => {
        if (finished) { transport!.stream.destroy(); return; }
        transport!.stream.once("secureConnect", send);
      });
      if (unix) transport.connect(`${host}/.s.PGSQL.${port}`);
      else transport.connect(port, peer);
    } catch { finish(); }
  });
};
