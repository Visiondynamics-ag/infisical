import Fastify from "fastify";
import cookie from "@fastify/cookie";
import { fastifyRequestContext } from "@fastify/request-context";
import { request as httpRequest } from "node:http";
import { performance } from "node:perf_hooks";
import { initEnvConfig } from "@app/lib/config/env";
import { crypto } from "@app/lib/crypto";
import { initLogger } from "@app/lib/logger";
import { RequestMemoizer } from "@app/lib/request-context/request-memoizer";
import { RequestContextKey } from "@app/lib/request-context/request-context-keys";
import { injectIdentity } from "@app/server/plugins/auth/inject-identity";
import { injectPermission } from "@app/server/plugins/auth/inject-permission";
import { injectAssumePrivilege } from "@app/server/plugins/auth/inject-assume-privilege";
import { fastifyErrHandler } from "@app/server/plugins/error-handler";
import { validatorCompiler, serializerCompiler } from "@app/server/plugins/fastify-zod";
import { registerG2ReconciliationRouter } from "@app/server/routes/v1/g2-reconciliation-router";
import { registerAuthRoutes } from "@app/server/routes/v1/auth-router";
import { tokenServiceFactory } from "@app/services/auth-token/auth-token-service";
import { tokenDALFactory } from "@app/services/auth-token/auth-token-dal";
import { userDALFactory } from "@app/services/user/user-dal";
import { orgDALFactory } from "@app/services/org/org-dal";
import { assumePrivilegeServiceFactory } from "@app/ee/services/assume-privilege/assume-privilege-service";
import { beforeAll, beforeEach, afterAll, expect, test } from "vitest";
import knex from "knex";
import { existsSync, readFileSync } from "node:fs";
import { packRules } from "@casl/ability/extra";
import { TableName } from "@app/db/schemas";
import { g2SnapshotDAL } from "@app/services/g2-reconciliation/g2-snapshot-dal";
import { G2, projectGraph } from "@app/services/g2-reconciliation/g2-snapshot-contract";
import { withSnapshotConnection } from "@app/services/g2-reconciliation/g2-snapshot-connection";
import { g2SnapshotService } from "@app/services/g2-reconciliation/g2-snapshot-service";
import { permissionDALFactory } from "@app/ee/services/permission/permission-dal";
import { ProjectPermissionSub } from "@app/ee/services/permission/project-permission";
import { permissionServiceFactory } from "@app/ee/services/permission/permission-service";
import { AuthMethod, AuthTokenType } from "@app/services/auth/auth-type";

// The new network-disabled container's Unix socket only. Never use env/default endpoints.
if (process.platform !== "linux" || process.arch !== "x64" || !existsSync("/g2-fixture-socket/.g2-test-only"))
  throw new Error("FIXTURE_REQUIRED");
const marker = readFileSync("/g2-fixture-socket/.g2-test-only", "utf8").trim();
if (!/^g2-fixture-[0-9a-f]{32}$/.test(marker)) throw new Error("FIXTURE_IDENTITY");
const db = knex({
  client: "pg",
  connection: {
    host: "/g2-fixture-socket",
    port: 5432,
    user: "g2_fixture",
    database: "g2_fixture",
    application_name: "g2-snapshot-fixture"
  },
  pool: { min: 0, max: 3 },
  acquireConnectionTimeout: 3000
});
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const target = id(100),
  user = id(1),
  session = id(2),
  orgMember = id(3),
  projectMember = id(4);
const leafRule = {
  action: ["describeSecret", "readValue"],
  subject: "secrets",
  conditions: { environment: { $eq: "prod" }, secretPath: { $glob: G2.folderPath } }
};
const checkpoint = async () => {};
const read = async () =>
  db.transaction(async (tx) => {
    await tx.raw("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    return projectGraph(await g2SnapshotDAL(tx, checkpoint).graph());
  });
const token = () => ({
  authTokenType: AuthTokenType.ACCESS_TOKEN,
  userId: user,
  tokenVersionId: session,
  accessVersion: 1,
  authMethod: AuthMethod.EMAIL,
  organizationId: G2.orgId,
  isMfaVerified: false,
  exp: Math.floor(Date.now() / 1000) + 600
});
const fail = () => {
  throw new Error("OUTSIDE_TX_CANARY");
};
Object.assign(db, { replicaNode: fail });
const permissionDAL = permissionDALFactory(db as Parameters<typeof permissionDALFactory>[0]);
const permission = permissionServiceFactory({
  permissionDAL,
  projectDAL: { findById: fail },
  userDAL: { findById: fail },
  identityDAL: { findById: fail },
  serviceTokenDAL: { findById: fail },
  keyStore: { getItem: fail },
  roleDAL: {},
  additionalPrivilegeDAL: {},
  groupDAL: {}
} as unknown as Parameters<typeof permissionServiceFactory>[0]);
const observe = () => g2SnapshotService(db, permission)(token(), "a".repeat(64), () => false);
beforeAll(async () => {
  initLogger();
  await initEnvConfig({} as never, {} as never);
  await crypto.initialize({} as never, {} as never, {} as never);
  const r = await db.raw(
    "SELECT current_database() AS name,current_user AS actor,inet_server_addr() AS address,pg_is_in_recovery() AS recovery"
  );
  expect(r.rows[0]).toEqual({ name: "g2_fixture", actor: "g2_fixture", address: null, recovery: false });
  expect(
    (await db.raw("SELECT count(*)::int AS count FROM information_schema.tables WHERE table_schema='public'")).rows[0]
      .count
  ).toBe(0);
  const migrations = await db.migrate.latest({
    directory: "./dist/db/migrations",
    loadExtensions: [".mjs"],
    tableName: "infisical_migrations"
  });
  console.log(
    JSON.stringify({ fixtureMigrationCount: migrations[1].length, endpoint: "unique-unix-socket", stockE2E: false })
  );
  await db(TableName.Organization).insert({
    id: G2.orgId,
    name: "fixture",
    slug: "g2-fixture",
    shouldUseNewPrivilegeSystem: true
  });
  await db(TableName.Project).insert({
    id: G2.projectId,
    orgId: G2.orgId,
    name: "fixture",
    slug: G2.projectSlug,
    type: "secret-manager"
  });
  await db(TableName.Environment).insert({
    id: G2.environmentId,
    projectId: G2.projectId,
    name: "prod",
    slug: "prod",
    position: 1
  });
  await db(TableName.SecretFolder).insert([
    { id: id(70), envId: G2.environmentId, name: "root", parentId: null },
    { id: id(71), envId: G2.environmentId, name: "ci", parentId: id(70) },
    { id: id(72), envId: G2.environmentId, name: "woodpecker", parentId: id(71) },
    { id: id(73), envId: G2.environmentId, name: "agents", parentId: id(72) },
    { id: G2.folderId, envId: G2.environmentId, name: "vd-infra", parentId: id(73) }
  ]);
  await db(TableName.Users).insert({ id: user, username: "fixture-user", isAccepted: true, isMfaEnabled: false });
  await db(TableName.AuthTokenSession).insert({
    id: session,
    userId: user,
    ip: "127.0.0.1",
    lastUsed: new Date(),
    accessVersion: 1
  });
  await db(TableName.Membership).insert([
    {
      id: orgMember,
      actorUserId: user,
      scope: "organization",
      scopeOrgId: G2.orgId,
      status: "accepted",
      isActive: true
    },
    {
      id: projectMember,
      actorUserId: user,
      scope: "project",
      scopeOrgId: G2.orgId,
      scopeProjectId: G2.projectId,
      isActive: true
    }
  ]);
  await db(TableName.MembershipRole).insert([
    { id: id(5), membershipId: orgMember, role: "admin" },
    { id: id(6), membershipId: projectMember, role: "admin" }
  ]);
}, 180000);
beforeEach(async () => {
  await db(TableName.Identity).where({ orgId: G2.orgId }).delete();
  await db(TableName.Identity).insert({ id: target, name: G2.name, orgId: G2.orgId });
  await db(TableName.Organization)
    .where({ id: G2.orgId })
    .update({ authEnforced: false, enforceMfa: false, selectedMfaMethod: null });
  await db(TableName.Users)
    .where({ id: user })
    .update({ isMfaEnabled: false, selectedMfaMethod: null, isLocked: false, isAccepted: true });
  await db(TableName.AuthTokenSession).where({ id: session }).update({ accessVersion: 1 });
  await db(TableName.MembershipRole)
    .whereIn("id", [id(5), id(6)])
    .update({ role: "admin" });
  await db(TableName.AdditionalPrivilege).where({ actorUserId: user }).delete();
  await db(TableName.Membership).where({ id: orgMember }).update({ status: "accepted", isActive: true });
});
afterAll(async () => {
  await db.destroy();
});
test("actual migration chain installs graph tables", async () => {
  for (const t of [TableName.Identity, TableName.Membership, TableName.MembershipRole, TableName.AdditionalPrivilege])
    expect(await db.schema.hasTable(t)).toBe(true);
});
test("primary read-only repeatable-read DAL preserves snapshot under concurrent insert", async () => {
  await db(TableName.Identity).where({ id: target }).delete();
  await db.transaction(async (tx) => {
    await tx.raw("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    const dal = g2SnapshotDAL(tx, checkpoint);
    expect((await dal.graph()).identities).toHaveLength(0);
    await db(TableName.Identity).insert({ id: target, name: G2.name, orgId: G2.orgId });
    expect((await dal.graph()).identities).toHaveLength(0);
  });
  expect((await read()).identityId).toBe(target);
});
test("PostgreSQL read-only transaction rejects attempted write", async () => {
  await expect(
    db.transaction(async (tx) => {
      await tx.raw("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      await tx(TableName.Identity).where({ id: target }).update({ name: "forbidden" });
    })
  ).rejects.toMatchObject({ code: "25006" });
});
test("roleless membership is retained as conflict", async () => {
  await db(TableName.Membership).insert({
    id: id(110),
    actorIdentityId: target,
    scope: "project",
    scopeOrgId: G2.orgId,
    scopeProjectId: G2.projectId
  });
  const g = await read();
  expect(g.memberships).toHaveLength(1);
  expect(g.memberships[0]).toMatchObject({ id: id(110), roles: [], comparison: "CONFLICT" });
});
test("orphan grant remains visible and conflicting", async () => {
  await db(TableName.AdditionalPrivilege).insert({
    id: id(120),
    actorIdentityId: target,
    projectId: G2.projectId,
    name: G2.grantName,
    permissions: JSON.stringify(packRules([leafRule]))
  });
  expect((await read()).privileges[0]).toMatchObject({ id: id(120), membershipPresent: false, comparison: "CONFLICT" });
});
test("exact no-access membership and scoped rule compare without exporting rule values", async () => {
  await db(TableName.Membership).insert({
    id: id(110),
    actorIdentityId: target,
    scope: "project",
    scopeOrgId: G2.orgId,
    scopeProjectId: G2.projectId
  });
  await db(TableName.MembershipRole).insert({ id: id(111), membershipId: id(110), role: "no-access" });
  await db(TableName.AdditionalPrivilege).insert({
    id: id(120),
    actorIdentityId: target,
    projectId: G2.projectId,
    name: G2.grantName,
    permissions: JSON.stringify(packRules([leafRule]))
  });
  const g = await read();
  expect(g.memberships[0].comparison).toBe("EXACT_NO_ACCESS");
  expect(g.privileges[0].comparison).toBe("EXACT_RULE");
  expect(JSON.stringify(g)).not.toContain("readValue");
});
test("same-name and case-fold collisions refuse rather than select UUID", async () => {
  await db(TableName.Identity).insert({ id: id(101), name: G2.name.toUpperCase(), orgId: G2.orgId });
  await expect(read()).rejects.toThrow("CONFLICT");
});
test("project-native same-name identity refuses", async () => {
  await db(TableName.Identity).where({ id: target }).update({ projectId: G2.projectId });
  await expect(read()).rejects.toThrow("CONFLICT");
});
test("metadata canary is counted but never projected", async () => {
  await db(TableName.IdentityMetadata).insert({
    id: id(130),
    identityId: target,
    orgId: G2.orgId,
    key: "fixture-key",
    value: "SYNTHETIC_VALUE_CANARY"
  });
  const g = await read();
  expect(g.metadataRowCount).toBe(1);
  expect(JSON.stringify(g)).not.toContain("SYNTHETIC_VALUE_CANARY");
});
test("metadata cap refuses whole graph", async () => {
  await db(TableName.IdentityMetadata).insert(
    Array.from({ length: 33 }, (_, n) => ({
      id: id(200 + n),
      identityId: target,
      orgId: G2.orgId,
      key: `fixture-${n}`,
      value: "SYNTHETIC"
    }))
  );
  await expect(read()).rejects.toThrow("CAP");
});
test("actual service and permission DAL use same primary transaction, preserving false authority", async () => {
  const r = await observe();
  expect(r.transaction).toMatchObject({ recovery: false, isolation: "repeatable read", readOnly: "on" });
  expect(r.executionAllowed).toBe(false);
  expect(r.deliveryAllowed).toBe(false);
  expect(r.credentialIssuance).toBe(false);
  expect(r.inverseQualified).toBe(false);
  expect(r.graph.identityId).toBe(target);
});
test("current session revocation refuses", async () => {
  await db(TableName.AuthTokenSession).where({ id: session }).update({ accessVersion: 2 });
  await expect(observe()).rejects.toThrow("AUTH");
});
test("current MFA user method refuses email and accepts TOTP", async () => {
  await db(TableName.Users).where({ id: user }).update({ isMfaEnabled: true, selectedMfaMethod: "totp" });
  const service = g2SnapshotService(db, permission);
  await expect(
    service({ ...token(), isMfaVerified: true, mfaMethod: "email" }, "a".repeat(64), () => false)
  ).rejects.toThrow("AUTH");
  await expect(
    service({ ...token(), isMfaVerified: true, mfaMethod: "totp" }, "a".repeat(64), () => false)
  ).resolves.toMatchObject({ executionAllowed: false });
});
test("SSO denial remains enforced from current transaction", async () => {
  await db(TableName.Organization).where({ id: G2.orgId }).update({ authEnforced: true });
  await db(TableName.MembershipRole)
    .where({ id: id(5) })
    .update({ role: "no-access" });
  await expect(observe()).rejects.toThrow();
});
test("current explicit identity-read denial refuses despite admin role", async () => {
  await db(TableName.AdditionalPrivilege).insert({
    id: id(140),
    actorUserId: user,
    projectId: G2.projectId,
    name: "fixture-deny",
    permissions: JSON.stringify(packRules([{ action: "read", subject: ProjectPermissionSub.Identity, inverted: true }]))
  });
  await expect(observe()).rejects.toThrow("AUTH");
});
test("cancellation refuses before connection and exports closed error", async () => {
  await expect(g2SnapshotService(db, permission)(token(), "a".repeat(64), () => true)).rejects.toMatchObject({
    code: "DEADLINE",
    message: "DEADLINE"
  });
});

// Actual auth plugin + JWT verifier + token service/DAL + org membership DAL.
// Only telemetry is a no-op sink; unused keystore/auth services throw instead of granting access.
const authDb = knex({
  client: "pg",
  connection: { host: "/g2-fixture-socket", port: 5432, user: "g2_fixture", database: "g2_fixture" },
  pool: { min: 0, max: 2 },
  acquireConnectionTimeout: 3000
});
Object.assign(authDb, { replicaNode: () => authDb });
const realUserDAL = userDALFactory(authDb as Parameters<typeof userDALFactory>[0]);
const realOrgDAL = orgDALFactory(authDb as Parameters<typeof orgDALFactory>[0]);
const realTokenDAL = tokenDALFactory(authDb as Parameters<typeof tokenDALFactory>[0]);
const authToken = tokenServiceFactory({
  tokenDAL: realTokenDAL,
  userDAL: realUserDAL,
  orgDAL: realOrgDAL,
  keyStore: new Proxy({}, { get: () => fail })
} as Parameters<typeof tokenServiceFactory>[0]);
const app = Fastify({ logger: false }).withTypeProvider<import("@app/server/plugins/fastify-zod").ZodTypeProvider>();
const url = "/api/v1/organization/identities/reconciliation-snapshots/woodpecker-vd-infra-g2";
const signingKey = "g2-synthetic-only-fixture-signing-key";
const signed = (overrides: Record<string, unknown> = {}, key = signingKey) =>
  crypto.jwt().sign({ ...token(), ...overrides }, key);
const headers = (overrides: Record<string, unknown> = {}) => ({
  authorization: `Bearer ${signed(overrides)}`,
  "x-vd-reconciliation-nonce": "a".repeat(64)
});
const http = (overrides: Record<string, unknown> = {}) =>
  app.inject({ method: "GET", url, headers: headers(overrides) });
const socketPath = "/tmp/g2-http-fixture.sock";
let serializationFault: null | "extra" | "authority" = null;
beforeEach(() => {
  serializationFault = null;
});
beforeAll(async () => {
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  app.addHook("preSerialization", async (req, _reply, payload) => {
    if (
      req.url === url &&
      payload &&
      (payload as { state?: string }).state === "SNAPSHOT_COMPLETE_FOR_FIXED_RECONCILIATION_GRAPH"
    ) {
      if (serializationFault === "extra") return { ...(payload as object), extra: "SYNTHETIC_SERIALIZER_CANARY" };
      if (serializationFault === "authority") return { ...(payload as object), executionAllowed: true };
    }
    return payload;
  });
  await app.register(cookie);
  await app.register(fastifyRequestContext, {
    defaultStoreValues: () => ({ [RequestContextKey.Memoizer]: new RequestMemoizer() })
  });
  app.decorate("services", {
    authToken,
    telemetry: { identifyUser: () => undefined },
    assumePrivileges: assumePrivilegeServiceFactory({ permissionService: permission })
  } as never);
  await app.register(fastifyErrHandler);
  await app.register(injectIdentity, { shouldForwardWritesToPrimaryInstance: false });
  await app.register(injectAssumePrivilege);
  await app.register(injectPermission);
  await app.register(registerG2ReconciliationRouter, { prefix: "/api/v1", db, permissionService: permission });
  await app.register(registerAuthRoutes, { prefix: "/api/v1/auth" });
  await app.listen({ path: socketPath }); // Unix socket in new container tmpfs only; no TCP listener.
});
afterAll(async () => {
  await app.close();
  await authDb.destroy();
});
test("HTTP actual JWT/session chain serializes exact success with no credential or rule values", async () => {
  await db(TableName.IdentityMetadata).insert({
    id: id(130),
    identityId: target,
    orgId: G2.orgId,
    key: "fixture-key",
    value: "SYNTHETIC_HTTP_CANARY"
  });
  const r = await http();
  expect(r.statusCode).toBe(200);
  expect(r.headers["cache-control"]).toBe("no-store");
  expect(r.headers["content-type"]).toContain("application/json");
  const body = r.json();
  expect(body.actor.userId).toBe(user);
  expect(body.graph.identityId).toBe(target);
  expect(body.graph.metadataRowCount).toBe(1);
  for (const k of ["executionAllowed", "credentialIssuance", "deliveryAllowed", "inverseQualified"])
    expect(body[k]).toBe(false);
  expect(Object.keys(body).sort()).toEqual(
    [
      "state",
      "nonce",
      "startedAt",
      "snapshotFinishedAt",
      "transaction",
      "scope",
      "actor",
      "folders",
      "graph",
      "executionAllowed",
      "credentialIssuance",
      "deliveryAllowed",
      "inverseQualified"
    ].sort()
  );
  expect(r.body).not.toContain("SYNTHETIC_HTTP_CANARY");
  expect(r.body).not.toContain(signingKey);
  expect(r.body).not.toContain("accessToken");
});
test("HTTP missing JWT refuses", async () => {
  expect(
    (await app.inject({ method: "GET", url, headers: { "x-vd-reconciliation-nonce": "a".repeat(64) } })).statusCode
  ).toBe(401);
});
test("HTTP invalid signature refuses before database authorization", async () => {
  const r = await app.inject({
    method: "GET",
    url,
    headers: { ...headers(), authorization: `Bearer ${signed({}, "wrong-synthetic-key")}` }
  });
  expect(r.statusCode).toBe(403);
});
test("HTTP expired JWT refuses", async () => {
  expect((await http({ exp: Math.floor(Date.now() / 1000) - 30 })).statusCode).toBe(403);
});
test("HTTP future not-before JWT refuses", async () => {
  expect((await http({ nbf: Math.floor(Date.now() / 1000) + 600 })).statusCode).toBe(403);
});
test("HTTP malformed JWT refuses without echo", async () => {
  const r = await app.inject({
    method: "GET",
    url,
    headers: { ...headers(), authorization: "Bearer SYNTHETIC_MALFORMED_CANARY" }
  });
  expect(r.statusCode).toBe(403);
  expect(r.body).not.toContain("SYNTHETIC_MALFORMED_CANARY");
});
test("HTTP current session revocation refuses through actual token service", async () => {
  await db(TableName.AuthTokenSession).where({ id: session }).update({ accessVersion: 2 });
  expect((await http()).statusCode).toBe(401);
});
test("HTTP nonexistent session refuses", async () => {
  expect((await http({ tokenVersionId: id(999) })).statusCode).toBe(404);
});
test("HTTP locked account refuses", async () => {
  await db(TableName.Users).where({ id: user }).update({ isLocked: true });
  expect((await http()).statusCode).toBe(401);
});
test("HTTP inactive organization membership refuses", async () => {
  await db(TableName.Membership).where({ id: orgMember }).update({ isActive: false });
  expect((await http()).statusCode).toBe(403);
});
test("HTTP missing org selection refuses", async () => {
  expect((await http({ organizationId: undefined })).statusCode).toBe(401);
});
test("HTTP delegated OAuth and MCP tokens cannot enter JWT-only route", async () => {
  for (const o of [{ oauthClientId: "fixture-oauth", scopes: [] }, { mcp: { endpointId: "fixture" } }])
    expect((await http(o)).statusCode).toBe(403);
});
test("HTTP assumed privilege cookie is rejected even when malformed cookie is cleared", async () => {
  const r = await app.inject({
    method: "GET",
    url,
    headers: { ...headers(), cookie: "infisical-project-assume-privileges=SYNTHETIC_INVALID_COOKIE" }
  });
  expect(r.statusCode).toBe(409);
  expect(r.json()).toEqual({ state: "REFUSED", code: "AUTH" });
});
test("HTTP actual MFA method validates and serializes closed refusal", async () => {
  await db(TableName.Users).where({ id: user }).update({ isMfaEnabled: true, selectedMfaMethod: "totp" });
  const bad = await http({ isMfaVerified: true, mfaMethod: "email" });
  expect(bad.statusCode).toBe(409);
  expect(bad.json()).toEqual({ state: "REFUSED", code: "AUTH" });
  expect((await http({ isMfaVerified: true, mfaMethod: "totp" })).statusCode).toBe(200);
});
test("HTTP evaluated identity deny serializes AUTH without rules", async () => {
  await db(TableName.AdditionalPrivilege).insert({
    id: id(140),
    actorUserId: user,
    projectId: G2.projectId,
    name: "fixture-deny",
    permissions: JSON.stringify(packRules([{ action: "read", subject: ProjectPermissionSub.Identity, inverted: true }]))
  });
  const r = await http();
  expect(r.statusCode).toBe(409);
  expect(r.json()).toEqual({ state: "REFUSED", code: "AUTH" });
  expect(r.body).not.toContain("fixture-deny");
});
test("HTTP case collision serializes only CONFLICT", async () => {
  await db(TableName.Identity).insert({ id: id(101), name: G2.name.toUpperCase(), orgId: G2.orgId });
  const r = await http();
  expect(r.statusCode).toBe(409);
  expect(r.json()).toEqual({ state: "REFUSED", code: "CONFLICT" });
});
test("HTTP nonce and caller scope injection refuse schema validation", async () => {
  expect(
    (await app.inject({ method: "GET", url, headers: { authorization: headers().authorization } })).statusCode
  ).toBe(422);
  expect((await app.inject({ method: "GET", url: url + "?projectId=" + id(999), headers: headers() })).statusCode).toBe(
    422
  );
});
test("existing checkAuth route still accepts ordinary and orgless JWT, rejects OAuth and stale session", async () => {
  const call = (o: Record<string, unknown> = {}) =>
    app.inject({ method: "POST", url: "/api/v1/auth/checkAuth", headers: headers(o) });
  expect((await call()).json()).toEqual({ message: "Authenticated" });
  expect((await call({ organizationId: undefined })).statusCode).toBe(200);
  expect((await call({ oauthClientId: "fixture" })).statusCode).toBe(403);
  await db(TableName.AuthTokenSession).where({ id: session }).update({ accessVersion: 2 });
  expect((await call()).statusCode).toBe(401);
});
test("HTTP client disconnect during real SQL wait produces no projection and releases transaction", async () => {
  const blocker = await authDb.transaction();
  await blocker.raw('LOCK TABLE "identities" IN ACCESS EXCLUSIVE MODE');
  let attempted = false,
    body = "",
    closed = false;
  let stopRequested = false;
  const afterStopQueries: string[] = [];
  const query = (q: { sql: string }) => {
    if (stopRequested) afterStopQueries.push(q.sql);
    if (q.sql.includes('from "identities"')) attempted = true;
  };
  db.on("query", query);
  const request = httpRequest({ socketPath, path: url, method: "GET", headers: headers() }, (r) => {
    r.on("data", (c) => {
      body += c;
    });
  });
  request.on("error", () => {});
  request.on("close", () => {
    closed = true;
  });
  request.end();
  try {
    const start = performance.now();
    while (!attempted && performance.now() - start < 5000) await new Promise((r) => setTimeout(r, 10));
    expect(attempted).toBe(true);
    stopRequested = true;
    request.destroy();
    const stop = performance.now();
    let active = true;
    while (active && performance.now() - stop < 5000) {
      await new Promise((r) => setTimeout(r, 40));
      const result = await authDb.raw(
        "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname='g2_fixture' AND application_name='g2-snapshot-fixture' AND xact_start IS NOT NULL"
      );
      active = result.rows[0].n !== 0;
    }
    expect(active).toBe(false);
    expect(performance.now() - stop).toBeLessThan(1000);
    console.log(
      JSON.stringify({
        transportAbortCleanupMs: Math.ceil(performance.now() - stop),
        projectionBytes: body.length,
        outstandingSnapshotTransactions: 0
      })
    );
    expect(afterStopQueries.every((sql) => sql === "ROLLBACK")).toBe(true);
    expect(closed).toBe(true);
    expect(body).toBe("");
  } finally {
    request.destroy();
    db.off("query", query);
    await blocker.rollback();
  }
});
test("saturated pool refuses at endpoint budget before the held connection is released", async () => {
  const single = knex({ client: "pg", connection: { host: "/g2-fixture-socket", port: 5432, user: "g2_fixture", database: "g2_fixture" }, pool: { min: 0, max: 1 }, acquireConnectionTimeout: 25000 });
  const held = await single.client.acquireConnection();
  const start = performance.now();
  let settled = false;
  const pending = g2SnapshotService(single, permission)(token(), "a".repeat(64), () => false).then(
    () => "UNEXPECTED_SUCCESS", (e) => e.code
  ).finally(() => { settled = true; });
  try {
    // Safety timeout belongs to the test, never to production cleanup.
    const outcome = await Promise.race([pending, new Promise((r) => setTimeout(() => r("TEST_TIMEOUT"), 15500))]);
    expect(outcome).toBe("DEADLINE");
    expect(settled).toBe(true);
    expect(single.client.pool.numPendingAcquires()).toBe(0);
    expect(single.client.pool.numUsed()).toBe(1); // Only test's blocker, not a lost grant.
    console.log(JSON.stringify({ poolWaitRefusalMs: Math.ceil(performance.now() - start), deadlineMs: 15000, testSchedulingToleranceMs: 500, releasedBlockerBeforeRefusal: false }));
  } finally {
    await single.client.releaseConnection(held);
    await pending;
    await single.destroy();
  }
}, 30000);

test("real Tarn grant racing abort is released without BEGIN and pool remains usable", async () => {
  const single = knex({ client: "pg", connection: { host: "/g2-fixture-socket", port: 5432, user: "g2_fixture", database: "g2_fixture" }, pool: { min: 0, max: 1 } });
  let cancelled = false, began = 0;
  const listener = () => { cancelled = true; };
  single.client.pool.on("acquireSuccess", listener);
  single.on("query", (q) => { if (q.sql === "BEGIN;") began++; });
  try {
    await expect(g2SnapshotService(single, permission)(token(), "a".repeat(64), () => cancelled)).rejects.toMatchObject({ code: "DEADLINE" });
    expect(began).toBe(0);
    expect(single.client.pool.numUsed()).toBe(0);
    single.client.pool.removeListener("acquireSuccess", listener);
    expect((await single.raw("SELECT 1 AS n")).rows[0].n).toBe(1);
  } finally { await single.destroy(); }
});

test("queued client abort removes only this acquire and does not consume a later grant", async () => {
  const single = knex({ client: "pg", connection: { host: "/g2-fixture-socket", port: 5432, user: "g2_fixture", database: "g2_fixture" }, pool: { min: 0, max: 1 } });
  const held = await single.client.acquireConnection();
  let cancelled = false;
  const pending = g2SnapshotService(single, permission)(token(), "a".repeat(64), () => cancelled);
  const result = pending.catch((e) => e.code);
  try {
    await new Promise((r) => setTimeout(r, 40));
    cancelled = true;
    expect(await result).toBe("DEADLINE");
    expect(single.client.pool.numPendingAcquires()).toBe(0);
    expect(single.client.pool.numUsed()).toBe(1);
  } finally { await single.client.releaseConnection(held); }
  try {
    expect((await single.raw("SELECT 1 AS n")).rows[0].n).toBe(1);
    expect(single.client.pool.numUsed()).toBe(0);
  } finally { await single.destroy(); }
});

for (const mode of ["deadline", "failure"] as const) test("owned connection " + mode + " rolls back real fixture transaction and does not leak", async () => {
  const single = knex({ client: "pg", connection: { host: "/g2-fixture-socket", port: 5432, user: "g2_fixture", database: "g2_fixture", application_name: "g2-cancel-fixture" }, pool: { min: 0, max: 1 } });
  // This helper-only test writes synthetic fixture data to prove rollback;
  // the production service still sets READ ONLY before its first read.
  await authDb.raw("CREATE TABLE g2_cancel_fixture (id integer)");
  try {
    const start = performance.now();
    const result = withSnapshotConnection(single, start + 200, () => {}, (connection) => single.transaction(async (tx) => {
      await tx.raw("SET LOCAL statement_timeout = 2000");
      await tx.raw("INSERT INTO g2_cancel_fixture VALUES (1)");
      if (mode === "failure") throw new Error("SYNTHETIC_FAILURE");
      await tx.raw("SELECT pg_sleep(10)");
    }, { connection }));
    await expect(result).rejects.toBeDefined();
    expect(performance.now() - start).toBeLessThan(1500);
    expect(single.client.pool.numUsed()).toBe(0);
    let outstanding = 1;
    const stop = performance.now();
    while (outstanding && performance.now() - stop < 1000) {
      await new Promise((r) => setTimeout(r, 20));
      outstanding = (await authDb.raw("SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name='g2-cancel-fixture' AND xact_start IS NOT NULL")).rows[0].n;
    }
    expect(outstanding).toBe(0);
    expect((await authDb.raw("SELECT count(*)::int AS n FROM g2_cancel_fixture")).rows[0].n).toBe(0);
    expect((await single.raw("SELECT 1 AS n")).rows[0].n).toBe(1);
  } finally { await single.destroy(); await authDb.raw("DROP TABLE g2_cancel_fixture"); }
});

for (const fault of ["extra", "authority"] as const)
  test("HTTP serializer rejects post-handler " + fault + " injection", async () => {
    serializationFault = fault;
    const r = await http();
    expect(r.statusCode).toBe(500);
    expect(r.body).not.toContain("SYNTHETIC_SERIALIZER_CANARY");
    expect(r.body).not.toContain("SNAPSHOT_COMPLETE_FOR_FIXED_RECONCILIATION_GRAPH");
    expect(r.body).not.toContain('"executionAllowed":true');
  });

for (const sql of ["SELECT 1 AS forbidden_after_stop", "COMMIT;"]) test("installed transaction guard refuses post-stop " + sql, async () => {
  let cancelled = false, attempted = false;
  const emitted: string[] = [];
  const listener = (q: { sql: string }) => { emitted.push(q.sql); };
  db.on("query", listener);
  const checkedPermission = {
    ...permission,
    getOrgPermission: async (params: Parameters<typeof permission.getOrgPermission>[0]) => {
      // Real transaction-bound authorization still executes; this test-only
      // wrapper then exercises the installed query guard, not a fake tx.
      const actual = await permission.getOrgPermission(params);
      cancelled = true;
      attempted = true;
      await params.snapshotTx!.raw(sql);
      return actual;
    }
  };
  try {
    await expect(g2SnapshotService(db, checkedPermission)(token(), "a".repeat(64), () => cancelled)).rejects.toMatchObject({ code: "DEADLINE" });
    expect(attempted).toBe(true);
    expect(emitted).not.toContain(sql);
    expect(db.client.pool.numUsed()).toBe(0);
  } finally { db.off("query", listener); }
});
