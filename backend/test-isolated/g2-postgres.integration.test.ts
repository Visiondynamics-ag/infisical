import { beforeAll, beforeEach, afterAll, expect, test } from "vitest";
import knex from "knex";
import { existsSync, readFileSync } from "node:fs";
import { packRules } from "@casl/ability/extra";
import { TableName } from "@app/db/schemas";
import { g2SnapshotDAL } from "@app/services/g2-reconciliation/g2-snapshot-dal";
import { G2, projectGraph } from "@app/services/g2-reconciliation/g2-snapshot-contract";
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
  connection: { host: "/g2-fixture-socket", port: 5432, user: "g2_fixture", database: "g2_fixture" },
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
  await db(TableName.Users).where({ id: user }).update({ isMfaEnabled: false, selectedMfaMethod: null });
  await db(TableName.AuthTokenSession).where({ id: session }).update({ accessVersion: 1 });
  await db(TableName.MembershipRole)
    .whereIn("id", [id(5), id(6)])
    .update({ role: "admin" });
  await db(TableName.AdditionalPrivilege).where({ actorUserId: user }).delete();
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
