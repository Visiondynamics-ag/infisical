import type { RawRule } from "@casl/ability";
import { packRules } from "@casl/ability/extra";
import type { Knex } from "knex";
import { expect, expectTypeOf, test, vi } from "vitest";

import { TableName } from "@app/db/schemas";

import { G2 } from "./g2-snapshot-contract";
import { g2SnapshotDAL } from "./g2-snapshot-dal";

const userId = "00000000-0000-4000-8000-000000000001";
const sessionId = "00000000-0000-4000-8000-000000000002";
const orgMembershipId = "00000000-0000-4000-8000-000000000003";
const projectMembershipId = "00000000-0000-4000-8000-000000000004";
// Unit query double only. Does not prove PostgreSQL affinity or isolation.
function actorFixture(selectedMfaMethod: string | null, isMfaEnabled = true) {
  const selections: { table: string; columns: string[] }[] = [];
  const rows: Record<string, unknown[]> = {
    [TableName.AuthTokenSession]: [{ id: sessionId, userId, accessVersion: 1 }],
    [TableName.Users]: [
      { id: userId, isAccepted: true, isLocked: false, temporaryLockDateEnd: null, isMfaEnabled, selectedMfaMethod }
    ],
    [TableName.UserGroupMembership]: [],
    [TableName.Membership]: [
      { id: orgMembershipId, scope: "organization", scopeProjectId: null, status: "accepted", isActive: true },
      { id: projectMembershipId, scope: "project", scopeProjectId: G2.projectId, isActive: true }
    ],
    [TableName.MembershipRole]: [],
    [TableName.AdditionalPrivilege]: [],
    [TableName.IdentityMetadata]: []
  };
  const tx = Object.assign(
    (table: string) => {
      const query = {
        where: () => query,
        whereIn: () => query,
        select: (...columns: (string | string[])[]) => {
          selections.push({ table, columns: columns.flat() });
          return query;
        },
        limit: () => Promise.resolve(rows[table])
      };
      return query;
    },
    { isTransaction: true }
  );
  return {
    dal: g2SnapshotDAL(
      tx as unknown as Knex.Transaction,
      vi.fn(async () => {})
    ),
    selections
  };
}
test("actor reads selected user method on supplied tx and rejects stale method", async () => {
  const f = actorFixture("totp");
  await expect(
    f.dal.actor(userId, sessionId, 1, true, "email", { enforceMfa: false, selectedMfaMethod: null })
  ).rejects.toThrow("AUTH");
  expect(f.selections.find((s) => s.table === TableName.Users)?.columns).toContain("selectedMfaMethod");
});
test("actor accepts current user TOTP despite dormant org email setting", async () => {
  const f = actorFixture("totp");
  await expect(
    f.dal.actor(userId, sessionId, 1, true, "totp", { enforceMfa: false, selectedMfaMethod: "email" })
  ).resolves.toMatchObject({ userId, orgMembershipId });
});
test("actor enforces organization precedence", async () => {
  const f = actorFixture("totp");
  await expect(
    f.dal.actor(userId, sessionId, 1, true, "totp", { enforceMfa: true, selectedMfaMethod: "webauthn" })
  ).rejects.toThrow("AUTH");
});
test("actor null required method accepts email fallback only", async () => {
  const f = actorFixture(null);
  await expect(
    f.dal.actor(userId, sessionId, 1, true, undefined, { enforceMfa: true, selectedMfaMethod: null })
  ).rejects.toThrow("AUTH");
  await expect(
    f.dal.actor(userId, sessionId, 1, true, "email", { enforceMfa: true, selectedMfaMethod: null })
  ).resolves.toMatchObject({ userId });
});
test("actor can read no-MFA state", async () => {
  const f = actorFixture(null, false);
  await expect(
    f.dal.actor(userId, sessionId, 1, false, undefined, { enforceMfa: false, selectedMfaMethod: null })
  ).resolves.toMatchObject({ userId });
});
test("actor stale accessVersion still refuses before MFA", async () => {
  const f = actorFixture("totp");
  await expect(
    f.dal.actor(userId, sessionId, 2, true, "totp", { enforceMfa: false, selectedMfaMethod: null })
  ).rejects.toThrow("AUTH");
});

// Exercises the shipped graph decoder at the database JSON boundary. These
// query doubles do not claim real PostgreSQL snapshot isolation.
const graphFixture = (permissions: unknown) => {
  const identityId = "00000000-0000-4000-8000-000000000010";
  const rows: Record<string, unknown[]> = {
    [TableName.Identity]: [{ id: identityId, name: G2.name, orgId: G2.orgId, projectId: null }],
    [TableName.Membership]: [],
    [TableName.MembershipRole]: [],
    [TableName.AdditionalPrivilege]: [
      {
        id: "00000000-0000-4000-8000-000000000011",
        actorIdentityId: identityId,
        actorUserId: null,
        orgId: null,
        projectId: G2.projectId,
        name: G2.grantName,
        isTemporary: false,
        permissions
      }
    ],
    [TableName.IdentityMetadata]: []
  };
  const tx = Object.assign(
    (table: string) => {
      const query = {
        where: () => query,
        whereRaw: () => query,
        whereIn: () => query,
        select: () => query,
        orderBy: () => query,
        limit: () => Promise.resolve(rows[table])
      };
      return query;
    },
    { isTransaction: true }
  );
  return g2SnapshotDAL(tx as unknown as Knex.Transaction, async () => {});
};
const validRules: RawRule<[string, string]>[] = [
  { action: "read", subject: "secrets" },
  { action: "read", subject: "secrets", conditions: { environment: "prod" } },
  { action: "read", subject: "secrets", inverted: true },
  { action: "read", subject: "secrets", fields: ["key"] },
  { action: "read", subject: "secrets", reason: "synthetic" },
  {
    action: ["readValue", "readDescription"],
    subject: "secrets",
    conditions: { environment: G2.environmentSlug, secretPath: { $glob: G2.folderPath } }
  }
];
test.each(validRules.map((rule, index) => ({ rule, index })))(
  "shipped DAL accepts CASL packed rule shape $index without coercion",
  async ({ rule }) => {
    const result = await graphFixture(packRules([rule])).graph();
    expect(result.privileges).toHaveLength(1);
    expect(result.privileges[0].rules).toMatchObject([
      { ...rule, action: typeof rule.action === "string" ? [rule.action] : rule.action }
    ]);
  }
);
const malformedPacked: unknown[] = [
  null,
  {},
  "not-array",
  [null],
  [{}],
  [[]],
  [["read"]],
  [[0, "secrets"]],
  [["read", []]],
  [["read", "secrets", 0, 0]],
  [["read", "secrets", 0, 2, "key"]],
  [["read", "secrets", 0, 0, null]],
  [["read", "secrets", 0, 0, 0, null]],
  [["read", "secrets", 0, 0, 0, "reason", "extra"]]
];
test.each(malformedPacked.map((permissions, index) => ({ permissions, index })))(
  "shipped DAL refuses malformed packed permission payload $index",
  async ({ permissions }) => {
    await expect(graphFixture(permissions).graph()).rejects.toThrow("SCHEMA");
  }
);

test("DAL selected results retain concrete static types", () => {
  type Dal = ReturnType<typeof g2SnapshotDAL>;
  type Structure = Awaited<ReturnType<Dal["structure"]>>;
  expectTypeOf<Structure>().not.toBeAny();
  expectTypeOf<Structure["org"]>().not.toBeAny();
  expectTypeOf<Structure["org"]["id"]>().toEqualTypeOf<string>();
  expectTypeOf<Structure["org"]["enforceMfa"]>().toEqualTypeOf<boolean>();
  expectTypeOf<Structure["org"]["selectedMfaMethod"]>().toEqualTypeOf<string | null | undefined>();
  expectTypeOf<Awaited<ReturnType<Dal["actor"]>>["userId"]>().toEqualTypeOf<string>();
});
