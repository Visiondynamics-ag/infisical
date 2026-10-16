// This module is the shipped projection/guard contract, not a database simulator.
export const G2 = Object.freeze({
  orgId: "564dcab2-f448-4e6e-b108-a83c5b0dbf15",
  projectId: "a7adff21-8f8b-463a-a71a-274f0f53ff9b",
  projectSlug: "vd-ci",
  environmentId: "85b57a09-1895-456f-bd1b-8b85acbe9d1a",
  environmentSlug: "prod",
  folderId: "8255f749-7a6b-4366-a8bc-6916b7bf4d2f",
  folderPath: "/ci/woodpecker/agents/vd-infra",
  name: "management-woodpecker-vd-infra-agent",
  grantName: "vd-management-woodpecker-vd-infra-agent-read"
});
export const LIMITS = Object.freeze({ identities: 2, memberships: 64, roles: 128, privileges: 256, metadata: 32 });
export class SnapshotRefusal extends Error {
  readonly code: "SCOPE" | "CAP" | "SCHEMA" | "CONFLICT" | "AUTH" | "TRANSACTION" | "DEADLINE" | "INTERNAL";

  constructor(code: SnapshotRefusal["code"]) {
    super(code);
    this.code = code;
  }
}
export function requireSnapshot(condition: unknown, code: SnapshotRefusal["code"]): asserts condition {
  if (!condition) throw new SnapshotRefusal(code);
}
export function bounded<T>(rows: T[], limit: number): T[] {
  requireSnapshot(Array.isArray(rows) && rows.length <= limit, "CAP");
  return rows;
}
export function uuid(value: unknown): string {
  requireSnapshot(
    typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value),
    "SCHEMA"
  );
  return value;
}
// PostgreSQL selected nullable columns must be present: never turn undefined into null.
export function nullableString(value: unknown): string | null {
  requireSnapshot(value === null || typeof value === "string", "SCHEMA");
  return value;
}
export function uniqueIds(rows: { id: string }[]) {
  const ids = rows.map((r) => uuid(r.id));
  requireSnapshot(new Set(ids).size === ids.length, "SCHEMA");
}
export function checkTransaction(row: { recovery: boolean; isolation: string; readOnly: string; snapshot: string }) {
  requireSnapshot(
    row.recovery === false && row.isolation === "repeatable read" && row.readOnly === "on",
    "TRANSACTION"
  );
  requireSnapshot(typeof row.snapshot === "string" && /^\d+:\d+:(\d+(,\d+)*)?$/.test(row.snapshot), "TRANSACTION");
}
export type MembershipRow = {
  id: string;
  actorIdentityId: string | null;
  actorUserId: string | null;
  actorGroupId: string | null;
  scope: string;
  scopeOrgId: string;
  scopeProjectId: string | null;
  scopeResourceId: string | null;
  scopeResourceType: string | null;
  isActive: boolean;
};
export type RoleRow = {
  id: string;
  membershipId: string;
  role: string;
  customRoleId: string | null;
  isTemporary: boolean;
};
export type PrivilegeRow = {
  id: string;
  actorIdentityId: string | null;
  actorUserId: string | null;
  orgId: string | null;
  projectId: string | null;
  name: string;
  isTemporary: boolean;
  rules: unknown;
};
export type IdentityRow = { id: string; name: string; orgId: string; projectId: string | null };
export type Graph = {
  identities: IdentityRow[];
  memberships: MembershipRow[];
  roles: RoleRow[];
  privileges: PrivilegeRow[];
  metadataIds: { id: string }[];
};
const keysExactly = (value: unknown, keys: string[]): value is Record<string, unknown> =>
  Boolean(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).sort().join(",") === [...keys].sort().join(",")
  );
export function exactLeafRule(rules: unknown): boolean {
  if (!Array.isArray(rules) || rules.length !== 1) return false;
  const ruleRows: unknown[] = rules;
  const [r] = ruleRows;
  if (
    !keysExactly(r, ["action", "subject", "conditions"]) &&
    !(keysExactly(r, ["action", "subject", "conditions", "inverted"]) && r.inverted === false)
  )
    return false;
  if (r.subject !== "secrets" || !Array.isArray(r.action) || r.action.length !== 2) return false;
  const actions: unknown[] = r.action;
  if (
    !actions.every((action) => typeof action === "string") ||
    [...actions].sort().join(",") !== "describeSecret,readValue"
  )
    return false;
  const c = r.conditions;
  return (
    keysExactly(c, ["environment", "secretPath"]) &&
    keysExactly(c.environment, ["$eq"]) &&
    c.environment.$eq === G2.environmentSlug &&
    keysExactly(c.secretPath, ["$glob"]) &&
    c.secretPath.$glob === G2.folderPath
  );
}
export function projectGraph(graph: Graph) {
  bounded(graph.identities, LIMITS.identities);
  bounded(graph.memberships, LIMITS.memberships);
  bounded(graph.roles, LIMITS.roles);
  bounded(graph.privileges, LIMITS.privileges);
  bounded(graph.metadataIds, LIMITS.metadata);
  [graph.identities, graph.memberships, graph.roles, graph.privileges, graph.metadataIds].forEach(uniqueIds);
  requireSnapshot(graph.identities.length <= 1, "CONFLICT");
  const identity = graph.identities[0];
  if (!identity) {
    requireSnapshot(
      !graph.memberships.length && !graph.roles.length && !graph.privileges.length && !graph.metadataIds.length,
      "SCHEMA"
    );
    return {
      identityState: "ABSENT_AT_SNAPSHOT" as const,
      identityId: null,
      metadataRowCount: 0,
      memberships: [],
      privileges: []
    };
  }
  requireSnapshot(identity.orgId === G2.orgId && identity.projectId === null && identity.name === G2.name, "CONFLICT");
  const scopes = new Set<string>();
  const memberships = graph.memberships.map((m) => {
    requireSnapshot(m.actorIdentityId === identity.id && m.actorUserId === null && m.actorGroupId === null, "SCHEMA");
    requireSnapshot(
      m.scopeOrgId === G2.orgId &&
        m.scopeResourceId === null &&
        m.scopeResourceType === null &&
        ((m.scope === "organization" && m.scopeProjectId === null) ||
          (m.scope === "project" && m.scopeProjectId === G2.projectId)),
      "SCOPE"
    );
    requireSnapshot(!scopes.has(m.scope), "CONFLICT");
    scopes.add(m.scope);
    requireSnapshot(typeof m.isActive === "boolean", "SCHEMA");
    const roles = graph.roles
      .filter((r) => r.membershipId === m.id)
      .map((r) => {
        requireSnapshot(typeof r.isTemporary === "boolean", "SCHEMA");
        return {
          id: r.id,
          comparison:
            r.role === "no-access" && r.customRoleId === null && !r.isTemporary
              ? ("EXACT_NO_ACCESS" as const)
              : ("CONFLICT" as const),
          isTemporary: r.isTemporary
        };
      });
    return {
      id: m.id,
      scope: m.scope,
      orgId: G2.orgId,
      projectId: m.scopeProjectId,
      isActive: m.isActive,
      roles,
      comparison:
        m.isActive && roles.length === 1 && roles[0].comparison === "EXACT_NO_ACCESS"
          ? ("EXACT_NO_ACCESS" as const)
          : ("CONFLICT" as const)
    };
  });
  requireSnapshot(
    graph.roles.every((r) => graph.memberships.some((m) => m.id === r.membershipId)),
    "SCHEMA"
  );
  const privileges = graph.privileges.map((p) => {
    requireSnapshot(p.actorIdentityId === identity.id && p.actorUserId === null, "SCHEMA");
    requireSnapshot(
      (p.projectId === G2.projectId && p.orgId === null) || (p.orgId === G2.orgId && p.projectId === null),
      "SCOPE"
    );
    requireSnapshot(typeof p.isTemporary === "boolean", "SCHEMA");
    const membershipPresent = memberships.some((m) =>
      p.projectId ? m.projectId === p.projectId : m.scope === "organization"
    );
    return {
      id: p.id,
      orgId: p.orgId,
      projectId: p.projectId,
      isTemporary: p.isTemporary,
      membershipPresent,
      comparison:
        membershipPresent &&
        p.name === G2.grantName &&
        p.projectId === G2.projectId &&
        !p.isTemporary &&
        exactLeafRule(p.rules)
          ? ("EXACT_RULE" as const)
          : ("CONFLICT" as const)
    };
  });
  return {
    identityState: "PRESENT_AT_SNAPSHOT" as const,
    identityId: identity.id,
    metadataRowCount: graph.metadataIds.length,
    memberships,
    privileges
  };
}
export function serializeSnapshot(value: unknown): string {
  const serialized = JSON.stringify(value);
  requireSnapshot(Buffer.byteLength(serialized, "utf8") <= 65536, "CAP");
  return serialized;
}
