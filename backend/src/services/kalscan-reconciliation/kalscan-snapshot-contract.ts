import { bounded, LIMITS, requireSnapshot, uniqueIds } from "../g2-reconciliation/g2-snapshot-contract";

export {
  bounded,
  checkTransaction,
  LIMITS,
  nullableString,
  requireSnapshot,
  serializeSnapshot,
  SnapshotRefusal,
  uuid
} from "../g2-reconciliation/g2-snapshot-contract";

// This module is the shipped projection/guard contract, not a database simulator.
export const KALSCAN = Object.freeze({
  orgId: "564dcab2-f448-4e6e-b108-a83c5b0dbf15",
  projectId: "fdeef73f-8a71-4310-9036-c3c35ed36dca",
  projectSlug: "kalvora",
  environmentId: "e76e88a0-952f-4b47-9b42-528cfdd9cbc0",
  environmentSlug: "prod",
  folderId: "d1e43adf-a4e6-4e5b-b183-3b3b6d718eda",
  folderPath: "/scan/runtime",
  name: "kalscan-prod-runtime",
  identityId: "7191dd8e-9d34-459a-a9a1-39e14cc2c514",
  grantName: "vd-kalscan-prod-runtime-read"
});
const G2 = KALSCAN;
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
export type IdentityRow = {
  id: string;
  name: string;
  orgId: string;
  projectId: string | null;
};
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
  // The historical returned UUID is an equality constraint, never absence/create authority.
  requireSnapshot(graph.identities.length === 1, "CONFLICT");
  const identity = graph.identities[0];
  requireSnapshot(
    identity.id === KALSCAN.identityId &&
      identity.orgId === G2.orgId &&
      identity.projectId === null &&
      identity.name === G2.name,
    "CONFLICT"
  );
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
