import { unpackRules } from "@casl/ability/extra";
import type { Knex } from "knex";

import { TableName } from "@app/db/schemas";

import { bounded, G2, Graph, LIMITS, nullableString, requireSnapshot, uuid } from "./g2-snapshot-contract";
import { requireSnapshotMfa } from "./g2-snapshot-mfa";

// No default connection, ORM, replica selector, credential table or write method.
export const g2SnapshotDAL = (tx: Knex.Transaction, checkpoint: () => Promise<void>) => {
  requireSnapshot(tx.isTransaction, "TRANSACTION");
  const one = async (table: TableName, filter: Record<string, string>, columns: string[]) => {
    await checkpoint();
    const rows = await tx(table).where(filter).select(columns).limit(2);
    requireSnapshot(rows.length === 1, "SCOPE");
    return rows[0];
  };
  const structure = async () => {
    const org = await one(TableName.Organization, { id: G2.orgId }, ["id", "rootOrgId", "parentOrgId", "enforceMfa", "selectedMfaMethod", "shouldUseNewPrivilegeSystem"]);
    // Child/inherited organization policy is deliberately unsupported by this fixed route.
    requireSnapshot(!org.rootOrgId && !org.parentOrgId && org.shouldUseNewPrivilegeSystem === true, "SCOPE");
    const project = await one(TableName.Project, { id: G2.projectId }, ["id", "orgId", "slug", "type", "deleteAfter"]);
    requireSnapshot(project.orgId === G2.orgId && project.slug === G2.projectSlug && project.type === "secret-manager" && project.deleteAfter === null, "SCOPE");
    const env = await one(TableName.Environment, { id: G2.environmentId }, ["id", "projectId", "slug", "deleteAfter"]);
    requireSnapshot(env.projectId === G2.projectId && env.slug === G2.environmentSlug && env.deleteAfter === null, "SCOPE");
    const folders: { id: string; parentId: string | null }[] = [];
    let folderId: string | null = G2.folderId;
    const names = [...G2.folderPath.split("/").filter(Boolean)].reverse();
    for (const name of names) {
      requireSnapshot(folderId, "SCOPE");
      const f = await one(TableName.SecretFolder, { id: folderId }, ["id", "envId", "name", "parentId"]);
      requireSnapshot(f.envId === G2.environmentId && f.name === name, "SCOPE");
      uuid(f.id); uuid(f.parentId); folders.push({ id: f.id, parentId: f.parentId }); folderId = f.parentId;
    }
    requireSnapshot(folderId, "SCOPE");
    const root = await one(TableName.SecretFolder, { id: folderId }, ["id", "envId", "parentId"]);
    requireSnapshot(root.envId === G2.environmentId && root.parentId === null, "SCOPE");
    folders.push({ id: uuid(root.id), parentId: null });
    requireSnapshot(new Set(folders.map((f) => f.id)).size === folders.length, "SCOPE");
    return { org, folders };
  };
  const actor = async (userId: string, sessionId: string, accessVersion: number, isMfaVerified: boolean, mfaMethod: string | undefined, org: { enforceMfa: boolean; selectedMfaMethod: string | null }) => {
    const session = await one(TableName.AuthTokenSession, { id: uuid(sessionId), userId: uuid(userId) }, ["id", "userId", "accessVersion"]);
    requireSnapshot(session.accessVersion === accessVersion, "AUTH");
    const user = await one(TableName.Users, { id: userId }, ["id", "isAccepted", "isLocked", "temporaryLockDateEnd", "isMfaEnabled", "selectedMfaMethod"]);
    requireSnapshot(user.isAccepted === true && !user.isLocked && (!user.temporaryLockDateEnd || new Date(user.temporaryLockDateEnd).getTime() <= Date.now()), "AUTH");
    requireSnapshotMfa(org, user, isMfaVerified, mfaMethod);
    await checkpoint();
    requireSnapshot((await tx(TableName.UserGroupMembership).where({ userId }).select("id").limit(1)).length === 0, "AUTH");
    await checkpoint();
    const memberships = bounded(await tx(TableName.Membership).where({ actorUserId: userId, scopeOrgId: G2.orgId }).select("id", "scope", "scopeProjectId", "status", "isActive").limit(65), 64);
    const orgMemberships = memberships.filter((m) => m.scope === "organization");
    const projectMemberships = memberships.filter((m) => m.scope === "project" && m.scopeProjectId === G2.projectId);
    requireSnapshot(orgMemberships.length === 1 && orgMemberships[0].isActive === true && orgMemberships[0].status === "accepted" && projectMemberships.length === 1 && projectMemberships[0].isActive === true, "AUTH");
    const ids = [orgMemberships[0].id, projectMemberships[0].id];
    await checkpoint();
    bounded(await tx(TableName.MembershipRole).whereIn("membershipId", ids).select("id").limit(33), 32);
    await checkpoint();
    bounded(await tx(TableName.AdditionalPrivilege).where({ actorUserId: userId }).select("id").limit(33), 32);
    await checkpoint();
    bounded(await tx(TableName.IdentityMetadata).where({ userId, orgId: G2.orgId }).select("id").limit(33), 32);
    return { userId, orgMembershipId: uuid(orgMemberships[0].id), projectMembershipId: uuid(projectMemberships[0].id) };
  };
  const graph = async (): Promise<Graph> => {
    await checkpoint();
    const identities = bounded(await tx(TableName.Identity).where({ orgId: G2.orgId })
      .whereRaw('lower("name" COLLATE "C") = ?', [G2.name])
      .select("id", "name", "orgId", "projectId").orderBy("id").limit(LIMITS.identities + 1), LIMITS.identities)
      .map((row) => ({ ...row, projectId: nullableString(row.projectId) }));
    // Reject collisions before any fanout; no name-only selection or silent UUID choice.
    requireSnapshot(identities.length <= 1 && identities.every((i) => i.name === G2.name && i.projectId === null), "CONFLICT");
    if (!identities.length) return { identities, memberships: [], roles: [], privileges: [], metadataIds: [] };
    const id = uuid(identities[0].id);
    await checkpoint();
    const memberships = bounded(await tx(TableName.Membership).where({ actorIdentityId: id }).select("id", "actorIdentityId", "actorUserId", "actorGroupId", "scope", "scopeOrgId", "scopeProjectId", "scopeResourceId", "scopeResourceType", "isActive").orderBy("id").limit(LIMITS.memberships + 1), LIMITS.memberships).map((row) => ({ ...row,
      actorIdentityId: nullableString(row.actorIdentityId), actorUserId: nullableString(row.actorUserId),
      actorGroupId: nullableString(row.actorGroupId), scopeProjectId: nullableString(row.scopeProjectId),
      scopeResourceId: nullableString(row.scopeResourceId), scopeResourceType: nullableString(row.scopeResourceType) }));
    await checkpoint();
    const roles = bounded(await tx(TableName.MembershipRole).whereIn("membershipId", memberships.map((m) => m.id)).select("id", "membershipId", "role", "customRoleId", "isTemporary").orderBy("id").limit(LIMITS.roles + 1), LIMITS.roles).map((row) => ({ ...row, customRoleId: nullableString(row.customRoleId) }));
    await checkpoint();
    const privileges = bounded(await tx(TableName.AdditionalPrivilege).where({ actorIdentityId: id }).select("id", "actorIdentityId", "actorUserId", "orgId", "projectId", "name", "isTemporary", "permissions").orderBy("id").limit(LIMITS.privileges + 1), LIMITS.privileges);
    await checkpoint();
    const metadataIds = bounded(await tx(TableName.IdentityMetadata).where({ identityId: id }).select("id").orderBy("id").limit(LIMITS.metadata + 1), LIMITS.metadata);
    return { identities, memberships, roles, metadataIds, privileges: privileges.map((p) => {
      requireSnapshot(Array.isArray(p.permissions), "SCHEMA");
      const rules = unpackRules(p.permissions as Parameters<typeof unpackRules>[0]).map((rule) => ({ ...rule,
        subject: Array.isArray(rule.subject) && rule.subject.length === 1 ? rule.subject[0] : rule.subject }));
      return { ...p, rules, actorIdentityId: nullableString(p.actorIdentityId), actorUserId: nullableString(p.actorUserId),
        orgId: nullableString(p.orgId), projectId: nullableString(p.projectId) };
    }) };
  };
  return { structure, actor, graph };
};
