import type { RawRule } from "@casl/ability";
import type { PackRule } from "@casl/ability/extra";
import { unpackRules } from "@casl/ability/extra";
import type { Knex } from "knex";

import {
  TableName,
  type TAuthTokenSessions,
  type TOrganizations,
  type TProjectEnvironments,
  type TProjects,
  type TSecretFolders,
  type TUsers
} from "@app/db/schemas";

import {
  bounded,
  G2,
  Graph,
  type IdentityRow,
  LIMITS,
  type MembershipRow,
  nullableString,
  type PrivilegeRow,
  requireSnapshot,
  type RoleRow,
  uuid
} from "./g2-snapshot-contract";
import { requireSnapshotMfa } from "./g2-snapshot-mfa";

type StructureRows = {
  [TableName.Organization]: Pick<
    TOrganizations,
    "id" | "rootOrgId" | "parentOrgId" | "enforceMfa" | "selectedMfaMethod" | "shouldUseNewPrivilegeSystem"
  >;
  [TableName.Project]: Pick<TProjects, "id" | "orgId" | "slug" | "type" | "deleteAfter">;
  [TableName.Environment]: Pick<TProjectEnvironments, "id" | "projectId" | "slug" | "deleteAfter">;
  [TableName.SecretFolder]: Pick<TSecretFolders, "id" | "envId" | "name" | "parentId">;
  [TableName.AuthTokenSession]: Pick<TAuthTokenSessions, "id" | "userId" | "accessVersion">;
  [TableName.Users]: Pick<
    TUsers,
    "id" | "isAccepted" | "isLocked" | "temporaryLockDateEnd" | "isMfaEnabled" | "selectedMfaMethod"
  >;
};
type ActorMembership = { id: string; scope: string; scopeProjectId: string | null; status: string; isActive: boolean };
type PackedReadRule = PackRule<RawRule<[string, string]>>;
const isPackedReadRule = (value: unknown): value is PackedReadRule => {
  if (!Array.isArray(value)) return false;
  const row: unknown[] = value;
  if (row.length < 2 || row.length > 6 || typeof row[0] !== "string" || typeof row[1] !== "string") return false;
  if (row.length === 4 && row[3] !== 1) return false;
  if (row.length >= 5 && row[3] !== 0 && row[3] !== 1) return false;
  if (row.length === 5 && typeof row[4] !== "string") return false;
  if (row.length === 6 && ((row[4] !== 0 && typeof row[4] !== "string") || typeof row[5] !== "string")) return false;
  return true;
};

// No default connection, ORM, replica selector, credential table or write method.
export const g2SnapshotDAL = (tx: Knex.Transaction, checkpoint: () => Promise<void>) => {
  requireSnapshot(tx.isTransaction, "TRANSACTION");
  const one = async <K extends keyof StructureRows>(
    table: K,
    filter: Record<string, string>,
    columns: (keyof StructureRows[K] & string)[]
  ): Promise<StructureRows[K]> => {
    await checkpoint();
    const rows = await tx<StructureRows[K], StructureRows[K][]>(table).where(filter).select(columns).limit(2);
    requireSnapshot(rows.length === 1, "SCOPE");
    return rows[0];
  };
  const structure = async () => {
    const org = await one(TableName.Organization, { id: G2.orgId }, [
      "id",
      "rootOrgId",
      "parentOrgId",
      "enforceMfa",
      "selectedMfaMethod",
      "shouldUseNewPrivilegeSystem"
    ]);
    // Child/inherited organization policy is deliberately unsupported by this fixed route.
    requireSnapshot(!org.rootOrgId && !org.parentOrgId && org.shouldUseNewPrivilegeSystem === true, "SCOPE");
    const project = await one(TableName.Project, { id: G2.projectId }, ["id", "orgId", "slug", "type", "deleteAfter"]);
    requireSnapshot(
      project.orgId === G2.orgId &&
        project.slug === G2.projectSlug &&
        project.type === "secret-manager" &&
        project.deleteAfter === null,
      "SCOPE"
    );
    const env = await one(TableName.Environment, { id: G2.environmentId }, ["id", "projectId", "slug", "deleteAfter"]);
    requireSnapshot(
      env.projectId === G2.projectId && env.slug === G2.environmentSlug && env.deleteAfter === null,
      "SCOPE"
    );
    const folders: { id: string; parentId: string | null }[] = [];
    let { folderId }: { folderId: string | null } = G2;
    const names = [...G2.folderPath.split("/").filter(Boolean)].reverse();
    await names.reduce<Promise<void>>(async (previous, name) => {
      await previous;
      requireSnapshot(folderId, "SCOPE");
      const f = await one(TableName.SecretFolder, { id: folderId }, ["id", "envId", "name", "parentId"]);
      requireSnapshot(f.envId === G2.environmentId && f.name === name, "SCOPE");
      const parentId = uuid(f.parentId);
      folders.push({ id: uuid(f.id), parentId });
      folderId = parentId;
    }, Promise.resolve());
    requireSnapshot(folderId, "SCOPE");
    const root = await one(TableName.SecretFolder, { id: folderId }, ["id", "envId", "parentId"]);
    requireSnapshot(root.envId === G2.environmentId && root.parentId === null, "SCOPE");
    folders.push({ id: uuid(root.id), parentId: null });
    requireSnapshot(new Set(folders.map((f) => f.id)).size === folders.length, "SCOPE");
    return { org, folders };
  };
  const actor = async (
    userId: string,
    sessionId: string,
    accessVersion: number,
    isMfaVerified: boolean,
    mfaMethod: string | undefined,
    org: Parameters<typeof requireSnapshotMfa>[0]
  ) => {
    const session = await one(TableName.AuthTokenSession, { id: uuid(sessionId), userId: uuid(userId) }, [
      "id",
      "userId",
      "accessVersion"
    ]);
    requireSnapshot(session.accessVersion === accessVersion, "AUTH");
    const user = await one(TableName.Users, { id: userId }, [
      "id",
      "isAccepted",
      "isLocked",
      "temporaryLockDateEnd",
      "isMfaEnabled",
      "selectedMfaMethod"
    ]);
    requireSnapshot(
      user.isAccepted === true &&
        !user.isLocked &&
        (!user.temporaryLockDateEnd || new Date(user.temporaryLockDateEnd).getTime() <= Date.now()),
      "AUTH"
    );
    requireSnapshotMfa(org, user, isMfaVerified, mfaMethod);
    await checkpoint();
    requireSnapshot(
      (await tx<{ id: string }>(TableName.UserGroupMembership).where({ userId }).select("id").limit(1)).length === 0,
      "AUTH"
    );
    await checkpoint();
    const memberships = bounded(
      await tx<ActorMembership>(TableName.Membership)
        .where({ actorUserId: userId, scopeOrgId: G2.orgId })
        .select("id", "scope", "scopeProjectId", "status", "isActive")
        .limit(65),
      64
    );
    const orgMemberships = memberships.filter((m) => m.scope === "organization");
    const projectMemberships = memberships.filter((m) => m.scope === "project" && m.scopeProjectId === G2.projectId);
    requireSnapshot(
      orgMemberships.length === 1 &&
        orgMemberships[0].isActive === true &&
        orgMemberships[0].status === "accepted" &&
        projectMemberships.length === 1 &&
        projectMemberships[0].isActive === true,
      "AUTH"
    );
    const ids = [orgMemberships[0].id, projectMemberships[0].id];
    await checkpoint();
    bounded(
      await tx<{ id: string; membershipId: string }>(TableName.MembershipRole)
        .whereIn("membershipId", ids)
        .select("id")
        .limit(33),
      32
    );
    await checkpoint();
    bounded(
      await tx<{ id: string; actorUserId: string }>(TableName.AdditionalPrivilege)
        .where({ actorUserId: userId })
        .select("id")
        .limit(33),
      32
    );
    await checkpoint();
    bounded(
      await tx<{ id: string; userId: string; orgId: string }>(TableName.IdentityMetadata)
        .where({ userId, orgId: G2.orgId })
        .select("id")
        .limit(33),
      32
    );
    return { userId, orgMembershipId: uuid(orgMemberships[0].id), projectMembershipId: uuid(projectMemberships[0].id) };
  };
  const graph = async (): Promise<Graph> => {
    await checkpoint();
    const identities = bounded(
      await tx<IdentityRow>(TableName.Identity)
        .where({ orgId: G2.orgId })
        .whereRaw('lower("name" COLLATE "C") = ?', [G2.name])
        .select("id", "name", "orgId", "projectId")
        .orderBy("id")
        .limit(LIMITS.identities + 1),
      LIMITS.identities
    ).map((row) => ({ ...row, projectId: nullableString(row.projectId) }));
    // Reject collisions before any fanout; no name-only selection or silent UUID choice.
    requireSnapshot(
      identities.length <= 1 && identities.every((i) => i.name === G2.name && i.projectId === null),
      "CONFLICT"
    );
    if (!identities.length) return { identities, memberships: [], roles: [], privileges: [], metadataIds: [] };
    const id = uuid(identities[0].id);
    await checkpoint();
    const memberships = bounded(
      await tx<MembershipRow>(TableName.Membership)
        .where({ actorIdentityId: id })
        .select(
          "id",
          "actorIdentityId",
          "actorUserId",
          "actorGroupId",
          "scope",
          "scopeOrgId",
          "scopeProjectId",
          "scopeResourceId",
          "scopeResourceType",
          "isActive"
        )
        .orderBy("id")
        .limit(LIMITS.memberships + 1),
      LIMITS.memberships
    ).map((row) => ({
      ...row,
      actorIdentityId: nullableString(row.actorIdentityId),
      actorUserId: nullableString(row.actorUserId),
      actorGroupId: nullableString(row.actorGroupId),
      scopeProjectId: nullableString(row.scopeProjectId),
      scopeResourceId: nullableString(row.scopeResourceId),
      scopeResourceType: nullableString(row.scopeResourceType)
    }));
    await checkpoint();
    const roles = bounded(
      await tx<RoleRow>(TableName.MembershipRole)
        .whereIn(
          "membershipId",
          memberships.map((m) => m.id)
        )
        .select("id", "membershipId", "role", "customRoleId", "isTemporary")
        .orderBy("id")
        .limit(LIMITS.roles + 1),
      LIMITS.roles
    ).map((row) => ({ ...row, customRoleId: nullableString(row.customRoleId) }));
    await checkpoint();
    const privileges = bounded(
      await tx<Omit<PrivilegeRow, "rules"> & { permissions: unknown }>(TableName.AdditionalPrivilege)
        .where({ actorIdentityId: id })
        .select("id", "actorIdentityId", "actorUserId", "orgId", "projectId", "name", "isTemporary", "permissions")
        .orderBy("id")
        .limit(LIMITS.privileges + 1),
      LIMITS.privileges
    );
    await checkpoint();
    const metadataIds = bounded(
      await tx<{ id: string; identityId: string }>(TableName.IdentityMetadata)
        .where({ identityId: id })
        .select("id")
        .orderBy("id")
        .limit(LIMITS.metadata + 1),
      LIMITS.metadata
    );
    return {
      identities,
      memberships,
      roles,
      metadataIds,
      privileges: privileges.map((p) => {
        requireSnapshot(Array.isArray(p.permissions), "SCHEMA");
        const packed: unknown[] = p.permissions;
        requireSnapshot(packed.every(isPackedReadRule), "SCHEMA");
        const rules = unpackRules<RawRule<[string, string]>>(packed).map((rule) => ({
          ...rule,
          subject: Array.isArray(rule.subject) && rule.subject.length === 1 ? rule.subject[0] : rule.subject
        }));
        return {
          ...p,
          rules,
          actorIdentityId: nullableString(p.actorIdentityId),
          actorUserId: nullableString(p.actorUserId),
          orgId: nullableString(p.orgId),
          projectId: nullableString(p.projectId)
        };
      })
    };
  };
  return { structure, actor, graph };
};
