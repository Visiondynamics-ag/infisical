import { performance } from "node:perf_hooks";

import { requestContext } from "@fastify/request-context";
import type { Knex } from "knex";

import { ActionProjectType, OrganizationActionScope, OrgMembershipRole } from "@app/db/schemas";
import { OrgPermissionIdentityActions, OrgPermissionSubjects } from "@app/ee/services/permission/org-permission";
import type { TPermissionServiceFactory } from "@app/ee/services/permission/permission-service-types";
import {
  ProjectPermissionActions,
  ProjectPermissionIdentityActions,
  ProjectPermissionSub
} from "@app/ee/services/permission/project-permission";
import { RequestContextKey } from "@app/lib/request-context/request-context-keys";
import type { AuthModeJwtTokenPayload } from "@app/services/auth/auth-type";
import { ActorType } from "@app/services/auth/auth-type";

import { withSnapshotConnection } from "../g2-reconciliation/g2-snapshot-connection";
import {
  checkTransaction,
  KALSCAN as G2,
  projectGraph,
  requireSnapshot,
  serializeSnapshot,
  SnapshotRefusal
} from "./kalscan-snapshot-contract";
import { kalscanSnapshotDAL } from "./kalscan-snapshot-dal";
import { requireUaMetadataAuthorization } from "./kalscan-ua-metadata-authorization";
import { readKalscanUaMetadata } from "./kalscan-ua-metadata-dal";

// A conditional read rule cannot certify an unfiltered finite inventory. Keep CASL's
// denial precedence, then refuse conditions/field restrictions rather than flatten them.
const requireUnrestrictedRead = (
  ability: {
    can: (action: never, subject: never) => boolean;
    rules: readonly {
      subject?: unknown;
      action?: unknown;
      conditions?: unknown;
      fields?: unknown;
    }[];
  },
  subject: string
) => {
  const matches = (value: unknown, key: string) => value === key || (Array.isArray(value) && value.includes(key));
  requireSnapshot(ability.can("read" as never, subject as never), "AUTH");
  requireSnapshot(
    !ability.rules.some(
      (r) =>
        (matches(r.subject, subject) || matches(r.subject, "all")) &&
        (matches(r.action, "read") || matches(r.action, "manage")) &&
        (r.conditions || r.fields)
    ),
    "AUTH"
  );
};

export const kalscanUaMetadataSnapshotService = (
  db: Knex,
  permission: Pick<
    TPermissionServiceFactory,
    "getOrgPermission" | "getProjectPermission" | "getFixedKalscanIdentityOrgSnapshotPermission"
  >
) => {
  return async (token: AuthModeJwtTokenPayload & { exp?: unknown }, nonce: string, cancelled: () => boolean) => {
    const started = performance.now();
    const startedAt = new Date().toISOString();
    const check = () => {
      requireSnapshot(!cancelled() && performance.now() - started < 15000, "DEADLINE");
      requireSnapshot(
        typeof token.exp === "number" && Number.isSafeInteger(token.exp) && token.exp * 1000 > Date.now(),
        "AUTH"
      );
    };
    try {
      requireSnapshot(
        /^[0-9a-f]{64}$/.test(nonce) &&
          token.authTokenType === "accessToken" &&
          token.organizationId === G2.orgId &&
          (!token.subOrganizationId || token.subOrganizationId === G2.orgId) &&
          !token.oauthClientId &&
          !token.mcp &&
          !token.scopes,
        "AUTH"
      );
      requireSnapshot(
        !requestContext.get(RequestContextKey.AssumedPrivilegeDetails) &&
          !requestContext.get(RequestContextKey.OauthScopes),
        "AUTH"
      );
      check();
      const result = await withSnapshotConnection(db, started + 15000, check, (connection, guard) =>
        db.transaction(
          async (tx) => {
            // Private transaction client only: after stop, no further application SQL
            // or COMMIT is submitted. ROLLBACK remains available for cleanup.
            // Pinned Knex declares client as any; narrow only the private query seam.
            const candidate: unknown = tx.client;
            requireSnapshot(
              typeof candidate === "object" &&
                candidate !== null &&
                "query" in candidate &&
                typeof candidate.query === "function",
              "TRANSACTION"
            );
            const transactionClient = candidate as {
              query: (conn: unknown, statement: string | { sql: string }) => Promise<unknown>;
            };
            const query = transactionClient.query.bind(transactionClient);
            transactionClient.query = (conn: unknown, statement: string | { sql: string }) => {
              try {
                if ((typeof statement === "string" ? statement : statement.sql) !== "ROLLBACK") guard();
              } catch (error) {
                return Promise.reject(error);
              }
              return query(conn, statement);
            };
            check();
            // First statement after BEGIN. No snapshot or permission read precedes it.
            await tx.raw("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
            const checkpoint = async () => {
              check();
              const remaining = Math.max(1, Math.min(2000, Math.floor(15000 - (performance.now() - started))));
              await tx.raw("SELECT set_config('statement_timeout', ?, true)", [`${remaining}ms`]);
            };
            await checkpoint();
            const properties = await tx.raw<{
              rows: {
                recovery: boolean;
                isolation: string;
                readOnly: string;
                snapshot: string;
              }[];
            }>(
              "SELECT pg_is_in_recovery() AS recovery, current_setting('transaction_isolation') AS isolation, current_setting('transaction_read_only') AS \"readOnly\", txid_current_snapshot()::text AS snapshot"
            );
            requireSnapshot(properties.rows.length === 1, "TRANSACTION");
            const transaction = properties.rows[0];
            checkTransaction(transaction);
            const dal = kalscanSnapshotDAL(tx, checkpoint);
            const { org, folders } = await dal.structure();
            const actor = await dal.actor(
              token.userId,
              token.tokenVersionId,
              token.accessVersion,
              token.isMfaVerified === true,
              token.mfaMethod,
              org
            );
            await checkpoint();
            const orgPermission = await permission.getOrgPermission({
              actor: ActorType.USER,
              actorId: token.userId,
              actorOrgId: G2.orgId,
              actorAuthMethod: token.authMethod,
              orgId: G2.orgId,
              scope: OrganizationActionScope.Any,
              snapshotTx: tx
            });
            // The extra org-admin requirement authorizes detection (never disclosure) of an
            // org-owned identity's unexpected destinations. A badge alone is insufficient.
            requireSnapshot(orgPermission.hasRole(OrgMembershipRole.Admin), "AUTH");
            requireSnapshot(
              orgPermission.permission.can(OrgPermissionIdentityActions.Read, OrgPermissionSubjects.Identity),
              "AUTH"
            );
            requireUnrestrictedRead(orgPermission.permission, OrgPermissionSubjects.Identity);
            await checkpoint();
            const projectPermission = await permission.getProjectPermission({
              actor: ActorType.USER,
              actorId: token.userId,
              actorOrgId: G2.orgId,
              actorAuthMethod: token.authMethod,
              projectId: G2.projectId,
              actionProjectType: ActionProjectType.SecretManager,
              snapshotTx: tx
            });
            requireSnapshot(
              projectPermission.permission.can(ProjectPermissionIdentityActions.Read, ProjectPermissionSub.Identity) &&
                projectPermission.permission.can(ProjectPermissionActions.Read, ProjectPermissionSub.Environments) &&
                projectPermission.permission.can(ProjectPermissionActions.Read, ProjectPermissionSub.SecretFolders),
              "AUTH"
            );
            [
              ProjectPermissionSub.Identity,
              ProjectPermissionSub.Environments,
              ProjectPermissionSub.SecretFolders
            ].forEach((s) => requireUnrestrictedRead(projectPermission.permission, s));
            const graph = projectGraph(await dal.graph());
            await checkpoint();
            const targetPermission = await permission.getFixedKalscanIdentityOrgSnapshotPermission({
              snapshotTx: tx,
              actorAuthMethod: token.authMethod
            });
            requireUaMetadataAuthorization(
              orgPermission.permission,
              targetPermission.permission,
              org.shouldUseNewPrivilegeSystem
            );
            const uaMetadata = await readKalscanUaMetadata(tx, checkpoint);
            check();
            const response = {
              state: "UA_METADATA_SNAPSHOT_COMPLETE_FOR_FIXED_IDENTITY" as const,
              nonce,
              startedAt,
              snapshotFinishedAt: new Date().toISOString(),
              transaction: {
                recovery: false as const,
                isolation: "repeatable read" as const,
                readOnly: "on" as const,
                snapshot: transaction.snapshot
              },
              scope: {
                orgId: G2.orgId,
                projectId: G2.projectId,
                environmentId: G2.environmentId,
                folderId: G2.folderId,
                folderPath: G2.folderPath
              },
              actor,
              folders,
              graph,
              ...uaMetadata,
              credentialLivenessQualified: false as const,
              networkBoundaryQualified: false as const,
              executionAllowed: false as const,
              credentialIssuance: false as const,
              deliveryAllowed: false as const,
              inverseQualified: false as const
            };
            serializeSnapshot(response);
            return response;
          },
          { connection }
        )
      );
      check(); // Expiry/deadline after COMMIT also discards the entire projection.
      return result;
    } catch (error) {
      // No original database/permission error or arbitrary values are exported/logged.
      throw new SnapshotRefusal(error instanceof SnapshotRefusal ? error.code : "INTERNAL");
    }
  };
};
