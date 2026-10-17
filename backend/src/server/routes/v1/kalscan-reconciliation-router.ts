import type { Knex } from "knex";
import { z } from "zod";

import type { TPermissionServiceFactory } from "@app/ee/services/permission/permission-service-types";
import { readLimit } from "@app/server/config/rateLimiter";
import { verifyAuth } from "@app/server/plugins/auth/verify-auth";
import { ActorType, AuthMode } from "@app/services/auth/auth-type";
import { SnapshotRefusal } from "@app/services/g2-reconciliation/g2-snapshot-contract";
import { kalscanSnapshotService } from "@app/services/kalscan-reconciliation/kalscan-snapshot-service";

const id = z.string().uuid();
const role = z
  .object({
    id,
    comparison: z.enum(["EXACT_NO_ACCESS", "CONFLICT"]),
    isTemporary: z.boolean()
  })
  .strict();
const response = z
  .object({
    state: z.literal("SNAPSHOT_COMPLETE_FOR_FIXED_RECONCILIATION_GRAPH"),
    nonce: z.string().regex(/^[0-9a-f]{64}$/),
    startedAt: z.string().datetime(),
    snapshotFinishedAt: z.string().datetime(),
    transaction: z
      .object({
        recovery: z.literal(false),
        isolation: z.literal("repeatable read"),
        readOnly: z.literal("on"),
        snapshot: z.string().max(4096)
      })
      .strict(),
    scope: z
      .object({
        orgId: z.literal("564dcab2-f448-4e6e-b108-a83c5b0dbf15"),
        projectId: z.literal("fdeef73f-8a71-4310-9036-c3c35ed36dca"),
        environmentId: z.literal("e76e88a0-952f-4b47-9b42-528cfdd9cbc0"),
        folderId: z.literal("d1e43adf-a4e6-4e5b-b183-3b3b6d718eda"),
        folderPath: z.literal("/scan/runtime")
      })
      .strict(),
    actor: z.object({ userId: id, orgMembershipId: id, projectMembershipId: id }).strict(),
    folders: z.array(z.object({ id, parentId: id.nullable() }).strict()).length(3),
    graph: z
      .object({
        identityState: z.literal("PRESENT_AT_SNAPSHOT"),
        identityId: z.literal("7191dd8e-9d34-459a-a9a1-39e14cc2c514"),
        metadataRowCount: z.number().int().min(0).max(32),
        memberships: z
          .array(
            z
              .object({
                id,
                scope: z.enum(["organization", "project"]),
                orgId: id,
                projectId: id.nullable(),
                isActive: z.boolean(),
                roles: z.array(role).max(128),
                comparison: z.enum(["EXACT_NO_ACCESS", "CONFLICT"])
              })
              .strict()
          )
          .max(64),
        privileges: z
          .array(
            z
              .object({
                id,
                orgId: id.nullable(),
                projectId: id.nullable(),
                isTemporary: z.boolean(),
                membershipPresent: z.boolean(),
                comparison: z.enum(["EXACT_RULE", "CONFLICT"])
              })
              .strict()
          )
          .max(256)
      })
      .strict(),
    executionAllowed: z.literal(false),
    credentialIssuance: z.literal(false),
    deliveryAllowed: z.literal(false),
    inverseQualified: z.literal(false)
  })
  .strict();
const refusal = z
  .object({
    state: z.literal("REFUSED"),
    code: z.enum(["SCOPE", "CAP", "SCHEMA", "CONFLICT", "AUTH", "TRANSACTION", "DEADLINE", "INTERNAL"])
  })
  .strict();
export const registerKalscanReconciliationRouter = async (
  server: FastifyZodProvider,
  options: { db: Knex; permissionService: TPermissionServiceFactory }
) => {
  const collect = kalscanSnapshotService(options.db, options.permissionService);
  server.route({
    method: "GET",
    url: "/organization/identities/reconciliation-snapshots/kalscan-prod-runtime",
    config: { rateLimit: readLimit },
    onRequest: verifyAuth([AuthMode.JWT]),
    schema: {
      hide: true,
      querystring: z.object({}).strict(),
      headers: z
        .object({
          "x-vd-reconciliation-nonce": z.string().regex(/^[0-9a-f]{64}$/)
        })
        .passthrough(),
      response: { 200: response, 409: refusal }
    },
    handler: async (req, reply) => {
      void reply.header("Cache-Control", "no-store");
      if (
        req.body !== undefined ||
        req.auth.authMode !== AuthMode.JWT ||
        req.auth.actor !== ActorType.USER ||
        req.cookies["infisical-project-assume-privileges"]
      ) {
        return reply.code(409).send({ state: "REFUSED", code: "AUTH" });
      }
      try {
        const result = await collect(
          req.auth.token,
          req.headers["x-vd-reconciliation-nonce"],
          () => req.raw.aborted || reply.raw.destroyed
        );
        return response.parse(result);
      } catch (error) {
        return reply.code(409).send({
          state: "REFUSED",
          code: error instanceof SnapshotRefusal ? error.code : "INTERNAL"
        });
      }
    }
  });
};
