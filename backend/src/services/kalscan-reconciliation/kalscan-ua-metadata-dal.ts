import type { Knex } from "knex";

import { TableName } from "@app/db/schemas";

import { KALSCAN, requireSnapshot } from "./kalscan-snapshot-contract";
import {
  CLIENT_SECRET_METADATA_COLUMNS,
  MAX_CLIENT_SECRET_METADATA,
  projectClientSecretMetadata,
  projectUaConfigMetadata,
  UA_METADATA_COLUMNS
} from "./kalscan-ua-metadata-contract";

type UaMetadataRow = Record<(typeof UA_METADATA_COLUMNS)[number], unknown>;
type ClientSecretMetadataRow = Record<(typeof CLIENT_SECRET_METADATA_COLUMNS)[number], unknown>;
export const readKalscanUaMetadata = async (tx: Knex.Transaction, checkpoint: () => Promise<void>) => {
  requireSnapshot(tx.isTransaction, "TRANSACTION");
  await checkpoint();
  const rows = await tx<UaMetadataRow, UaMetadataRow[]>(TableName.IdentityUniversalAuth)
    .where({ identityId: KALSCAN.identityId })
    .select(...UA_METADATA_COLUMNS)
    .orderBy("id")
    .limit(2);
  // Absence is a refusal, never credential issuance or auth-attachment authority.
  requireSnapshot(rows.length === 1, "SCOPE");
  const universalAuthMetadata = projectUaConfigMetadata(rows[0]);
  await checkpoint();
  // No revoked filter: both revoked and unrevoked records survive this snapshot.
  const secrets = await tx<ClientSecretMetadataRow, ClientSecretMetadataRow[]>(TableName.IdentityUaClientSecret)
    .where({ identityUAId: universalAuthMetadata.id })
    .select(...CLIENT_SECRET_METADATA_COLUMNS)
    .orderBy("id")
    .limit(MAX_CLIENT_SECRET_METADATA + 1);
  return {
    universalAuthMetadata,
    clientSecretMetadata: projectClientSecretMetadata(secrets, universalAuthMetadata.id)
  };
};
