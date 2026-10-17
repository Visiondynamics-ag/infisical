import { KALSCAN, requireSnapshot, uuid } from "./kalscan-snapshot-contract";

export const MAX_CLIENT_SECRET_METADATA = 32;
export const UA_METADATA_COLUMNS = [
  "id",
  "identityId",
  "createdAt",
  "updatedAt",
  "accessTokenTTL",
  "accessTokenMaxTTL",
  "accessTokenNumUsesLimit",
  "accessTokenPeriod",
  "lockoutEnabled",
  "lockoutThreshold",
  "lockoutDurationSeconds",
  "lockoutCounterResetSeconds"
] as const;
export const CLIENT_SECRET_METADATA_COLUMNS = [
  "id",
  "identityUAId",
  "createdAt",
  "updatedAt",
  "clientSecretNumUses",
  "clientSecretNumUsesLimit",
  "clientSecretTTL",
  "isClientSecretRevoked"
] as const;
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const record = (value: unknown, keys: readonly string[]): Record<string, unknown> => {
  requireSnapshot(isRecord(value), "SCHEMA");
  requireSnapshot(Object.keys(value).sort().join(",") === [...keys].sort().join(","), "SCHEMA");
  return value;
};
export const sqlMetadataInteger = (value: unknown): number => {
  requireSnapshot(
    typeof value === "number" || (typeof value === "string" && /^(0|[1-9][0-9]{0,15})$/.test(value)),
    "SCHEMA"
  );
  const number = typeof value === "number" ? value : Number(value);
  requireSnapshot(Number.isSafeInteger(number) && number >= 0, "SCHEMA");
  return number;
};
const date = (value: unknown): string => {
  requireSnapshot(value instanceof Date && Number.isFinite(value.getTime()), "SCHEMA");
  return value.toISOString();
};
const boolean = (value: unknown): boolean => {
  requireSnapshot(typeof value === "boolean", "SCHEMA");
  return value;
};
export const projectUaConfigMetadata = (value: unknown) => {
  const r = record(value, UA_METADATA_COLUMNS);
  requireSnapshot(r.identityId === KALSCAN.identityId, "CONFLICT");
  return {
    id: uuid(r.id),
    identityId: KALSCAN.identityId,
    createdAt: date(r.createdAt),
    updatedAt: date(r.updatedAt),
    accessTokenTTL: sqlMetadataInteger(r.accessTokenTTL),
    accessTokenMaxTTL: sqlMetadataInteger(r.accessTokenMaxTTL),
    accessTokenNumUsesLimit: sqlMetadataInteger(r.accessTokenNumUsesLimit),
    accessTokenPeriod: sqlMetadataInteger(r.accessTokenPeriod),
    lockoutEnabled: boolean(r.lockoutEnabled),
    lockoutThreshold: sqlMetadataInteger(r.lockoutThreshold),
    lockoutDurationSeconds: sqlMetadataInteger(r.lockoutDurationSeconds),
    lockoutCounterResetSeconds: sqlMetadataInteger(r.lockoutCounterResetSeconds)
  };
};
export const projectClientSecretMetadata = (values: unknown, uaId: string) => {
  requireSnapshot(Array.isArray(values), "SCHEMA");
  requireSnapshot(values.length <= MAX_CLIENT_SECRET_METADATA, "CAP");
  const seen = new Set<string>();
  return values.map((value: unknown) => {
    const r = record(value, CLIENT_SECRET_METADATA_COLUMNS);
    const id = uuid(r.id);
    requireSnapshot(!seen.has(id), "CONFLICT");
    seen.add(id);
    requireSnapshot(r.identityUAId === uaId, "CONFLICT");
    return {
      id,
      identityUAId: uuid(r.identityUAId),
      createdAt: date(r.createdAt),
      updatedAt: date(r.updatedAt),
      clientSecretNumUses: sqlMetadataInteger(r.clientSecretNumUses),
      clientSecretNumUsesLimit: sqlMetadataInteger(r.clientSecretNumUsesLimit),
      clientSecretTTL: sqlMetadataInteger(r.clientSecretTTL),
      isClientSecretRevoked: boolean(r.isClientSecretRevoked)
    };
  });
};
