import type { MongoAbility } from "@casl/ability";

import {
  OrgPermissionIdentityActions,
  type OrgPermissionSet,
  OrgPermissionSubjects
} from "@app/ee/services/permission/org-permission";
import { validatePrivilegeChangeOperation } from "@app/ee/services/permission/permission-fns";

import { requireSnapshot } from "./kalscan-snapshot-contract";

export const requireUaMetadataAuthorization = (
  actorPermission: MongoAbility<OrgPermissionSet>,
  managedPermission: MongoAbility<OrgPermissionSet>,
  shouldUseNewPrivilegeSystem: boolean | null
) => {
  requireSnapshot(shouldUseNewPrivilegeSystem === true, "SCOPE");
  requireSnapshot(actorPermission.can(OrgPermissionIdentityActions.Read, OrgPermissionSubjects.Identity), "AUTH");
  const matches = (value: unknown, key: string) => value === key || (Array.isArray(value) && value.includes(key));
  // A conditional/field-limited rule cannot certify an unfiltered metadata list.
  requireSnapshot(
    !actorPermission.rules.some(
      (r) =>
        (matches(r.subject, OrgPermissionSubjects.Identity) || matches(r.subject, "all")) &&
        [OrgPermissionIdentityActions.Read, OrgPermissionIdentityActions.GetToken, "manage"].some((a) =>
          matches(r.action, a)
        ) &&
        (r.conditions || r.fields)
    ),
    "AUTH"
  );
  requireSnapshot(
    validatePrivilegeChangeOperation(
      shouldUseNewPrivilegeSystem,
      OrgPermissionIdentityActions.GetToken,
      OrgPermissionSubjects.Identity,
      actorPermission,
      managedPermission
    ).isValid,
    "AUTH"
  );
};
