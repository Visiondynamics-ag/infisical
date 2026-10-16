import { MfaMethod } from "./auth-type";

/*
 * Determines whether MFA is required and which method applies, based on org enforcement vs user
 * preference. Org enforcement takes precedence over the user's own selection. Shared between the
 * login flow (which challenges for MFA) and the OAuth consent flow (which must reject sessions that
 * never completed a required MFA challenge before issuing a delegation code).
 */
export const getRequiredMfaMethod = (
  org: { enforceMfa?: boolean | null; selectedMfaMethod?: string | null },
  user: { isMfaEnabled?: boolean | null; selectedMfaMethod?: string | null }
): { isMfaRequired: boolean; requiredMfaMethod: MfaMethod } => {
  const isOrgMfaEnforced = Boolean(org.enforceMfa);
  const isUserMfaEnabled = Boolean(user.isMfaEnabled);
  const isMfaRequired = isOrgMfaEnforced || isUserMfaEnabled;

  const requiredMfaMethod = isOrgMfaEnforced
    ? ((org.selectedMfaMethod as MfaMethod) ?? MfaMethod.EMAIL)
    : ((user.selectedMfaMethod as MfaMethod) ?? MfaMethod.EMAIL);

  return { isMfaRequired, requiredMfaMethod };
};
