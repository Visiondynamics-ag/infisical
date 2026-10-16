import { getRequiredMfaMethod } from "../auth/auth-mfa-method";
import { requireSnapshot } from "./g2-snapshot-contract";

// Settings must come from the same transaction as the inventory. Reuse the login
// and OAuth method-selection helper, including organization precedence/email fallback.
export const requireSnapshotMfa = (
  org: Parameters<typeof getRequiredMfaMethod>[0],
  user: Parameters<typeof getRequiredMfaMethod>[1],
  verified: boolean,
  method: string | undefined
) => {
  const { isMfaRequired, requiredMfaMethod } = getRequiredMfaMethod(org, user);
  requireSnapshot(
    !isMfaRequired ||
      (["email", "totp", "webauthn"].includes(requiredMfaMethod) && verified === true && method === requiredMfaMethod),
    "AUTH"
  );
};
