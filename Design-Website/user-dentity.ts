import { JWTValidator } from "./jwt-validator";

export const USER_TYPE_IDS = {
  INFINITE: 1,
  LSGS: 2,
  VA: 3,
  VETERAN: 4,
} as const;

export type UserTypeIdNumber = (typeof USER_TYPE_IDS)[keyof typeof USER_TYPE_IDS];

export interface UserIdentityCheckable {
  UserTypeId?: number | null;
  User?: {
    UserTypeId?: number | null;
    [key: string]: unknown;
  } | null;
  Claims?: Array<{ ClaimType?: string; ClaimValue?: string; type?: string; value?: string }> | null;
  Token?: string | null;
}

/**
 * Checks whether the given user or auth response represents a Veteran Portal (VP) user.
 * Veteran Portal users have UserTypeId === 4 (or role 'Veteran') and are unauthorized to access MDE4Vets.
 */
export const isVeteranPortalUser = (
  user?: UserIdentityCheckable | null
): boolean => {
  if (!user) return false;

  const directUserTypeId = Number(user.UserTypeId ?? user.User?.UserTypeId ?? 0);
  if (directUserTypeId === USER_TYPE_IDS.VETERAN) {
    return true;
  }

  // Also check token roles if token is present
  if (user.Token && typeof user.Token === "string") {
    try {
      if (
        JWTValidator.hasRole(user.Token, "Veteran") ||
        JWTValidator.hasRole(user.Token, "veteran")
      ) {
        return true;
      }
    } catch {
      // Ignore token parse error
    }
  }

  // Also check Claims array if present
  if (user.Claims && Array.isArray(user.Claims)) {
    const hasVeteranRoleClaim = user.Claims.some((claim) => {
      const type = claim.ClaimType || claim.type || "";
      const val = claim.ClaimValue || claim.value || "";
      const isRoleClaim =
        type.toLowerCase().includes("role") ||
        type.endsWith("/role") ||
        type.endsWith("/claims/role");
      return isRoleClaim && val.toLowerCase() === "veteran";
    });

    if (hasVeteranRoleClaim) {
      return true;
    }
  }

  return false;
};
