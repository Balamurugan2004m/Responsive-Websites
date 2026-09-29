import React, { useEffect, useState } from 'react';
import { useSelector } from 'react-redux';
import { Navigate, useLocation } from 'react-router';
import { RootState } from '../../store';
import { JWTValidator } from '../../utils/jwt-validator';
import { LoadingSpinner } from '../../ui/loading-spinner';
import { paths } from '../../constants/paths';
import { Claim } from '../../types/claims-types';
import { useAuthRehydrated } from '../../hooks/use-auth-rehydrated';
import { isVeteranPortalUser } from '../../utils/user-identity';

interface AuthGuardProps {
  children: React.ReactNode;
  requiredRoles?: string[];
  requiredPermissions?: string[];
  requiredClaims?: Array<{
    claimType: string;
    claimValue?: string;
    claimValues?: string[];
    requireAll?: boolean;
  }>;
  requireAnyClaim?: boolean;
  fallbackPath?: string;
  showLoading?: boolean;
  requireAllRoles?: boolean; // If true, user must have ALL roles, not just any
}

const useRoleValidation = (
  token: string | undefined, 
  requiredRoles: string[] = [],
  requireAllRoles: boolean = false
): boolean => {
  if (!token || requiredRoles.length === 0) return true;
  
  if (requireAllRoles) {
    return JWTValidator.hasAllRoles(token, requiredRoles);
  }
  
  return JWTValidator.hasAnyRole(token, requiredRoles);
};

const usePermissionValidation = (
  token: string | undefined,
  requiredPermissions: string[] = []
): boolean => {
  if (!token || requiredPermissions.length === 0) return true;
  
  // Get claims from token
  const claims = JWTValidator.getUserClaims(token);
  
  // Check if user has all required permissions
  return requiredPermissions.every(permission => {
    // Check if permission exists in claims
    const permissionClaim = claims.find(c => c.ClaimType === 'permissions' || c.ClaimType === 'permission');
    if (permissionClaim) {
      // If it's an array value, check if it includes the permission
      try {
        const permissionValues = JSON.parse(permissionClaim.ClaimValue);
        if (Array.isArray(permissionValues)) {
          return permissionValues.includes(permission);
        }
      } catch {
        // If not JSON, check direct match
        return permissionClaim.ClaimValue === permission;
      }
    }
    // Also check direct permission claim
    return JWTValidator.hasClaim(claims, 'permissions', permission) ||
           JWTValidator.hasClaim(claims, 'permission', permission);
  });
};

const useClaimsValidation = (
  claims: Claim[],
  requiredClaims: Array<{
    claimType: string;
    claimValue?: string;
    claimValues?: string[];
    requireAll?: boolean;
  }> = [],
  requireAnyClaim: boolean = false
): boolean => {
  if (!claims || claims.length === 0 || requiredClaims.length === 0) return true;

  const matchesClaim = (claim: {
    claimType: string;
    claimValue?: string;
    claimValues?: string[];
    requireAll?: boolean;
  }) => {
    if (claim.claimValue) {
      return JWTValidator.hasClaim(claims, claim.claimType, claim.claimValue);
    }

    if (claim.claimValues && claim.claimValues.length > 0) {
      if (claim.requireAll) {
        return claim.claimValues.every((value) =>
          JWTValidator.hasClaim(claims, claim.claimType, value)
        );
      }
      return claim.claimValues.some((value) =>
        JWTValidator.hasClaim(claims, claim.claimType, value)
      );
    }

    return JWTValidator.hasClaim(claims, claim.claimType);
  };

  return requireAnyClaim
    ? requiredClaims.some(matchesClaim)
    : requiredClaims.every(matchesClaim);
};

export const AuthGuard: React.FC<AuthGuardProps> = ({
  children,
  requiredRoles = [],
  requiredPermissions = [],
  requiredClaims = [],
  requireAnyClaim = false,
  fallbackPath = paths.LOGIN.pathName,
  showLoading = true,
  requireAllRoles = false,
}) => {
  const rehydrated = useAuthRehydrated();
  const { authUser } = useSelector((state: RootState) => state.authUser);
  const location = useLocation();
  const token = authUser?.Token;
  const isTokenValid = Boolean(token && JWTValidator.isValidToken(token));
  const hasRequiredRoles = useRoleValidation(token, requiredRoles, requireAllRoles);
  const hasRequiredPermissions = usePermissionValidation(token, requiredPermissions);
  const hasRequiredClaims = useClaimsValidation(
    authUser?.Claims || [],
    requiredClaims,
    requireAnyClaim
  );

  // Wait for persisted auth before deciding whether the user is logged out.
  if (!rehydrated) {
    return showLoading ? (
      <LoadingSpinner message="Loading session..." />
    ) : null;
  }

  // Redirect to login if not authenticated or token is invalid
  if (!token || !isTokenValid) {
    const isManual = sessionStorage.getItem('manualLogout') === 'true';
    const hasExpiredFlag = sessionStorage.getItem('sessionExpired') === 'true';
    const isExpiredToken = Boolean(token && !isTokenValid);
    const sessionExpired = !isManual && (hasExpiredFlag || isExpiredToken);

    if (sessionExpired) {
      sessionStorage.setItem('sessionExpired', 'true');
    }

    return (
      <Navigate
        to={fallbackPath}
        state={{ from: location, ...(sessionExpired ? { sessionExpired: true } : {}) }}
        replace
      />
    );
  }

  // Check if authenticated user is a Veteran Portal user
  if (isVeteranPortalUser(authUser)) {
    return (
      <Navigate
        to={paths.UNAUTHORIZED.pathName}
        state={{
          from: location,
          isVeteranUser: true,
          reason: 'vp_credentials',
        }}
        replace
      />
    );
  }

  // Check role-based access if required roles are specified
  if (requiredRoles.length > 0 && !hasRequiredRoles) {
    return (
      <Navigate
        to="/unauthorized"
        state={{ 
          from: location, 
          requiredRoles,
          requireAllRoles,
          reason: 'insufficient_roles'
        }}
        replace
      />
    );
  }

  // Check permission-based access if required permissions are specified
  if (requiredPermissions.length > 0 && !hasRequiredPermissions) {
    return (
      <Navigate
        to="/unauthorized"
        state={{ 
          from: location, 
          requiredPermissions,
          reason: 'insufficient_permissions'
        }}
        replace
      />
    );
  }

  // Check claims-based access if required claims are specified
  if (requiredClaims.length > 0 && !hasRequiredClaims) {
    return (
      <Navigate
        to="/unauthorized"
        state={{ 
          from: location, 
          requiredClaims,
          reason: 'insufficient_claims'
        }}
        replace
      />
    );
  }

  // User is authenticated, token is valid, and has required roles/permissions/claims
  return <>{children}</>;
};

// Higher-order component for protecting components
// eslint-disable-next-line react-refresh/only-export-components
export const withAuth = <P extends object>(
  Component: React.ComponentType<P>,
  options?: {
    requiredRoles?: string[];
    requiredPermissions?: string[];
    requiredClaims?: Array<{
      claimType: string;
      claimValue?: string;
      claimValues?: string[];
      requireAll?: boolean;
    }>;
    fallbackPath?: string;
    requireAllRoles?: boolean;
  }
) => {
  const WrappedComponent: React.FC<P> = (props) => (
    <AuthGuard 
      requiredRoles={options?.requiredRoles}
      requiredPermissions={options?.requiredPermissions}
      requiredClaims={options?.requiredClaims}
      fallbackPath={options?.fallbackPath}
      requireAllRoles={options?.requireAllRoles}
    >
      <Component {...props} />
    </AuthGuard>
  );

  WrappedComponent.displayName = `withAuth(${Component.displayName || Component.name})`;
  return WrappedComponent;
};

// Hook for conditional rendering based on authentication
// eslint-disable-next-line react-refresh/only-export-components
export const useAuthGuard = (options?: {
  requiredRoles?: string[];
  requiredPermissions?: string[];
  requireAllRoles?: boolean;
}) => {
  const { authUser } = useSelector((state: RootState) => state.authUser);
  const [isValidating, setIsValidating] = useState(true);

  const { requiredRoles = [], requiredPermissions = [], requireAllRoles = false } = options || {};

  useEffect(() => {
    const validate = () => {
      if (!authUser?.Token) {
        setIsValidating(false);
        return;
      }

      JWTValidator.isValidToken(authUser.Token);
      setIsValidating(false);
    };

    validate();
  }, [authUser?.Token]);

  const canAccess = React.useMemo(() => {
    if (isValidating || !authUser?.Token) return false;
    
    const isTokenValid = JWTValidator.isValidToken(authUser.Token);
    if (!isTokenValid) return false;

    // Check roles
    if (requiredRoles.length > 0) {
      const hasRoles = requireAllRoles 
        ? JWTValidator.hasAllRoles(authUser.Token, requiredRoles)
        : JWTValidator.hasAnyRole(authUser.Token, requiredRoles);
      if (!hasRoles) return false;
    }

    // Check permissions
    if (requiredPermissions.length > 0) {
      // Get claims from token and validate permissions
      const claims = JWTValidator.getUserClaims(authUser.Token);
      const hasPermissions = requiredPermissions.every(permission => {
        const permissionClaim = claims.find(c => c.ClaimType === 'permissions' || c.ClaimType === 'permission');
        if (permissionClaim) {
          try {
            const permissionValues = JSON.parse(permissionClaim.ClaimValue);
            if (Array.isArray(permissionValues)) {
              return permissionValues.includes(permission);
            }
          } catch {
            return permissionClaim.ClaimValue === permission;
          }
        }
        return JWTValidator.hasClaim(claims, 'permissions', permission) ||
               JWTValidator.hasClaim(claims, 'permission', permission);
      });
      if (!hasPermissions) return false;
    }

    return true;
  }, [isValidating, authUser?.Token, requiredRoles, requiredPermissions, requireAllRoles]);

  return {
    canAccess,
    isLoading: isValidating,
    isAuthenticated: !!authUser?.Token && JWTValidator.isValidToken(authUser.Token),
    user: authUser?.Token ? JWTValidator.getUserFromToken(authUser.Token) : null,
  };
};
