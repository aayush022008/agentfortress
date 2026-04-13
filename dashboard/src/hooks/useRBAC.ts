import { useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';

const PERMISSION_CACHE: Record<string, boolean> = {};

export const useRBAC = () => {
  const { user } = useAuth();

  const hasPermission = useCallback((permission: string): boolean => {
    if (!user) return false;
    const cacheKey = `${user.user_id}:${permission}`;
    if (cacheKey in PERMISSION_CACHE) return PERMISSION_CACHE[cacheKey];

    // Admin / wildcard check
    if (user.roles.includes('admin')) {
      PERMISSION_CACHE[cacheKey] = true;
      return true;
    }

    // Simple role-to-permission mapping (real impl: server-side check)
    const rolePermissions: Record<string, string[]> = {
      analyst: ['alerts:read', 'sessions:read', 'events:read', 'forensics:read', 'search:read'],
      hunter: ['hunt:read', 'hunt:write', 'events:read', 'intel:read'],
      viewer: ['alerts:read', 'sessions:read', 'dashboard:read'],
    };

    for (const role of user.roles) {
      const perms = rolePermissions[role] || [];
      if (perms.includes(permission) || perms.includes('*')) {
        PERMISSION_CACHE[cacheKey] = true;
        return true;
      }
    }

    PERMISSION_CACHE[cacheKey] = false;
    return false;
  }, [user]);

  const hasAnyPermission = useCallback((permissions: string[]): boolean => {
    return permissions.some(p => hasPermission(p));
  }, [hasPermission]);

  const hasAllPermissions = useCallback((permissions: string[]): boolean => {
    return permissions.every(p => hasPermission(p));
  }, [hasPermission]);

  const isAdmin = user?.roles.includes('admin') ?? false;

  return { hasPermission, hasAnyPermission, hasAllPermissions, isAdmin, user };
};
