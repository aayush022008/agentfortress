import React, { useEffect, useState } from 'react';

interface Role {
  role_id: string;
  name: string;
  description: string;
  permissions: string[];
  built_in: boolean;
}

interface Assignment {
  assignment_id: string;
  user_id: string;
  role_id: string;
  assigned_at: number;
}

const RBAC: React.FC = () => {
  const [roles, setRoles] = useState<Role[]>([]);
  const [selectedRole, setSelectedRole] = useState<Role | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    fetch('/api/rbac/roles')
      .then(r => r.json())
      .then(d => setRoles(d.roles || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const ALL_PERMISSIONS = [
    'alerts:read', 'alerts:write', 'sessions:read', 'events:read', 'events:write',
    'policies:read', 'policies:write', 'hunt:read', 'hunt:write',
    'forensics:read', 'forensics:write', 'compliance:read', 'users:read', 'users:write',
    'rbac:read', 'rbac:write', 'billing:read', 'settings:write', '*',
  ];

  if (loading) return <div style={{ padding: 24, color: '#9ca3af' }}>Loading...</div>;

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700 }}>Role Management</h1>
          <p style={{ color: '#6b7280' }}>Manage roles and permissions for platform access</p>
        </div>
        <button
          style={{ background: '#3b82f6', color: 'white', border: 'none', borderRadius: 6, padding: '10px 20px', cursor: 'pointer' }}
          onClick={() => alert('Create role dialog (implement modal)')}
        >
          + Create Role
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16 }}>
        {/* Role list */}
        <div>
          {roles.map(role => (
            <div
              key={role.role_id}
              onClick={() => setSelectedRole(role)}
              style={{
                background: selectedRole?.role_id === role.role_id ? '#3b4f6b' : '#1f2937',
                borderRadius: 8, padding: 12, marginBottom: 8, cursor: 'pointer',
                border: `1px solid ${selectedRole?.role_id === role.role_id ? '#3b82f6' : '#374151'}`,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 600, color: '#f9fafb' }}>{role.name}</span>
                {role.built_in && (
                  <span style={{ background: '#374151', color: '#9ca3af', fontSize: 10, padding: '2px 6px', borderRadius: 10 }}>
                    BUILT-IN
                  </span>
                )}
              </div>
              <div style={{ fontSize: 12, color: '#6b7280', marginTop: 4 }}>{role.description}</div>
              <div style={{ fontSize: 11, color: '#9ca3af', marginTop: 4 }}>
                {role.permissions.length} permissions
              </div>
            </div>
          ))}
        </div>

        {/* Role detail / Permission matrix */}
        <div style={{ background: '#1f2937', borderRadius: 8, padding: 20 }}>
          {selectedRole ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <h2 style={{ fontSize: 18, fontWeight: 700 }}>{selectedRole.name}</h2>
                {!selectedRole.built_in && (
                  <button style={{ background: '#374151', color: '#f9fafb', border: 'none', borderRadius: 6, padding: '6px 14px', cursor: 'pointer' }}>
                    Edit
                  </button>
                )}
              </div>
              <p style={{ color: '#6b7280', marginBottom: 16 }}>{selectedRole.description}</p>
              <div style={{ fontSize: 13, color: '#9ca3af', marginBottom: 12 }}>PERMISSIONS</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8 }}>
                {ALL_PERMISSIONS.map(perm => {
                  const hasWildcard = selectedRole.permissions.includes('*');
                  const hasPerm = hasWildcard || selectedRole.permissions.includes(perm);
                  return (
                    <div
                      key={perm}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8,
                        background: '#111827', borderRadius: 6, padding: '8px 12px',
                      }}
                    >
                      <span style={{ color: hasPerm ? '#10b981' : '#6b7280', fontSize: 16 }}>
                        {hasPerm ? '✓' : '○'}
                      </span>
                      <span style={{ fontSize: 12, color: hasPerm ? '#f9fafb' : '#6b7280' }}>{perm}</span>
                    </div>
                  );
                })}
              </div>
            </>
          ) : (
            <div style={{ textAlign: 'center', color: '#6b7280', padding: 48 }}>
              Select a role to view permissions
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RBAC;
