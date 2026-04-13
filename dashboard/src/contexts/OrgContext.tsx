import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

interface Organization {
  org_id: string;
  name: string;
  plan: string;
  features: string[];
}

interface OrgContextType {
  organization: Organization | null;
  organizations: Organization[];
  switchOrg: (orgId: string) => void;
  hasFeature: (feature: string) => boolean;
}

const OrgContext = createContext<OrgContextType | null>(null);

export const OrgProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);

  useEffect(() => {
    fetchOrganizations();
  }, []);

  const fetchOrganizations = async (): Promise<void> => {
    try {
      const response = await fetch('/api/organizations');
      if (!response.ok) return;
      const data = await response.json();
      const orgs: Organization[] = data.organizations || [];
      setOrganizations(orgs);
      const savedOrgId = localStorage.getItem('agentshield_org_id');
      const current = orgs.find(o => o.org_id === savedOrgId) || orgs[0] || null;
      setOrganization(current);
    } catch {
      // Use default
    }
  };

  const switchOrg = (orgId: string): void => {
    const org = organizations.find(o => o.org_id === orgId);
    if (org) {
      setOrganization(org);
      localStorage.setItem('agentshield_org_id', orgId);
    }
  };

  const hasFeature = (feature: string): boolean => {
    if (!organization) return false;
    return organization.features.includes(feature) || organization.features.includes('*');
  };

  return (
    <OrgContext.Provider value={{ organization, organizations, switchOrg, hasFeature }}>
      {children}
    </OrgContext.Provider>
  );
};

export const useOrg = (): OrgContextType => {
  const ctx = useContext(OrgContext);
  if (!ctx) throw new Error('useOrg must be used within OrgProvider');
  return ctx;
};

export default OrgContext;
