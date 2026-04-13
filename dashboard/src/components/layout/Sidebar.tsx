import { NavLink } from 'react-router-dom';
import { Shield, LayoutDashboard, Activity, Bell, Settings, Play, BarChart2, Building, Key } from 'lucide-react';
import { clsx } from 'clsx';

const navItems = [
  { to: '/overview', label: 'Overview', icon: LayoutDashboard },
  { to: '/sessions', label: 'Sessions', icon: Activity },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/policies', label: 'Policies', icon: Settings },
  { to: '/analytics', label: 'Analytics', icon: BarChart2 },
  { to: '/organizations', label: 'Organizations', icon: Building },
  { to: '/apikeys', label: 'API Keys', icon: Key },
];

export default function Sidebar() {
  return (
    <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col">
      <div className="flex items-center gap-2 px-4 py-5 border-b border-gray-800">
        <Shield className="h-7 w-7 text-blue-500" />
        <span className="font-bold text-lg text-white">AgentShield</span>
      </div>
      <nav className="flex-1 py-4 px-2 space-y-1">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800',
              )
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-gray-800 text-xs text-gray-500">
        v1.0.0
      </div>
    </aside>
  );
}
