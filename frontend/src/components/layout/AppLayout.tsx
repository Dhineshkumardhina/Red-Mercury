import React, { useState } from 'react';
import { useLocation, useNavigate, Link, Navigate } from 'react-router-dom';
import {
  LayoutDashboard,
  FolderGit2,
  ShieldAlert,
  CheckCircle2,
  FileText,
  Code2,
  Settings,
  LogOut,
  Shield,
} from 'lucide-react';
import { Header } from './Header';
import { useAuth } from '../../context/AuthContext';

export interface AppLayoutProps {
  children: React.ReactNode;
  onTriggerScan?: () => void;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ children, onTriggerScan }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, isLoading, logout } = useAuth();

  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-slate-500">
          <svg className="w-6 h-6 animate-spin text-slate-900" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
          </svg>
          <span className="text-xs text-slate-600 font-medium">Authenticating session...</span>
        </div>
      </div>
    );
  }

  if (!user || !user.isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  const navSections = [
    {
      title: 'OVERVIEW',
      items: [
        {
          path: '/dashboard',
          label: 'Dashboard',
          icon: LayoutDashboard,
        },
        {
          path: '/repositories',
          label: 'Repositories',
          icon: FolderGit2,
        },
        {
          path: '/findings',
          label: 'Findings',
          icon: ShieldAlert,
        },
      ],
    },
    {
      title: 'VERIFICATION & GATES',
      items: [
        {
          path: '/verification',
          label: 'Fix Verification',
          icon: CheckCircle2,
        },
        {
          path: '/analyzer',
          label: 'Patch Analyzer',
          icon: Code2,
        },
        {
          path: '/evidence',
          label: 'Evidence Center',
          icon: FileText,
        },
      ],
    },
    {
      title: 'PREFERENCES',
      items: [
        {
          path: '/settings',
          label: 'Settings',
          icon: Settings,
        },
      ],
    },
  ];

  const handleSignOut = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 antialiased flex flex-col font-sans">
      {/* Mobile Backdrop */}
      {isMobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/40 lg:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Modern Clean Vertical Navigation */}
      <aside
        className={`fixed left-0 top-0 h-screen w-64 bg-white border-r border-slate-200/80 z-50 flex flex-col justify-between select-none transition-transform duration-200 ease-in-out ${
          isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="flex flex-col flex-1 min-h-0">
          {/* Brand Header */}
          <div className="h-14 px-4 border-b border-slate-100 flex items-center justify-between bg-white shrink-0">
            <Link to="/dashboard" className="flex items-center gap-2.5 group">
              <div className="w-8 h-8 rounded-lg bg-slate-900 text-white flex items-center justify-center shadow-xs group-hover:bg-slate-800 transition-colors">
                <Shield className="w-4 h-4 text-white" />
              </div>
              <div className="flex flex-col">
                <span className="font-bold text-sm text-slate-900 tracking-tight leading-none">
                  Red Mercury
                </span>
                <span className="text-[10px] text-slate-400 font-mono tracking-wider uppercase leading-tight mt-0.5">
                  AppSec Platform
                </span>
              </div>
            </Link>
            <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200/60">
              v1.2
            </span>
          </div>

          {/* Clean Categorized Navigation */}
          <nav className="flex-1 px-3 py-3 overflow-y-auto space-y-4">
            {navSections.map(section => (
              <div key={section.title} className="space-y-0.5">
                <div className="px-3 py-1.5 text-[11px] font-semibold tracking-wider text-slate-400 uppercase font-sans">
                  {section.title}
                </div>
                {section.items.map(item => {
                  const isActive =
                    location.pathname === item.path ||
                    (item.path !== '/dashboard' && location.pathname.startsWith(item.path));
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.path}
                      type="button"
                      onClick={() => {
                        navigate(item.path);
                        setIsMobileMenuOpen(false);
                      }}
                      aria-label={item.label}
                      className={`w-full flex items-center px-3 py-2 rounded-lg text-left transition-colors text-[13px] cursor-pointer group ${
                        isActive
                          ? 'bg-slate-100 text-slate-900 font-medium'
                          : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900 font-normal'
                      }`}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <Icon
                          className={`w-4 h-4 shrink-0 transition-colors ${
                            isActive ? 'text-slate-900' : 'text-slate-400 group-hover:text-slate-600'
                          }`}
                        />
                        <span className="truncate">{item.label}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            ))}
          </nav>
        </div>

        {/* User Session Footer */}
        <div className="p-3 border-t border-slate-100 bg-white shrink-0">
          <div className="flex items-center justify-between p-1.5 rounded-lg hover:bg-slate-50 transition-colors">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="relative shrink-0">
                <div className="w-8 h-8 rounded-full bg-slate-900 text-white font-semibold flex items-center justify-center text-xs shadow-2xs">
                  {user?.fullName ? user.fullName.charAt(0).toUpperCase() : 'D'}
                </div>
                <span className="absolute bottom-0 right-0 w-2 h-2 rounded-full bg-emerald-500 ring-2 ring-white"></span>
              </div>
              <div className="flex flex-col min-w-0 leading-tight">
                <span className="font-semibold text-xs text-slate-900 truncate">
                  {user?.fullName || 'Dhinesh Kumar'}
                </span>
                <span className="text-[11px] text-slate-500 truncate">
                  {user?.role || 'SecOps Lead'}
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={handleSignOut}
              title="Sign out"
              aria-label="Sign Out"
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-800 hover:bg-slate-100 transition-colors cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="lg:pl-64 flex flex-col flex-1 min-h-screen">
        {/* Top Navigation Bar */}
        <Header
          onOpenMobileMenu={() => setIsMobileMenuOpen(true)}
          onTriggerScan={onTriggerScan || (() => navigate('/repositories'))}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
        />

        {/* Dynamic Screen View */}
        <main className="relative pt-14 flex-1">
          {children}
        </main>
      </div>
    </div>
  );
};
