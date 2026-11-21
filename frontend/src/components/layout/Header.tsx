import React, { useRef, useEffect } from 'react';
import { Search, Menu, Play } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface HeaderProps {
  onOpenMobileMenu: () => void;
  onTriggerScan: () => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenMobileMenu,
  onTriggerScan,
  searchQuery,
  onSearchChange
}) => {
  const { user } = useAuth();
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Keyboard shortcut '/' to focus search input
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement !== searchInputRef.current) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <header className="fixed top-0 left-0 lg:left-64 right-0 h-14 glass-nav border-b border-slate-200/80 z-40 flex items-center justify-between px-4 lg:px-8">
      {/* Left side: Hamburger for mobile + Search Input */}
      <div className="flex items-center gap-3 flex-1 max-w-xl">
        <button
          onClick={onOpenMobileMenu}
          className="lg:hidden p-1.5 rounded-lg hover:bg-slate-100 text-slate-600 cursor-pointer font-medium text-xs flex items-center gap-1"
          aria-label="Open Navigation"
        >
          <Menu className="w-5 h-5 text-slate-700" />
        </button>

        <div className="relative w-full">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            ref={searchInputRef}
            value={searchQuery}
            onChange={e => onSearchChange(e.target.value)}
            className="w-full pl-8 pr-8 py-1.5 bg-slate-100/70 hover:bg-white focus:bg-white border border-slate-200/80 focus:border-slate-400 rounded-lg text-xs text-slate-900 placeholder:text-slate-400 focus:outline-hidden transition-all shadow-2xs font-sans"
            placeholder="Search repositories, findings, rules, commit hashes..."
            type="text"
          />
          <kbd className="hidden sm:inline-block absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] font-mono px-1.5 py-0.2 rounded bg-white border border-slate-200 text-slate-400 shadow-2xs">
            /
          </kbd>
        </div>
      </div>

      {/* Right side: Quick Scan & User Profile */}
      <div className="flex items-center gap-3">
        {/* Quick Scan Action */}
        <button
          type="button"
          onClick={onTriggerScan}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs shadow-xs transition-colors cursor-pointer"
        >
          <Play className="w-3 h-3 fill-current" />
          <span>New Scan</span>
        </button>

        <div className="h-4 w-px bg-slate-200 hidden sm:block" />

        {/* User Badge */}
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-full bg-slate-900 text-white font-semibold flex items-center justify-center text-xs shadow-2xs">
            {user?.fullName?.[0]?.toUpperCase() || user?.email?.[0]?.toUpperCase() || 'U'}
          </div>
          <span className="hidden md:inline text-xs font-semibold text-slate-800 font-sans">
            {user?.fullName || user?.email || 'SecOps Engineer'}
          </span>
        </div>
      </div>
    </header>
  );
};
