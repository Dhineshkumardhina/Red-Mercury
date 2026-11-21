import React from 'react';
import { Menu } from 'lucide-react';

interface HeaderProps {
  onOpenMobileMenu: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenMobileMenu }) => {
  return (
    <header className="lg:hidden fixed top-0 left-0 right-0 h-12 bg-white border-b border-slate-200 z-40 flex items-center justify-between px-4">
      <button
        type="button"
        onClick={onOpenMobileMenu}
        className="p-1.5 rounded-md hover:bg-slate-100 text-slate-700 cursor-pointer flex items-center gap-1.5 text-xs font-medium"
        aria-label="Open Navigation"
      >
        <Menu className="w-5 h-5" />
        <span>Red Mercury</span>
      </button>
    </header>
  );
};
