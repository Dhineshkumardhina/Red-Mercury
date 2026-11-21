import React from 'react';
import { CheckCircle2, GitMerge, AlertOctagon, HelpCircle, ShieldCheck, Loader2, Clock } from 'lucide-react';

export type VerificationState = 'verified' | 'failed' | 'inconclusive' | 'clean' | 'running' | 'pending' | 'merged';

interface StatusBadgeProps {
  status: VerificationState | string;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className = '' }) => {
  const norm = status.toLowerCase();

  const configs: Record<string, { bg: string; text: string; border: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
    verified: {
      bg: 'bg-emerald-50',
      text: 'text-emerald-700',
      border: 'border-emerald-200',
      icon: CheckCircle2,
      label: 'Verified',
    },
    merged: {
      bg: 'bg-purple-50',
      text: 'text-purple-700',
      border: 'border-purple-200',
      icon: GitMerge,
      label: 'Merged',
    },
    failed: {
      bg: 'bg-rose-50',
      text: 'text-rose-700',
      border: 'border-rose-200',
      icon: AlertOctagon,
      label: 'Verification Failed',
    },
    inconclusive: {
      bg: 'bg-amber-50',
      text: 'text-amber-700',
      border: 'border-amber-200',
      icon: HelpCircle,
      label: 'Inconclusive',
    },
    clean: {
      bg: 'bg-blue-50',
      text: 'text-blue-700',
      border: 'border-blue-200',
      icon: ShieldCheck,
      label: 'Passed Checks',
    },
    running: {
      bg: 'bg-blue-50',
      text: 'text-blue-700',
      border: 'border-blue-200',
      icon: Loader2,
      label: 'Running',
    },
    pending: {
      bg: 'bg-slate-100',
      text: 'text-slate-700',
      border: 'border-slate-200',
      icon: Clock,
      label: 'Pending',
    },
  };

  const current = configs[norm] || configs.pending;
  const Icon = current.icon;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-sans text-xs font-medium border ${current.bg} ${current.text} ${current.border} ${className}`}
    >
      <Icon className={`w-3.5 h-3.5 shrink-0 ${norm === 'running' ? 'animate-spin' : ''}`} />
      <span>{current.label}</span>
    </span>
  );
};
