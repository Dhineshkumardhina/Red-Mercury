import React from 'react';
import { AlertTriangle, AlertOctagon, Loader2, HelpCircle, ShieldCheck } from 'lucide-react';

export type ScanStatusType = 'healthy' | 'at-risk' | 'vulnerable' | 'running' | 'synchronized';

interface ScanStatusIndicatorProps {
  status: ScanStatusType | string;
  label?: string;
  showIcon?: boolean;
}

export const ScanStatusIndicator: React.FC<ScanStatusIndicatorProps> = ({
  status,
  label,
  showIcon = true,
}) => {
  const norm = status.toLowerCase();

  let badgeColor = 'bg-slate-100 text-slate-700 border-slate-200';
  let dotColor = 'bg-slate-500';
  let defaultLabel = 'Unknown';
  let IconComponent = HelpCircle;

  if (norm === 'secure' || norm === 'healthy' || norm === 'synchronized' || norm === 'clean') {
    badgeColor = 'bg-emerald-50 text-emerald-700 border-emerald-200';
    dotColor = 'bg-emerald-500';
    defaultLabel = 'Healthy';
    IconComponent = ShieldCheck;
  } else if (norm === 'at-risk' || norm === 'warning') {
    badgeColor = 'bg-amber-50 text-amber-700 border-amber-200';
    dotColor = 'bg-amber-500';
    defaultLabel = 'At Risk';
    IconComponent = AlertTriangle;
  } else if (norm === 'vulnerable' || norm === 'failed' || norm === 'error') {
    badgeColor = 'bg-rose-50 text-rose-700 border-rose-200';
    dotColor = 'bg-rose-500';
    defaultLabel = 'Vulnerable';
    IconComponent = AlertOctagon;
  } else if (norm === 'running' || norm === 'scanning') {
    badgeColor = 'bg-blue-50 text-blue-700 border-blue-200';
    dotColor = 'bg-blue-500 animate-pulse';
    defaultLabel = 'Scanning';
    IconComponent = Loader2;
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-sans font-medium border ${badgeColor}`}
    >
      {showIcon ? (
        <IconComponent className={`w-3.5 h-3.5 shrink-0 ${norm === 'running' || norm === 'scanning' ? 'animate-spin' : ''}`} aria-hidden="true" />
      ) : (
        <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} aria-hidden="true" />
      )}
      <span>{label || defaultLabel}</span>
    </span>
  );
};
