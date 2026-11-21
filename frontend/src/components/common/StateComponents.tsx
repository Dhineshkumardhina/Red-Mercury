import React from 'react';
import { AlertCircle, Plus, Loader2, FolderX } from 'lucide-react';

interface EmptyStateProps {
  icon?: string;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  actionLabel,
  onAction,
  className = '',
}) => {
  return (
    <div className={`flex flex-col items-center justify-center p-8 text-center bg-white border border-dashed border-slate-200 rounded-xl ${className}`}>
      <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center text-slate-500 mb-3">
        {icon === 'folder_off' ? (
          <FolderX className="w-6 h-6 text-slate-400" />
        ) : (
          <svg className="w-6 h-6 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="22 12 16 12 14 15 10 15 8 12 2 12"></polyline>
            <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path>
          </svg>
        )}
      </div>
      <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
      <p className="mt-1 text-xs text-slate-500 max-w-md">{description}</p>
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="mt-4 px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-lg shadow-xs transition-colors flex items-center gap-1.5 cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>{actionLabel}</span>
        </button>
      )}
    </div>
  );
};

export const LoadingState: React.FC<{ message?: string; className?: string }> = ({
  message = 'Loading security data...',
  className = '',
}) => {
  return (
    <div className={`flex flex-col items-center justify-center p-12 text-center ${className}`}>
      <Loader2 className="w-6 h-6 text-slate-900 animate-spin mb-3" />
      <p className="text-xs text-slate-500 font-medium">{message}</p>
    </div>
  );
};

export const ErrorMessage: React.FC<{
  title?: string;
  message: string;
  requestId?: string;
  onRetry?: () => void;
  className?: string;
}> = ({
  title = 'API Operation Failed',
  message,
  requestId,
  onRetry,
  className = '',
}) => {
  return (
    <div className={`p-4 rounded-xl bg-rose-50/70 border border-rose-200 text-left ${className}`}>
      <div className="flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <h4 className="text-xs font-semibold text-rose-900">{title}</h4>
          <p className="mt-0.5 text-xs text-rose-800 leading-relaxed break-words">{message}</p>
          {requestId && (
            <p className="mt-1 font-mono text-[10px] text-rose-600">
              Trace Request ID: <span className="font-semibold">{requestId}</span>
            </p>
          )}
        </div>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="px-2.5 py-1 text-xs font-medium bg-white border border-rose-300 text-rose-700 hover:bg-rose-50 rounded transition-colors shrink-0 cursor-pointer"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  );
};
