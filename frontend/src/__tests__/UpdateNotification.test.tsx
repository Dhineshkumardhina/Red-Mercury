import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { UpdateNotification } from '../components/common/UpdateNotification';
import type { UpdateStatus } from '../types/electron';

describe('UpdateNotification Component (Phase 11A In-App Update UI)', () => {
  let currentMockState: UpdateStatus;
  const mockDownload = vi.fn().mockResolvedValue({});
  const mockInstall = vi.fn().mockResolvedValue({ success: true, platform: 'win32' });
  const mockCancel = vi.fn().mockResolvedValue(true);

  beforeEach(() => {
    vi.clearAllMocks();
    currentMockState = {
      state: 'idle',
      currentVersion: '1.0.0',
      platform: 'win32',
      isReadyToInstall: false,
    };

    window.electronAPI = {
      isElectron: true,
      selectDirectory: vi.fn(),
      getAppInfo: vi.fn(),
      checkBackend: vi.fn(),
      openExternal: vi.fn(),
      getUpdateStatus: vi.fn().mockImplementation(() => Promise.resolve(currentMockState)),
      onUpdateStatus: vi.fn().mockReturnValue(() => {}),
      onUpdateProgress: vi.fn().mockReturnValue(() => {}),
      downloadUpdate: mockDownload,
      installUpdate: mockInstall,
      cancelUpdateDownload: mockCancel,
    };
  });

  it('renders nothing when update state is idle or not-available', async () => {
    render(<UpdateNotification />);
    expect(screen.queryByText(/Update Available/i)).toBeNull();
  });

  it('renders update available banner and allows operator to download', async () => {
    currentMockState = {
      state: 'available',
      currentVersion: '1.0.0',
      platform: 'win32',
      isReadyToInstall: false,
      availableUpdate: {
        version: '1.1.0',
        releaseNotes: 'What\'s New:\n- Improved Patch Analyzer.\n- Bug fixes.',
        publisher: 'Xerova Digital Solutions',
      },
    };

    await act(async () => {
      render(<UpdateNotification />);
    });

    expect(screen.getByText(/Red Mercury — Update Available/i)).toBeInTheDocument();
    expect(screen.getByText(/v1.1.0/i)).toBeInTheDocument();
    expect(screen.getByText(/Improved Patch Analyzer/i)).toBeInTheDocument();

    const downloadBtn = screen.getByRole('button', { name: /Download Update/i });
    fireEvent.click(downloadBtn);
    expect(mockDownload).toHaveBeenCalledTimes(1);
  });

  it('renders ready-to-install banner and requires user approval before calling install', async () => {
    currentMockState = {
      state: 'ready-to-install',
      currentVersion: '1.0.0',
      platform: 'win32',
      isReadyToInstall: true,
      availableUpdate: {
        version: '1.1.0',
      },
    };

    await act(async () => {
      render(<UpdateNotification />);
    });

    expect(screen.getByText(/Update Ready to Install/i)).toBeInTheDocument();
    expect(screen.getByText(/Update downloaded and cryptographically verified/i)).toBeInTheDocument();

    const installBtn = screen.getByRole('button', { name: /Restart and Install/i });
    fireEvent.click(installBtn);
    expect(mockInstall).toHaveBeenCalledTimes(1);
  });

  it('allows dismissing banner with Remind Me Later', async () => {
    currentMockState = {
      state: 'available',
      currentVersion: '1.0.0',
      platform: 'win32',
      isReadyToInstall: false,
      availableUpdate: {
        version: '1.1.0',
      },
    };

    await act(async () => {
      render(<UpdateNotification />);
    });

    const remindBtn = screen.getAllByRole('button', { name: /Remind Me Later/i })[0];
    fireEvent.click(remindBtn);

    expect(screen.queryByText(/Red Mercury — Update Available/i)).toBeNull();
  });
});
