import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TestSelector } from '../components/common/TestSelector';
import { ScannerToolInfo } from '../services/api';

const mockTools: ScannerToolInfo[] = [
  { name: 'bandit', display_name: 'Bandit Python SAST', category: 'sast', is_available: true, version: '1.9.4' },
  { name: 'injection_scanner', display_name: 'SQL & NoSQL Injection Scanner', category: 'sast', is_available: true, version: '1.0' },
  { name: 'gitleaks', display_name: 'Gitleaks Secret Scanner', category: 'secret', is_available: true, version: '8.18' },
  { name: 'secret_detector', display_name: 'Red Mercury Secret Engine', category: 'secret', is_available: true, version: '1.0' },
  { name: 'pip_audit', display_name: 'pip-audit Dependency SCA', category: 'sca', is_available: true, version: '2.10' },
  { name: 'iac_scanner', display_name: 'Infrastructure as Code (IaC) Scanner', category: 'iac', is_available: true, version: '1.0' },
  { name: 'semgrep', display_name: 'Semgrep Multi-Language SAST', category: 'sast', is_available: false, version: null },
];

describe('TestSelector Component', () => {
  it('renders all available tools with category badges', () => {
    const handleChange = vi.fn();
    render(
      <TestSelector
        tools={mockTools}
        selectedTools={['bandit', 'gitleaks']}
        onChange={handleChange}
      />
    );

    expect(screen.getByText('Bandit Python SAST')).toBeInTheDocument();
    expect(screen.getByText('Gitleaks Secret Scanner')).toBeInTheDocument();
    expect(screen.getByText('pip-audit Dependency SCA')).toBeInTheDocument();
    expect(screen.getByText('2 of 6 available')).toBeInTheDocument();
  });

  it('allows toggling individual tests on and off', () => {
    const handleChange = vi.fn();
    render(
      <TestSelector
        tools={mockTools}
        selectedTools={['bandit']}
        onChange={handleChange}
      />
    );

    const pipAuditCard = screen.getByText('pip-audit Dependency SCA');
    fireEvent.click(pipAuditCard);

    expect(handleChange).toHaveBeenCalledWith(['bandit', 'pip_audit']);
  });

  it('applies the Secrets Only preset correctly', () => {
    const handleChange = vi.fn();
    render(
      <TestSelector
        tools={mockTools}
        selectedTools={['bandit']}
        onChange={handleChange}
      />
    );

    const secretsBtn = screen.getByRole('button', { name: /Secrets Only/i });
    fireEvent.click(secretsBtn);

    expect(handleChange).toHaveBeenCalledWith(['gitleaks', 'secret_detector']);
  });

  it('applies the Recommended preset correctly', () => {
    const handleChange = vi.fn();
    render(
      <TestSelector
        tools={mockTools}
        selectedTools={[]}
        onChange={handleChange}
      />
    );

    const recBtn = screen.getByRole('button', { name: /Recommended/i });
    fireEvent.click(recBtn);

    expect(handleChange).toHaveBeenCalledWith(
      expect.arrayContaining(['bandit', 'injection_scanner', 'gitleaks', 'secret_detector', 'pip_audit'])
    );
  });

  it('filters tests when category tabs are clicked', () => {
    const handleChange = vi.fn();
    render(
      <TestSelector
        tools={mockTools}
        selectedTools={['bandit']}
        onChange={handleChange}
      />
    );

    const secretsTab = screen.getByRole('button', { name: 'Secrets' });
    fireEvent.click(secretsTab);

    expect(screen.getByText('Gitleaks Secret Scanner')).toBeInTheDocument();
    expect(screen.queryByText('Bandit Python SAST')).not.toBeInTheDocument();
  });

  it('filters tests via the search input', () => {
    const handleChange = vi.fn();
    render(
      <TestSelector
        tools={mockTools}
        selectedTools={['bandit']}
        onChange={handleChange}
      />
    );

    const searchInput = screen.getByPlaceholderText('Search test...');
    fireEvent.change(searchInput, { target: { value: 'injection' } });

    expect(screen.getByText('SQL & NoSQL Injection Scanner')).toBeInTheDocument();
    expect(screen.queryByText('pip-audit Dependency SCA')).not.toBeInTheDocument();
  });
});

