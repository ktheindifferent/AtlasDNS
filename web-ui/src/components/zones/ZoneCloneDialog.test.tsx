import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import '@testing-library/jest-dom';
import ZoneCloneDialog from './ZoneCloneDialog';
import zonesReducer, { cloneZone } from '../../store/slices/zonesSlice';
import { Zone } from '../../store/slices/zonesSlice';
import { useSnackbar } from 'notistack';
import errorMonitoring from '../../services/errorMonitoring';

// Mock notistack
jest.mock('notistack', () => ({
  useSnackbar: jest.fn(),
}));

// Mock error monitoring
jest.mock('../../services/errorMonitoring', () => ({
  __esModule: true,
  default: {
    addBreadcrumb: jest.fn(),
    captureException: jest.fn(),
  },
}));

// Mock the cloneZone thunk
jest.mock('../../store/slices/zonesSlice', () => {
  const actual = jest.requireActual('../../store/slices/zonesSlice');
  return {
    ...actual,
    cloneZone: jest.fn(),
  };
});

const mockZone: Zone = {
  id: 'zone-1',
  name: 'example.com',
  type: 'master',
  status: 'active',
  records: 10,
  dnssecEnabled: false,
  lastModified: '2024-01-01T00:00:00Z',
  serial: 2024010101,
  ttl: 3600,
  refresh: 10800,
  retry: 3600,
  expire: 604800,
  minimum: 86400,
  primaryNs: 'ns1.example.com',
  adminEmail: 'admin@example.com',
};

describe('ZoneCloneDialog', () => {
  let store: any;
  let mockEnqueueSnackbar: jest.Mock;

  beforeEach(() => {
    // Create a mock store
    store = configureStore({
      reducer: {
        zones: zonesReducer,
        auth: (state = { user: { id: 'user-1', email: 'test@example.com' } }) => state,
      },
    });

    // Setup mock for useSnackbar
    mockEnqueueSnackbar = jest.fn();
    (useSnackbar as jest.Mock).mockReturnValue({
      enqueueSnackbar: mockEnqueueSnackbar,
    });

    // Clear all mocks
    jest.clearAllMocks();
  });

  const renderWithProvider = (component: React.ReactElement) => {
    return render(
      <Provider store={store}>
        {component}
      </Provider>
    );
  };

  it('renders dialog when open', () => {
    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={jest.fn()} zone={mockZone} />
    );

    expect(screen.getByText('Clone Zone')).toBeInTheDocument();
    expect(screen.getByText(/This will create a new zone/)).toBeInTheDocument();
    expect(screen.getByText('example.com')).toBeInTheDocument();
  });

  it('does not render when closed', () => {
    renderWithProvider(
      <ZoneCloneDialog open={false} onClose={jest.fn()} zone={mockZone} />
    );

    expect(screen.queryByText('Clone Zone')).not.toBeInTheDocument();
  });

  it('sets default clone name with .clone suffix', () => {
    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={jest.fn()} zone={mockZone} />
    );

    const input = screen.getByLabelText('New Zone Name') as HTMLInputElement;
    expect(input.value).toBe('example.com.clone');
  });

  it('validates zone name format', async () => {
    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={jest.fn()} zone={mockZone} />
    );

    const input = screen.getByLabelText('New Zone Name') as HTMLInputElement;
    
    // Test invalid zone name
    fireEvent.change(input, { target: { value: 'invalid..zone' } });
    
    await waitFor(() => {
      expect(screen.getByText('Invalid DNS zone name format')).toBeInTheDocument();
    });

    // Test valid zone name
    fireEvent.change(input, { target: { value: 'valid.zone.com' } });
    
    await waitFor(() => {
      expect(screen.queryByText('Invalid DNS zone name format')).not.toBeInTheDocument();
    });
  });

  it('validates that new name is different from original', async () => {
    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={jest.fn()} zone={mockZone} />
    );

    const input = screen.getByLabelText('New Zone Name') as HTMLInputElement;
    
    fireEvent.change(input, { target: { value: 'example.com' } });
    
    await waitFor(() => {
      expect(screen.getByText('New zone name must be different from the original')).toBeInTheDocument();
    });
  });

  it('requires zone name to be provided', async () => {
    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={jest.fn()} zone={mockZone} />
    );

    const input = screen.getByLabelText('New Zone Name') as HTMLInputElement;
    
    fireEvent.change(input, { target: { value: '' } });
    
    await waitFor(() => {
      expect(screen.getByText('Zone name is required')).toBeInTheDocument();
    });
  });

  it('successfully clones zone', async () => {
    const mockOnClose = jest.fn();
    const mockDispatch = jest.fn().mockResolvedValue({ unwrap: () => Promise.resolve() });
    
    (cloneZone as jest.Mock).mockReturnValue({
      type: 'zones/cloneZone/fulfilled',
      payload: { ...mockZone, id: 'zone-2', name: 'example.com.clone' },
    });

    // Override store dispatch
    store.dispatch = mockDispatch;

    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={mockOnClose} zone={mockZone} />
    );

    const input = screen.getByLabelText('New Zone Name') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'example.com.clone' } });

    const cloneButton = screen.getByRole('button', { name: /Clone Zone/i });
    fireEvent.click(cloneButton);

    await waitFor(() => {
      expect(errorMonitoring.addBreadcrumb).toHaveBeenCalledWith({
        message: 'Cloning zone: example.com to example.com.clone',
        category: 'zone-operations',
        level: 'info',
        data: { originalZone: 'example.com', newZone: 'example.com.clone' },
      });
    });

    await waitFor(() => {
      expect(mockEnqueueSnackbar).toHaveBeenCalledWith(
        'Zone "example.com" successfully cloned to "example.com.clone"',
        { variant: 'success', autoHideDuration: 5000 }
      );
    });

    expect(mockOnClose).toHaveBeenCalled();
  });

  it('handles clone error', async () => {
    const mockOnClose = jest.fn();
    const mockError = new Error('Clone failed');
    const mockDispatch = jest.fn().mockRejectedValue(mockError);

    (cloneZone as jest.Mock).mockReturnValue({
      type: 'zones/cloneZone/rejected',
      error: mockError,
    });

    store.dispatch = mockDispatch;

    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={mockOnClose} zone={mockZone} />
    );

    const input = screen.getByLabelText('New Zone Name') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'example.com.clone' } });

    const cloneButton = screen.getByRole('button', { name: /Clone Zone/i });
    fireEvent.click(cloneButton);

    await waitFor(() => {
      expect(errorMonitoring.captureException).toHaveBeenCalledWith(
        mockError,
        {
          context: 'zone-clone',
          originalZone: 'example.com',
          newZone: 'example.com.clone',
        }
      );
    });

    await waitFor(() => {
      expect(mockEnqueueSnackbar).toHaveBeenCalledWith(
        'Clone failed',
        { variant: 'error', autoHideDuration: 5000 }
      );
    });

    expect(mockOnClose).not.toHaveBeenCalled();
  });

  it('disables inputs and shows loading state while cloning', async () => {
    const mockDispatch = jest.fn().mockImplementation(() => 
      new Promise(resolve => setTimeout(resolve, 100))
    );
    
    store.dispatch = mockDispatch;

    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={jest.fn()} zone={mockZone} />
    );

    const cloneButton = screen.getByRole('button', { name: /Clone Zone/i });
    fireEvent.click(cloneButton);

    await waitFor(() => {
      expect(screen.getByText('Cloning...')).toBeInTheDocument();
    });

    const input = screen.getByLabelText('New Zone Name') as HTMLInputElement;
    expect(input).toBeDisabled();
    
    const cancelButton = screen.getByRole('button', { name: /Cancel/i });
    expect(cancelButton).toBeDisabled();
  });

  it('closes dialog when Cancel is clicked', () => {
    const mockOnClose = jest.fn();
    
    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={mockOnClose} zone={mockZone} />
    );

    const cancelButton = screen.getByRole('button', { name: /Cancel/i });
    fireEvent.click(cancelButton);

    expect(mockOnClose).toHaveBeenCalled();
  });

  it('displays zone cloning details', () => {
    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={jest.fn()} zone={mockZone} />
    );

    expect(screen.getByText(/All DNS records/)).toBeInTheDocument();
    expect(screen.getByText(/Zone settings/)).toBeInTheDocument();
    expect(screen.getByText(/DNSSEC configuration/)).toBeInTheDocument();
  });

  it('handles null zone gracefully', () => {
    renderWithProvider(
      <ZoneCloneDialog open={true} onClose={jest.fn()} zone={null} />
    );

    const cloneButton = screen.getByRole('button', { name: /Clone Zone/i });
    expect(cloneButton).toBeDisabled();
  });
});