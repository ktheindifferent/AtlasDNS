import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ErrorBoundary from './ErrorBoundary';
import errorMonitoring from '../services/errorMonitoring';
import { enqueueSnackbar } from 'notistack';

// Mock the error monitoring service
jest.mock('../services/errorMonitoring', () => ({
  __esModule: true,
  default: {
    logError: jest.fn(),
    addBreadcrumb: jest.fn(),
  },
}));

// Mock notistack
jest.mock('notistack', () => ({
  enqueueSnackbar: jest.fn(),
}));

// Component that throws an error
const ThrowError: React.FC<{ shouldThrow: boolean; error?: Error }> = ({ 
  shouldThrow, 
  error = new Error('Test error') 
}) => {
  if (shouldThrow) {
    throw error;
  }
  return <div>No error</div>;
};

describe('ErrorBoundary', () => {
  let originalConsoleError: typeof console.error;

  beforeEach(() => {
    // Store original console.error and mock it
    originalConsoleError = console.error;
    console.error = jest.fn();
    
    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Restore console.error
    console.error = originalConsoleError;
  });

  it('renders children when there is no error', () => {
    render(
      <ErrorBoundary>
        <div>Test content</div>
      </ErrorBoundary>
    );

    expect(screen.getByText('Test content')).toBeInTheDocument();
  });

  it('renders error UI when child component throws', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText('Oops! Something went wrong')).toBeInTheDocument();
    expect(screen.getByText(/We encountered an unexpected error/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Try Again/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Reload Page/i })).toBeInTheDocument();
  });

  it('logs error to monitoring service', () => {
    const testError = new Error('Test monitoring error');
    
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} error={testError} />
      </ErrorBoundary>
    );

    expect(errorMonitoring.logError).toHaveBeenCalledWith(
      testError,
      expect.objectContaining({
        componentStack: expect.any(String),
      }),
      expect.objectContaining({
        errorCount: 1,
        component: 'ErrorBoundary',
      })
    );

    expect(errorMonitoring.addBreadcrumb).toHaveBeenCalledWith({
      message: 'Error caught by boundary: Test monitoring error',
      category: 'error-boundary',
      level: 'error',
      data: {
        errorCount: 1,
      },
    });
  });

  it('shows toast notification on first error', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(enqueueSnackbar).toHaveBeenCalledWith(
      'An unexpected error occurred. Our team has been notified.',
      {
        variant: 'error',
        autoHideDuration: 5000,
      }
    );
  });

  it('shows error details in development mode', () => {
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    const testError = new Error('Development error message');
    
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} error={testError} />
      </ErrorBoundary>
    );

    expect(screen.getByText('Error Details (Development Mode)')).toBeInTheDocument();
    expect(screen.getByText('Development error message')).toBeInTheDocument();

    process.env.NODE_ENV = originalNodeEnv;
  });

  it('hides error details in production mode', () => {
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    const testError = new Error('Production error message');
    
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} error={testError} />
      </ErrorBoundary>
    );

    expect(screen.queryByText('Error Details (Development Mode)')).not.toBeInTheDocument();
    expect(screen.queryByText('Production error message')).not.toBeInTheDocument();

    process.env.NODE_ENV = originalNodeEnv;
  });

  it('renders custom fallback when provided', () => {
    const customFallback = <div>Custom error fallback</div>;
    
    render(
      <ErrorBoundary fallback={customFallback}>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText('Custom error fallback')).toBeInTheDocument();
    expect(screen.queryByText('Oops! Something went wrong')).not.toBeInTheDocument();
  });

  it('resets error state when Try Again is clicked', async () => {
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText('Oops! Something went wrong')).toBeInTheDocument();

    const tryAgainButton = screen.getByRole('button', { name: /Try Again/i });
    fireEvent.click(tryAgainButton);

    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    );

    await waitFor(() => {
      expect(screen.getByText('No error')).toBeInTheDocument();
    });
  });

  it('reloads page when Reload Page is clicked', () => {
    const originalReload = window.location.reload;
    window.location.reload = jest.fn();

    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    const reloadButton = screen.getByRole('button', { name: /Reload Page/i });
    fireEvent.click(reloadButton);

    expect(window.location.reload).toHaveBeenCalled();

    window.location.reload = originalReload;
  });

  it('shows warning for multiple errors', () => {
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    );

    // Trigger multiple errors
    for (let i = 0; i < 4; i++) {
      rerender(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} error={new Error(`Error ${i + 1}`)} />
        </ErrorBoundary>
      );
    }

    expect(screen.getByText('Multiple Errors Detected')).toBeInTheDocument();
    expect(screen.getByText(/The application has encountered multiple errors/)).toBeInTheDocument();
  });

  it('increments error count on each error', () => {
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    );

    // First error
    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} error={new Error('First error')} />
      </ErrorBoundary>
    );

    expect(errorMonitoring.logError).toHaveBeenLastCalledWith(
      expect.any(Error),
      expect.any(Object),
      expect.objectContaining({
        errorCount: 1,
      })
    );

    // Reset and trigger second error
    const tryAgainButton = screen.getByRole('button', { name: /Try Again/i });
    fireEvent.click(tryAgainButton);

    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} error={new Error('Second error')} />
      </ErrorBoundary>
    );

    expect(errorMonitoring.logError).toHaveBeenLastCalledWith(
      expect.any(Error),
      expect.any(Object),
      expect.objectContaining({
        errorCount: 2,
      })
    );
  });

  it('only shows toast for first error to avoid spam', () => {
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    );

    // First error - should show toast
    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} error={new Error('First error')} />
      </ErrorBoundary>
    );

    expect(enqueueSnackbar).toHaveBeenCalledTimes(1);

    // Reset and trigger second error
    const tryAgainButton = screen.getByRole('button', { name: /Try Again/i });
    fireEvent.click(tryAgainButton);

    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} error={new Error('Second error')} />
      </ErrorBoundary>
    );

    // Should still be called only once (no additional call for second error)
    expect(enqueueSnackbar).toHaveBeenCalledTimes(1);
  });
});