import { useSnackbar, VariantType } from 'notistack';
import { useCallback } from 'react';
import errorMonitoring from '../services/errorMonitoring';

interface ErrorToastOptions {
  variant?: VariantType;
  autoHideDuration?: number;
  persist?: boolean;
  preventDuplicate?: boolean;
  action?: React.ReactNode;
}

export const useErrorToast = () => {
  const { enqueueSnackbar, closeSnackbar } = useSnackbar();

  const showError = useCallback((
    error: Error | string,
    options: ErrorToastOptions = {}
  ) => {
    const {
      variant = 'error',
      autoHideDuration = 5000,
      persist = false,
      preventDuplicate = true,
      action,
    } = options;

    const message = typeof error === 'string' ? error : error.message;

    // Log to monitoring service
    if (typeof error !== 'string') {
      errorMonitoring.captureException(error, {
        source: 'error-toast',
        showedToUser: true,
      });
    }

    return enqueueSnackbar(message, {
      variant,
      autoHideDuration: persist ? null : autoHideDuration,
      preventDuplicate,
      action,
    });
  }, [enqueueSnackbar]);

  const showSuccess = useCallback((
    message: string,
    options: Omit<ErrorToastOptions, 'variant'> = {}
  ) => {
    const {
      autoHideDuration = 3000,
      persist = false,
      preventDuplicate = true,
      action,
    } = options;

    return enqueueSnackbar(message, {
      variant: 'success',
      autoHideDuration: persist ? null : autoHideDuration,
      preventDuplicate,
      action,
    });
  }, [enqueueSnackbar]);

  const showInfo = useCallback((
    message: string,
    options: Omit<ErrorToastOptions, 'variant'> = {}
  ) => {
    const {
      autoHideDuration = 4000,
      persist = false,
      preventDuplicate = true,
      action,
    } = options;

    return enqueueSnackbar(message, {
      variant: 'info',
      autoHideDuration: persist ? null : autoHideDuration,
      preventDuplicate,
      action,
    });
  }, [enqueueSnackbar]);

  const showWarning = useCallback((
    message: string,
    options: Omit<ErrorToastOptions, 'variant'> = {}
  ) => {
    const {
      autoHideDuration = 4000,
      persist = false,
      preventDuplicate = true,
      action,
    } = options;

    return enqueueSnackbar(message, {
      variant: 'warning',
      autoHideDuration: persist ? null : autoHideDuration,
      preventDuplicate,
      action,
    });
  }, [enqueueSnackbar]);

  const dismiss = useCallback((key?: string | number) => {
    closeSnackbar(key);
  }, [closeSnackbar]);

  return {
    showError,
    showSuccess,
    showInfo,
    showWarning,
    dismiss,
  };
};

export default useErrorToast;