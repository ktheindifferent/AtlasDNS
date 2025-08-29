import { ErrorInfo } from 'react';
import api from './api';

interface ErrorReport {
  message: string;
  stack?: string;
  componentStack?: string;
  timestamp: string;
  userAgent: string;
  url: string;
  userId?: string;
  sessionId?: string;
  metadata?: Record<string, any>;
}

interface ErrorContext {
  userId?: string;
  sessionId?: string;
  environment?: string;
  release?: string;
  tags?: Record<string, string>;
  extra?: Record<string, any>;
}

class ErrorMonitoringService {
  private context: ErrorContext = {};
  private errorQueue: ErrorReport[] = [];
  private isOnline: boolean = navigator.onLine;
  private flushInterval: NodeJS.Timeout | null = null;
  private maxQueueSize = 50;
  private flushDelay = 5000; // 5 seconds

  constructor() {
    this.initialize();
  }

  private initialize() {
    // Listen for online/offline events
    window.addEventListener('online', this.handleOnline);
    window.addEventListener('offline', this.handleOffline);

    // Set up periodic flush
    this.flushInterval = setInterval(() => {
      this.flushErrors();
    }, this.flushDelay);

    // Flush errors before page unload
    window.addEventListener('beforeunload', () => {
      this.flushErrors(true);
    });

    // Set default context
    this.setContext({
      environment: process.env.NODE_ENV || 'development',
      release: process.env.REACT_APP_VERSION || 'unknown',
    });
  }

  private handleOnline = () => {
    this.isOnline = true;
    this.flushErrors();
  };

  private handleOffline = () => {
    this.isOnline = false;
  };

  public setContext(context: Partial<ErrorContext>) {
    this.context = { ...this.context, ...context };
  }

  public setUser(userId: string, sessionId?: string) {
    this.context.userId = userId;
    if (sessionId) {
      this.context.sessionId = sessionId;
    }
  }

  public clearUser() {
    delete this.context.userId;
    delete this.context.sessionId;
  }

  public logError(error: Error, errorInfo?: ErrorInfo, metadata?: Record<string, any>) {
    const errorReport: ErrorReport = {
      message: error.message || 'Unknown error',
      stack: error.stack,
      componentStack: errorInfo?.componentStack,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href,
      userId: this.context.userId,
      sessionId: this.context.sessionId,
      metadata: {
        ...metadata,
        ...this.context.extra,
        tags: this.context.tags,
        environment: this.context.environment,
        release: this.context.release,
      },
    };

    // Add to queue
    this.errorQueue.push(errorReport);

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.group('Error Monitoring Service');
      console.error('Error:', error);
      if (errorInfo) {
        console.error('Component Stack:', errorInfo.componentStack);
      }
      console.table(errorReport);
      console.groupEnd();
    }

    // Flush immediately for critical errors
    if (this.isCriticalError(error)) {
      this.flushErrors();
    } else if (this.errorQueue.length >= this.maxQueueSize) {
      // Flush if queue is full
      this.flushErrors();
    }
  }

  private isCriticalError(error: Error): boolean {
    // Define critical error patterns
    const criticalPatterns = [
      /TypeError.*cannot read/i,
      /ReferenceError/i,
      /SecurityError/i,
      /NetworkError/i,
      /ChunkLoadError/i,
    ];

    return criticalPatterns.some(pattern => pattern.test(error.message));
  }

  private async flushErrors(sync = false) {
    if (this.errorQueue.length === 0 || !this.isOnline) {
      return;
    }

    const errors = [...this.errorQueue];
    this.errorQueue = [];

    try {
      if (sync) {
        // Use sendBeacon for synchronous sends (page unload)
        const data = JSON.stringify({ errors });
        navigator.sendBeacon('/api/v2/monitoring/errors', data);
      } else {
        // Use regular API call
        await this.sendErrorsToBackend(errors);
      }
    } catch (error) {
      // If send fails, add errors back to queue (unless it's too large)
      if (this.errorQueue.length + errors.length <= this.maxQueueSize * 2) {
        this.errorQueue = [...errors, ...this.errorQueue];
      }
      console.error('Failed to send errors to monitoring service:', error);
    }
  }

  private async sendErrorsToBackend(errors: ErrorReport[]) {
    try {
      await api.post('/monitoring/errors', {
        errors,
        context: this.context,
      });
    } catch (error) {
      // If the monitoring endpoint doesn't exist, try alternative endpoints
      if (error instanceof Error && error.message.includes('404')) {
        // Try sending to logs endpoint as fallback
        await api.post('/logs', {
          level: 'error',
          source: 'frontend',
          entries: errors.map(e => ({
            message: e.message,
            details: e,
            timestamp: e.timestamp,
          })),
        });
      } else {
        throw error;
      }
    }
  }

  public captureException(error: Error | string, metadata?: Record<string, any>) {
    const errorObj = typeof error === 'string' ? new Error(error) : error;
    this.logError(errorObj, undefined, metadata);
  }

  public captureMessage(message: string, level: 'info' | 'warning' | 'error' = 'info', metadata?: Record<string, any>) {
    const errorReport: ErrorReport = {
      message,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href,
      userId: this.context.userId,
      sessionId: this.context.sessionId,
      metadata: {
        ...metadata,
        level,
        ...this.context.extra,
      },
    };

    if (level === 'error') {
      this.errorQueue.push(errorReport);
    } else {
      // For non-error messages, send immediately if online
      if (this.isOnline) {
        this.sendErrorsToBackend([errorReport]).catch(console.error);
      }
    }
  }

  public addBreadcrumb(breadcrumb: {
    message: string;
    category?: string;
    level?: string;
    data?: Record<string, any>;
  }) {
    // Store breadcrumbs in context for future errors
    if (!this.context.extra) {
      this.context.extra = {};
    }
    if (!this.context.extra.breadcrumbs) {
      this.context.extra.breadcrumbs = [];
    }
    this.context.extra.breadcrumbs.push({
      ...breadcrumb,
      timestamp: new Date().toISOString(),
    });

    // Keep only last 20 breadcrumbs
    if (this.context.extra.breadcrumbs.length > 20) {
      this.context.extra.breadcrumbs = this.context.extra.breadcrumbs.slice(-20);
    }
  }

  public destroy() {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }
    window.removeEventListener('online', this.handleOnline);
    window.removeEventListener('offline', this.handleOffline);
    this.flushErrors(true);
  }
}

// Create singleton instance
const errorMonitoring = new ErrorMonitoringService();

// Export for use in non-React contexts
export const captureException = (error: Error | string, metadata?: Record<string, any>) => {
  errorMonitoring.captureException(error, metadata);
};

export const captureMessage = (message: string, level: 'info' | 'warning' | 'error' = 'info', metadata?: Record<string, any>) => {
  errorMonitoring.captureMessage(message, level, metadata);
};

export const addBreadcrumb = (breadcrumb: {
  message: string;
  category?: string;
  level?: string;
  data?: Record<string, any>;
}) => {
  errorMonitoring.addBreadcrumb(breadcrumb);
};

export default errorMonitoring;