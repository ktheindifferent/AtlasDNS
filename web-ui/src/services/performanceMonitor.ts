import { getCLS, getFCP, getFID, getLCP, getTTFB, Metric } from 'web-vitals';

export interface PerformanceMetric {
  id: string;
  name: string;
  value: number;
  rating: 'good' | 'needs-improvement' | 'poor';
  timestamp: number;
}

export interface ResourceTiming {
  name: string;
  initiatorType: string;
  startTime: number;
  duration: number;
  transferSize: number;
  encodedBodySize: number;
  decodedBodySize: number;
}

export interface ComponentRenderMetric {
  componentName: string;
  renderTime: number;
  timestamp: number;
  props?: Record<string, any>;
}

export interface APIMetric {
  endpoint: string;
  method: string;
  duration: number;
  status: number;
  timestamp: number;
  size?: number;
}

export interface MemoryMetric {
  usedJSHeapSize: number;
  totalJSHeapSize: number;
  jsHeapSizeLimit: number;
  timestamp: number;
}

export interface PerformanceBudget {
  metric: string;
  threshold: number;
  unit: 'ms' | 'kb' | 'mb' | 'score';
}

class PerformanceMonitor {
  private metrics: PerformanceMetric[] = [];
  private componentMetrics: ComponentRenderMetric[] = [];
  private apiMetrics: APIMetric[] = [];
  private memoryMetrics: MemoryMetric[] = [];
  private resourceTimings: ResourceTiming[] = [];
  private budgets: PerformanceBudget[] = [];
  private observers: Map<string, PerformanceObserver> = new Map();
  private metricsEndpoint: string = '/api/metrics';
  private bufferSize: number = 100;
  private reportingInterval: number = 30000; // 30 seconds
  private reportingTimer: NodeJS.Timeout | null = null;

  constructor() {
    this.initializeWebVitals();
    this.initializePerformanceObservers();
    this.initializeMemoryMonitoring();
    this.startReporting();
    this.setupBudgets();
  }

  private initializeWebVitals(): void {
    getCLS(this.handleWebVitalMetric.bind(this));
    getFCP(this.handleWebVitalMetric.bind(this));
    getFID(this.handleWebVitalMetric.bind(this));
    getLCP(this.handleWebVitalMetric.bind(this));
    getTTFB(this.handleWebVitalMetric.bind(this));
  }

  private handleWebVitalMetric(metric: Metric): void {
    const performanceMetric: PerformanceMetric = {
      id: metric.id,
      name: metric.name,
      value: metric.value,
      rating: metric.rating || 'needs-improvement',
      timestamp: Date.now(),
    };

    this.addMetric(performanceMetric);
    this.checkBudget(metric.name, metric.value);
  }

  private initializePerformanceObservers(): void {
    if ('PerformanceObserver' in window) {
      // Observe navigation timing
      try {
        const navigationObserver = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (entry.entryType === 'navigation') {
              this.processNavigationTiming(entry as PerformanceNavigationTiming);
            }
          }
        });
        navigationObserver.observe({ entryTypes: ['navigation'] });
        this.observers.set('navigation', navigationObserver);
      } catch (e) {
        console.warn('Navigation observer not supported:', e);
      }

      // Observe resource timing
      try {
        const resourceObserver = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (entry.entryType === 'resource') {
              this.processResourceTiming(entry as PerformanceResourceTiming);
            }
          }
        });
        resourceObserver.observe({ entryTypes: ['resource'] });
        this.observers.set('resource', resourceObserver);
      } catch (e) {
        console.warn('Resource observer not supported:', e);
      }

      // Observe long tasks
      try {
        const longTaskObserver = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            this.processLongTask(entry);
          }
        });
        longTaskObserver.observe({ entryTypes: ['longtask'] });
        this.observers.set('longtask', longTaskObserver);
      } catch (e) {
        console.warn('Long task observer not supported:', e);
      }

      // Observe layout shifts
      try {
        const layoutShiftObserver = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if ('value' in entry) {
              this.processLayoutShift(entry as any);
            }
          }
        });
        layoutShiftObserver.observe({ entryTypes: ['layout-shift'] });
        this.observers.set('layout-shift', layoutShiftObserver);
      } catch (e) {
        console.warn('Layout shift observer not supported:', e);
      }
    }
  }

  private processNavigationTiming(entry: PerformanceNavigationTiming): void {
    const metrics = {
      domContentLoaded: entry.domContentLoadedEventEnd - entry.domContentLoadedEventStart,
      loadComplete: entry.loadEventEnd - entry.loadEventStart,
      domInteractive: entry.domInteractive - entry.fetchStart,
      domComplete: entry.domComplete - entry.fetchStart,
    };

    Object.entries(metrics).forEach(([name, value]) => {
      this.addMetric({
        id: `nav-${name}-${Date.now()}`,
        name,
        value,
        rating: this.getRating(name, value),
        timestamp: Date.now(),
      });
    });
  }

  private processResourceTiming(entry: PerformanceResourceTiming): void {
    const timing: ResourceTiming = {
      name: entry.name,
      initiatorType: entry.initiatorType,
      startTime: entry.startTime,
      duration: entry.duration,
      transferSize: entry.transferSize || 0,
      encodedBodySize: entry.encodedBodySize || 0,
      decodedBodySize: entry.decodedBodySize || 0,
    };

    this.resourceTimings.push(timing);
    if (this.resourceTimings.length > this.bufferSize) {
      this.resourceTimings.shift();
    }
  }

  private processLongTask(entry: PerformanceEntry): void {
    this.addMetric({
      id: `longtask-${Date.now()}`,
      name: 'longTask',
      value: entry.duration,
      rating: entry.duration > 100 ? 'poor' : entry.duration > 50 ? 'needs-improvement' : 'good',
      timestamp: Date.now(),
    });
  }

  private processLayoutShift(entry: any): void {
    if (!entry.hadRecentInput) {
      this.addMetric({
        id: `cls-${Date.now()}`,
        name: 'layoutShift',
        value: entry.value,
        rating: entry.value > 0.25 ? 'poor' : entry.value > 0.1 ? 'needs-improvement' : 'good',
        timestamp: Date.now(),
      });
    }
  }

  private initializeMemoryMonitoring(): void {
    if ('memory' in performance) {
      setInterval(() => {
        const memory = (performance as any).memory;
        const metric: MemoryMetric = {
          usedJSHeapSize: memory.usedJSHeapSize,
          totalJSHeapSize: memory.totalJSHeapSize,
          jsHeapSizeLimit: memory.jsHeapSizeLimit,
          timestamp: Date.now(),
        };
        
        this.memoryMetrics.push(metric);
        if (this.memoryMetrics.length > this.bufferSize) {
          this.memoryMetrics.shift();
        }

        // Check for potential memory leaks
        if (this.memoryMetrics.length > 10) {
          const recentMetrics = this.memoryMetrics.slice(-10);
          const isIncreasing = recentMetrics.every((m, i) => 
            i === 0 || m.usedJSHeapSize >= recentMetrics[i - 1].usedJSHeapSize
          );
          
          if (isIncreasing) {
            this.notifyMemoryLeak();
          }
        }
      }, 5000); // Check every 5 seconds
    }
  }

  private setupBudgets(): void {
    this.budgets = [
      { metric: 'LCP', threshold: 2500, unit: 'ms' },
      { metric: 'FID', threshold: 100, unit: 'ms' },
      { metric: 'CLS', threshold: 0.1, unit: 'score' },
      { metric: 'FCP', threshold: 1800, unit: 'ms' },
      { metric: 'TTFB', threshold: 600, unit: 'ms' },
      { metric: 'bundleSize', threshold: 500, unit: 'kb' },
    ];
  }

  private getRating(metricName: string, value: number): 'good' | 'needs-improvement' | 'poor' {
    const thresholds: Record<string, { good: number; poor: number }> = {
      LCP: { good: 2500, poor: 4000 },
      FID: { good: 100, poor: 300 },
      CLS: { good: 0.1, poor: 0.25 },
      FCP: { good: 1800, poor: 3000 },
      TTFB: { good: 600, poor: 1800 },
      domContentLoaded: { good: 1000, poor: 3000 },
      loadComplete: { good: 2000, poor: 5000 },
    };

    const threshold = thresholds[metricName];
    if (!threshold) return 'needs-improvement';

    if (value <= threshold.good) return 'good';
    if (value >= threshold.poor) return 'poor';
    return 'needs-improvement';
  }

  private addMetric(metric: PerformanceMetric): void {
    this.metrics.push(metric);
    if (this.metrics.length > this.bufferSize) {
      this.metrics.shift();
    }
  }

  public trackComponentRender(componentName: string, renderTime: number, props?: Record<string, any>): void {
    const metric: ComponentRenderMetric = {
      componentName,
      renderTime,
      timestamp: Date.now(),
      props,
    };

    this.componentMetrics.push(metric);
    if (this.componentMetrics.length > this.bufferSize) {
      this.componentMetrics.shift();
    }
  }

  public trackAPICall(endpoint: string, method: string, duration: number, status: number, size?: number): void {
    const metric: APIMetric = {
      endpoint,
      method,
      duration,
      status,
      timestamp: Date.now(),
      size,
    };

    this.apiMetrics.push(metric);
    if (this.apiMetrics.length > this.bufferSize) {
      this.apiMetrics.shift();
    }

    this.checkBudget('apiResponse', duration);
  }

  private checkBudget(metric: string, value: number): void {
    const budget = this.budgets.find(b => b.metric === metric);
    if (budget && value > budget.threshold) {
      this.notifyBudgetExceeded(metric, value, budget.threshold);
    }
  }

  private notifyBudgetExceeded(metric: string, value: number, threshold: number): void {
    const event = new CustomEvent('performance-budget-exceeded', {
      detail: { metric, value, threshold },
    });
    window.dispatchEvent(event);
  }

  private notifyMemoryLeak(): void {
    const event = new CustomEvent('potential-memory-leak', {
      detail: { memoryMetrics: this.memoryMetrics.slice(-10) },
    });
    window.dispatchEvent(event);
  }

  private startReporting(): void {
    this.reportingTimer = setInterval(() => {
      this.reportMetrics();
    }, this.reportingInterval);
  }

  private async reportMetrics(): Promise<void> {
    const data = {
      webVitals: this.metrics,
      componentMetrics: this.componentMetrics,
      apiMetrics: this.apiMetrics,
      memoryMetrics: this.memoryMetrics,
      resourceTimings: this.resourceTimings,
      timestamp: Date.now(),
      userAgent: navigator.userAgent,
      url: window.location.href,
    };

    try {
      await fetch(this.metricsEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
    } catch (error) {
      console.error('Failed to report metrics:', error);
    }
  }

  public getMetrics(): PerformanceMetric[] {
    return [...this.metrics];
  }

  public getComponentMetrics(): ComponentRenderMetric[] {
    return [...this.componentMetrics];
  }

  public getAPIMetrics(): APIMetric[] {
    return [...this.apiMetrics];
  }

  public getMemoryMetrics(): MemoryMetric[] {
    return [...this.memoryMetrics];
  }

  public getResourceTimings(): ResourceTiming[] {
    return [...this.resourceTimings];
  }

  public getBudgets(): PerformanceBudget[] {
    return [...this.budgets];
  }

  public setBudget(metric: string, threshold: number, unit: 'ms' | 'kb' | 'mb' | 'score'): void {
    const existingIndex = this.budgets.findIndex(b => b.metric === metric);
    if (existingIndex >= 0) {
      this.budgets[existingIndex] = { metric, threshold, unit };
    } else {
      this.budgets.push({ metric, threshold, unit });
    }
  }

  public clearMetrics(): void {
    this.metrics = [];
    this.componentMetrics = [];
    this.apiMetrics = [];
    this.memoryMetrics = [];
    this.resourceTimings = [];
  }

  public destroy(): void {
    if (this.reportingTimer) {
      clearInterval(this.reportingTimer);
    }
    
    this.observers.forEach(observer => observer.disconnect());
    this.observers.clear();
  }
}

export const performanceMonitor = new PerformanceMonitor();
export default performanceMonitor;