import { useEffect, useRef, useState } from 'react';
import performanceMonitor, {
  PerformanceMetric,
  ComponentRenderMetric,
  APIMetric,
  MemoryMetric,
  ResourceTiming,
  PerformanceBudget,
} from '../services/performanceMonitor';

export interface PerformanceData {
  webVitals: PerformanceMetric[];
  componentMetrics: ComponentRenderMetric[];
  apiMetrics: APIMetric[];
  memoryMetrics: MemoryMetric[];
  resourceTimings: ResourceTiming[];
  budgets: PerformanceBudget[];
}

export const usePerformanceMonitor = () => {
  const [performanceData, setPerformanceData] = useState<PerformanceData>({
    webVitals: [],
    componentMetrics: [],
    apiMetrics: [],
    memoryMetrics: [],
    resourceTimings: [],
    budgets: [],
  });

  const [budgetAlerts, setBudgetAlerts] = useState<Array<{
    metric: string;
    value: number;
    threshold: number;
    timestamp: number;
  }>>([]);

  const [memoryLeakWarning, setMemoryLeakWarning] = useState(false);

  useEffect(() => {
    const updateInterval = setInterval(() => {
      setPerformanceData({
        webVitals: performanceMonitor.getMetrics(),
        componentMetrics: performanceMonitor.getComponentMetrics(),
        apiMetrics: performanceMonitor.getAPIMetrics(),
        memoryMetrics: performanceMonitor.getMemoryMetrics(),
        resourceTimings: performanceMonitor.getResourceTimings(),
        budgets: performanceMonitor.getBudgets(),
      });
    }, 1000);

    const handleBudgetExceeded = (event: CustomEvent) => {
      setBudgetAlerts(prev => [...prev, {
        ...event.detail,
        timestamp: Date.now(),
      }].slice(-10)); // Keep last 10 alerts
    };

    const handleMemoryLeak = () => {
      setMemoryLeakWarning(true);
      setTimeout(() => setMemoryLeakWarning(false), 10000); // Clear after 10 seconds
    };

    window.addEventListener('performance-budget-exceeded', handleBudgetExceeded as EventListener);
    window.addEventListener('potential-memory-leak', handleMemoryLeak);

    return () => {
      clearInterval(updateInterval);
      window.removeEventListener('performance-budget-exceeded', handleBudgetExceeded as EventListener);
      window.removeEventListener('potential-memory-leak', handleMemoryLeak);
    };
  }, []);

  const trackComponentRender = (componentName: string, renderTime: number, props?: Record<string, any>) => {
    performanceMonitor.trackComponentRender(componentName, renderTime, props);
  };

  const trackAPICall = (endpoint: string, method: string, duration: number, status: number, size?: number) => {
    performanceMonitor.trackAPICall(endpoint, method, duration, status, size);
  };

  const setBudget = (metric: string, threshold: number, unit: 'ms' | 'kb' | 'mb' | 'score') => {
    performanceMonitor.setBudget(metric, threshold, unit);
  };

  const clearMetrics = () => {
    performanceMonitor.clearMetrics();
    setBudgetAlerts([]);
  };

  return {
    performanceData,
    budgetAlerts,
    memoryLeakWarning,
    trackComponentRender,
    trackAPICall,
    setBudget,
    clearMetrics,
  };
};

export const useComponentPerformance = (componentName: string) => {
  const renderStartTime = useRef<number>(0);

  useEffect(() => {
    renderStartTime.current = performance.now();
  });

  useEffect(() => {
    const renderTime = performance.now() - renderStartTime.current;
    performanceMonitor.trackComponentRender(componentName, renderTime);
  });
};