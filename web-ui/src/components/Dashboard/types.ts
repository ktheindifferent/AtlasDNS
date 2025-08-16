export interface WidgetConfig {
  id: string;
  type: string;
  title: string;
  data?: any;
  refreshInterval?: number;
  customSettings?: Record<string, any>;
}

export interface DashboardLayout {
  i: string;
  x: number;
  y: number;
  w: number;
  h: number;
  minW?: number;
  maxW?: number;
  minH?: number;
  maxH?: number;
  static?: boolean;
}

export interface DashboardConfig {
  id: string;
  name: string;
  widgets: WidgetConfig[];
  layouts: {
    lg: DashboardLayout[];
    md?: DashboardLayout[];
    sm?: DashboardLayout[];
    xs?: DashboardLayout[];
  };
  createdAt: Date;
  updatedAt: Date;
}

export interface WidgetProps {
  config: WidgetConfig;
  onRemove?: (id: string) => void;
  onUpdate?: (id: string, config: Partial<WidgetConfig>) => void;
  isEditMode?: boolean;
}

export type WidgetType = 
  | 'metric'
  | 'chart'
  | 'table'
  | 'realtime'
  | 'custom'
  | 'text'
  | 'alert'
  | 'gauge';

export interface MetricData {
  value: number | string;
  label: string;
  trend?: 'up' | 'down' | 'stable';
  change?: number;
  unit?: string;
}

export interface ChartData {
  labels: string[];
  datasets: {
    label: string;
    data: number[];
    backgroundColor?: string | string[];
    borderColor?: string | string[];
  }[];
}

export interface TableData {
  columns: {
    field: string;
    headerName: string;
    width?: number;
    type?: 'string' | 'number' | 'date' | 'boolean';
  }[];
  rows: any[];
}

export interface WebSocketMessage {
  widgetId: string;
  type: 'update' | 'error' | 'info';
  data: any;
  timestamp: Date;
}