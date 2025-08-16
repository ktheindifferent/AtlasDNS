export interface FilterPreset {
  id: string;
  name: string;
  description?: string;
  query: any;
  isPublic: boolean;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
  tags?: string[];
}

export interface SearchHistory {
  id: string;
  query: string;
  timestamp: Date;
  resultCount: number;
}

export interface TimeRange {
  start: Date | null;
  end: Date | null;
  preset?: 'last-hour' | 'last-24h' | 'last-7d' | 'last-30d' | 'last-90d' | 'custom';
}

export interface FilterState {
  query: any;
  timeRange: TimeRange;
  quickFilters: string[];
  columnFilters: Record<string, any>;
  searchTerm: string;
  regex?: string;
  naturalLanguageQuery?: string;
}

export interface ExportFormat {
  format: 'csv' | 'json' | 'xml' | 'excel' | 'pdf';
  includeHeaders: boolean;
  selectedColumns?: string[];
}

export interface FacetValue {
  value: string;
  count: number;
  selected: boolean;
}

export interface Facet {
  field: string;
  label: string;
  values: FacetValue[];
  type: 'checkbox' | 'range' | 'date';
}

export interface QueryBuilderField {
  name: string;
  label: string;
  type: 'text' | 'number' | 'select' | 'date' | 'boolean';
  operators?: string[];
  values?: { name: string; label: string }[];
  defaultOperator?: string;
  defaultValue?: any;
  validator?: (value: any) => boolean | string;
}

export interface DNSRecordFilter {
  recordTypes?: string[];
  zones?: string[];
  ttlRange?: { min: number; max: number };
  priority?: { min: number; max: number };
  status?: ('active' | 'inactive' | 'pending')[];
  tags?: string[];
  createdDate?: TimeRange;
  modifiedDate?: TimeRange;
}