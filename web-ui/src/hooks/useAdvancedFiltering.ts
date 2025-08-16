import { useState, useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { FilterState, FilterPreset, SearchHistory } from '../types/filtering';
import { RuleGroupType, formatQuery } from 'react-querybuilder';
import Papa from 'papaparse';
import { saveAs } from 'file-saver';

interface UseAdvancedFilteringOptions {
  defaultFilter?: Partial<FilterState>;
  onFilterChange?: (filter: FilterState) => void;
  persistToUrl?: boolean;
  storageKey?: string;
}

export const useAdvancedFiltering = (options: UseAdvancedFilteringOptions = {}) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [filterState, setFilterState] = useState<FilterState>(() => {
    // Try to load from URL params first
    if (options.persistToUrl) {
      const filterParam = searchParams.get('filter');
      if (filterParam) {
        try {
          return JSON.parse(decodeURIComponent(filterParam));
        } catch (e) {
          console.error('Failed to parse filter from URL', e);
        }
      }
    }

    // Try to load from localStorage
    if (options.storageKey) {
      const stored = localStorage.getItem(options.storageKey);
      if (stored) {
        try {
          return JSON.parse(stored);
        } catch (e) {
          console.error('Failed to parse filter from localStorage', e);
        }
      }
    }

    // Use default filter
    return {
      query: { combinator: 'and', rules: [] },
      timeRange: { start: null, end: null },
      quickFilters: [],
      columnFilters: {},
      searchTerm: '',
      ...options.defaultFilter,
    };
  });

  const [savedFilters, setSavedFilters] = useState<FilterPreset[]>(() => {
    const stored = localStorage.getItem('savedFilters');
    return stored ? JSON.parse(stored) : [];
  });

  const [searchHistory, setSearchHistory] = useState<SearchHistory[]>(() => {
    const stored = localStorage.getItem('searchHistory');
    return stored ? JSON.parse(stored) : [];
  });

  // Persist filter state to URL
  useEffect(() => {
    if (options.persistToUrl) {
      const params = new URLSearchParams(searchParams);
      params.set('filter', encodeURIComponent(JSON.stringify(filterState)));
      setSearchParams(params, { replace: true });
    }
  }, [filterState, options.persistToUrl, searchParams, setSearchParams]);

  // Persist filter state to localStorage
  useEffect(() => {
    if (options.storageKey) {
      localStorage.setItem(options.storageKey, JSON.stringify(filterState));
    }
  }, [filterState, options.storageKey]);

  // Persist saved filters to localStorage
  useEffect(() => {
    localStorage.setItem('savedFilters', JSON.stringify(savedFilters));
  }, [savedFilters]);

  // Persist search history to localStorage
  useEffect(() => {
    localStorage.setItem('searchHistory', JSON.stringify(searchHistory));
  }, [searchHistory]);

  const updateFilter = useCallback((newFilter: Partial<FilterState>) => {
    setFilterState(prev => {
      const updated = { ...prev, ...newFilter };
      if (options.onFilterChange) {
        options.onFilterChange(updated);
      }
      return updated;
    });
  }, [options]);

  const clearFilters = useCallback(() => {
    const cleared: FilterState = {
      query: { combinator: 'and', rules: [] },
      timeRange: { start: null, end: null },
      quickFilters: [],
      columnFilters: {},
      searchTerm: '',
    };
    setFilterState(cleared);
    if (options.onFilterChange) {
      options.onFilterChange(cleared);
    }
  }, [options]);

  const saveFilter = useCallback((preset: FilterPreset) => {
    setSavedFilters(prev => [...prev, preset]);
  }, []);

  const deleteFilter = useCallback((id: string) => {
    setSavedFilters(prev => prev.filter(f => f.id !== id));
  }, []);

  const addToHistory = useCallback((query: string, resultCount: number) => {
    const historyItem: SearchHistory = {
      id: Date.now().toString(),
      query,
      timestamp: new Date(),
      resultCount,
    };
    setSearchHistory(prev => [historyItem, ...prev].slice(0, 100)); // Keep last 100 items
  }, []);

  const clearHistory = useCallback(() => {
    setSearchHistory([]);
  }, []);

  const exportData = useCallback(async (
    data: any[],
    format: string,
    options: {
      includeHeaders?: boolean;
      selectedColumns?: string[];
      dateFormat?: string;
      delimiter?: string;
      includeMetadata?: boolean;
    } = {}
  ) => {
    const {
      includeHeaders = true,
      selectedColumns,
      dateFormat = 'iso',
      delimiter = ',',
      includeMetadata = false,
    } = options;

    // Filter columns if specified
    let exportData = data;
    if (selectedColumns && selectedColumns.length > 0) {
      exportData = data.map(row => {
        const filtered: any = {};
        selectedColumns.forEach(col => {
          filtered[col] = row[col];
        });
        return filtered;
      });
    }

    // Format dates
    if (dateFormat !== 'iso') {
      exportData = exportData.map(row => {
        const formatted: any = {};
        Object.keys(row).forEach(key => {
          if (row[key] instanceof Date) {
            if (dateFormat === 'unix') {
              formatted[key] = row[key].getTime();
            } else if (dateFormat === 'locale') {
              formatted[key] = row[key].toLocaleString();
            }
          } else {
            formatted[key] = row[key];
          }
        });
        return formatted;
      });
    }

    let blob: Blob;
    let filename: string;

    switch (format) {
      case 'csv':
        const csv = Papa.unparse(exportData, {
          header: includeHeaders,
          delimiter,
        });
        blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        filename = `export-${Date.now()}.csv`;
        break;

      case 'json':
        const jsonData = includeMetadata ? {
          metadata: {
            exportDate: new Date().toISOString(),
            recordCount: exportData.length,
            filters: filterState,
          },
          data: exportData,
        } : exportData;
        blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
        filename = `export-${Date.now()}.json`;
        break;

      case 'xml':
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<records>\n';
        if (includeMetadata) {
          xml += '  <metadata>\n';
          xml += `    <exportDate>${new Date().toISOString()}</exportDate>\n`;
          xml += `    <recordCount>${exportData.length}</recordCount>\n`;
          xml += '  </metadata>\n';
        }
        exportData.forEach(row => {
          xml += '  <record>\n';
          Object.keys(row).forEach(key => {
            xml += `    <${key}>${row[key]}</${key}>\n`;
          });
          xml += '  </record>\n';
        });
        xml += '</records>';
        blob = new Blob([xml], { type: 'application/xml' });
        filename = `export-${Date.now()}.xml`;
        break;

      default:
        throw new Error(`Unsupported export format: ${format}`);
    }

    saveAs(blob, filename);
  }, [filterState]);

  const convertQueryToSQL = useCallback((query: RuleGroupType): string => {
    return formatQuery(query, 'sql');
  }, []);

  const convertQueryToMongoDB = useCallback((query: RuleGroupType): object => {
    const convertRule = (rule: any): any => {
      if (rule.rules) {
        const conditions = rule.rules.map(convertRule).filter(Boolean);
        if (conditions.length === 0) return null;
        
        const operator = rule.combinator === 'and' ? '$and' : '$or';
        return { [operator]: conditions };
      }

      const { field, operator, value } = rule;
      switch (operator) {
        case '=':
          return { [field]: value };
        case '!=':
          return { [field]: { $ne: value } };
        case '>':
          return { [field]: { $gt: value } };
        case '>=':
          return { [field]: { $gte: value } };
        case '<':
          return { [field]: { $lt: value } };
        case '<=':
          return { [field]: { $lte: value } };
        case 'contains':
          return { [field]: { $regex: value, $options: 'i' } };
        case 'doesNotContain':
          return { [field]: { $not: { $regex: value, $options: 'i' } } };
        case 'beginsWith':
          return { [field]: { $regex: `^${value}`, $options: 'i' } };
        case 'endsWith':
          return { [field]: { $regex: `${value}$`, $options: 'i' } };
        case 'in':
          return { [field]: { $in: value.split(',').map((v: string) => v.trim()) } };
        case 'notIn':
          return { [field]: { $nin: value.split(',').map((v: string) => v.trim()) } };
        default:
          return null;
      }
    };

    return convertRule(query) || {};
  }, []);

  return {
    filterState,
    updateFilter,
    clearFilters,
    savedFilters,
    saveFilter,
    deleteFilter,
    searchHistory,
    addToHistory,
    clearHistory,
    exportData,
    convertQueryToSQL,
    convertQueryToMongoDB,
  };
};