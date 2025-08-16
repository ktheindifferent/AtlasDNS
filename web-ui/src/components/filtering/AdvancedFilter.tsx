import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Tabs,
  Tab,
  Button,
  IconButton,
  Tooltip,
  Collapse,
  Badge,
  Chip,
  Stack,
  Typography,
  Divider,
} from '@mui/material';
import {
  FilterList,
  Save,
  Share,
  Clear,
  ExpandMore,
  ExpandLess,
  Download,
  History,
  QueryBuilder as QueryBuilderIcon,
  Search,
  Code,
  Timeline,
} from '@mui/icons-material';
import { QueryBuilder, formatQuery, RuleGroupType } from 'react-querybuilder';
import 'react-querybuilder/dist/query-builder.css';
import NaturalLanguageSearch from './NaturalLanguageSearch';
import FacetedSearch from './FacetedSearch';
import TimeRangePicker from './TimeRangePicker';
import QuickFilterChips from './QuickFilterChips';
import SavedFilters from './SavedFilters';
import SearchHistory from './SearchHistory';
import RegexFilter from './RegexFilter';
import ExportDialog from './ExportDialog';
import { FilterState, TimeRange, FilterPreset, QueryBuilderField } from '../../types/filtering';
import { useSnackbar } from 'notistack';

interface AdvancedFilterProps {
  fields: QueryBuilderField[];
  onFilterChange: (filter: FilterState) => void;
  onExport?: (format: string, filters: FilterState) => void;
  defaultFilter?: Partial<FilterState>;
  showTimeRange?: boolean;
  showNaturalLanguage?: boolean;
  showRegex?: boolean;
  showFacets?: boolean;
  facets?: any[];
  savedFilters?: FilterPreset[];
  onSaveFilter?: (filter: FilterPreset) => void;
  onDeleteFilter?: (id: string) => void;
  searchHistory?: any[];
}

const AdvancedFilter: React.FC<AdvancedFilterProps> = ({
  fields,
  onFilterChange,
  onExport,
  defaultFilter,
  showTimeRange = true,
  showNaturalLanguage = true,
  showRegex = true,
  showFacets = true,
  facets = [],
  savedFilters = [],
  onSaveFilter,
  onDeleteFilter,
  searchHistory = [],
}) => {
  const { enqueueSnackbar } = useSnackbar();
  const [expanded, setExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState(0);
  const [query, setQuery] = useState<RuleGroupType>({
    combinator: 'and',
    rules: [],
  });
  const [timeRange, setTimeRange] = useState<TimeRange>({
    start: null,
    end: null,
    preset: 'last-24h',
  });
  const [quickFilters, setQuickFilters] = useState<string[]>([]);
  const [naturalLanguageQuery, setNaturalLanguageQuery] = useState('');
  const [regexPattern, setRegexPattern] = useState('');
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [facetFilters, setFacetFilters] = useState<Record<string, any>>({});

  useEffect(() => {
    if (defaultFilter) {
      if (defaultFilter.query) setQuery(defaultFilter.query);
      if (defaultFilter.timeRange) setTimeRange(defaultFilter.timeRange);
      if (defaultFilter.quickFilters) setQuickFilters(defaultFilter.quickFilters);
      if (defaultFilter.naturalLanguageQuery) setNaturalLanguageQuery(defaultFilter.naturalLanguageQuery);
      if (defaultFilter.regex) setRegexPattern(defaultFilter.regex);
    }
  }, [defaultFilter]);

  const handleFilterChange = useCallback(() => {
    const filterState: FilterState = {
      query,
      timeRange,
      quickFilters,
      columnFilters: facetFilters,
      searchTerm: naturalLanguageQuery,
      regex: regexPattern || undefined,
      naturalLanguageQuery: naturalLanguageQuery || undefined,
    };
    onFilterChange(filterState);
  }, [query, timeRange, quickFilters, facetFilters, naturalLanguageQuery, regexPattern, onFilterChange]);

  useEffect(() => {
    handleFilterChange();
  }, [query, timeRange, quickFilters, facetFilters, naturalLanguageQuery, regexPattern]);

  const handleClearFilters = () => {
    setQuery({ combinator: 'and', rules: [] });
    setTimeRange({ start: null, end: null, preset: 'last-24h' });
    setQuickFilters([]);
    setNaturalLanguageQuery('');
    setRegexPattern('');
    setFacetFilters({});
    enqueueSnackbar('Filters cleared', { variant: 'info' });
  };

  const handleSaveFilter = () => {
    setSaveDialogOpen(true);
  };

  const handleShareFilter = () => {
    const filterState: FilterState = {
      query,
      timeRange,
      quickFilters,
      columnFilters: facetFilters,
      searchTerm: naturalLanguageQuery,
      regex: regexPattern || undefined,
    };
    
    const shareableUrl = `${window.location.origin}${window.location.pathname}?filter=${encodeURIComponent(
      JSON.stringify(filterState)
    )}`;
    
    navigator.clipboard.writeText(shareableUrl);
    enqueueSnackbar('Filter URL copied to clipboard', { variant: 'success' });
  };

  const activeFiltersCount = 
    (query.rules?.length || 0) +
    (quickFilters.length || 0) +
    (naturalLanguageQuery ? 1 : 0) +
    (regexPattern ? 1 : 0) +
    Object.keys(facetFilters).length;

  return (
    <Paper elevation={2} sx={{ mb: 2 }}>
      <Box sx={{ p: 2 }}>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={2}>
            <Badge badgeContent={activeFiltersCount} color="primary">
              <FilterList />
            </Badge>
            <Typography variant="h6">Advanced Filters</Typography>
            {!expanded && activeFiltersCount > 0 && (
              <Stack direction="row" spacing={1}>
                {quickFilters.slice(0, 3).map((filter) => (
                  <Chip key={filter} label={filter} size="small" />
                ))}
                {quickFilters.length > 3 && (
                  <Chip label={`+${quickFilters.length - 3} more`} size="small" />
                )}
              </Stack>
            )}
          </Box>
          <Box display="flex" alignItems="center" gap={1}>
            <Tooltip title="Clear all filters">
              <IconButton onClick={handleClearFilters} size="small">
                <Clear />
              </IconButton>
            </Tooltip>
            <Tooltip title="Save filter preset">
              <IconButton onClick={handleSaveFilter} size="small">
                <Save />
              </IconButton>
            </Tooltip>
            <Tooltip title="Share filter">
              <IconButton onClick={handleShareFilter} size="small">
                <Share />
              </IconButton>
            </Tooltip>
            <Tooltip title="Export results">
              <IconButton onClick={() => setExportDialogOpen(true)} size="small">
                <Download />
              </IconButton>
            </Tooltip>
            <Tooltip title="Search history">
              <IconButton onClick={() => setHistoryOpen(true)} size="small">
                <History />
              </IconButton>
            </Tooltip>
            <IconButton onClick={() => setExpanded(!expanded)}>
              {expanded ? <ExpandLess /> : <ExpandMore />}
            </IconButton>
          </Box>
        </Box>

        <Collapse in={expanded}>
          <Divider sx={{ my: 2 }} />
          
          <Tabs value={activeTab} onChange={(_, value) => setActiveTab(value)} sx={{ mb: 2 }}>
            <Tab icon={<QueryBuilderIcon />} label="Query Builder" />
            {showNaturalLanguage && <Tab icon={<Search />} label="Natural Language" />}
            {showFacets && <Tab icon={<FilterList />} label="Faceted Search" />}
            {showRegex && <Tab icon={<Code />} label="Regex" />}
            {showTimeRange && <Tab icon={<Timeline />} label="Time Range" />}
          </Tabs>

          <Box sx={{ minHeight: 300 }}>
            {activeTab === 0 && (
              <Box>
                <QueryBuilder
                  fields={fields}
                  query={query}
                  onQueryChange={setQuery}
                  controlElements={{
                    addRuleAction: (props: any) => (
                      <Button {...props} variant="outlined" size="small">
                        Add Rule
                      </Button>
                    ),
                    addGroupAction: (props: any) => (
                      <Button {...props} variant="outlined" size="small">
                        Add Group
                      </Button>
                    ),
                  }}
                />
                <Box sx={{ mt: 2 }}>
                  <Typography variant="caption" color="textSecondary">
                    SQL: {formatQuery(query, 'sql')}
                  </Typography>
                </Box>
              </Box>
            )}

            {showNaturalLanguage && activeTab === 1 && (
              <NaturalLanguageSearch
                value={naturalLanguageQuery}
                onChange={setNaturalLanguageQuery}
                onQueryParse={(parsedQuery) => setQuery(parsedQuery)}
                suggestions={searchHistory.map(h => h.query)}
              />
            )}

            {showFacets && activeTab === 2 && (
              <FacetedSearch
                facets={facets}
                selectedFacets={facetFilters}
                onChange={setFacetFilters}
              />
            )}

            {showRegex && activeTab === 3 && (
              <RegexFilter
                value={regexPattern}
                onChange={setRegexPattern}
                testData={[]}
              />
            )}

            {showTimeRange && activeTab === 4 && (
              <TimeRangePicker
                value={timeRange}
                onChange={setTimeRange}
              />
            )}
          </Box>

          <Divider sx={{ my: 2 }} />

          <QuickFilterChips
            selected={quickFilters}
            onChange={setQuickFilters}
            options={[
              'Active Records',
              'Modified Today',
              'High Priority',
              'A Records',
              'CNAME Records',
              'MX Records',
              'TXT Records',
              'NS Records',
              'SOA Records',
              'PTR Records',
              'AAAA Records',
              'SRV Records',
              'CAA Records',
            ]}
          />
        </Collapse>
      </Box>

      <SavedFilters
        open={saveDialogOpen}
        onClose={() => setSaveDialogOpen(false)}
        onSave={onSaveFilter}
        currentFilter={{
          query,
          timeRange,
          quickFilters,
          columnFilters: facetFilters,
          searchTerm: naturalLanguageQuery,
          regex: regexPattern,
        }}
        savedFilters={savedFilters}
        onLoad={(filter) => {
          setQuery(filter.query);
          setTimeRange(filter.timeRange);
          setQuickFilters(filter.quickFilters);
          setFacetFilters(filter.columnFilters);
          setNaturalLanguageQuery(filter.searchTerm);
          setRegexPattern(filter.regex || '');
          setSaveDialogOpen(false);
          enqueueSnackbar('Filter loaded', { variant: 'success' });
        }}
        onDelete={onDeleteFilter}
      />

      <SearchHistory
        open={historyOpen}
        onClose={() => setHistoryOpen(false)}
        history={searchHistory}
        onSelect={(item) => {
          setNaturalLanguageQuery(item.query);
          setHistoryOpen(false);
        }}
      />

      <ExportDialog
        open={exportDialogOpen}
        onClose={() => setExportDialogOpen(false)}
        onExport={(format) => {
          if (onExport) {
            onExport(format, {
              query,
              timeRange,
              quickFilters,
              columnFilters: facetFilters,
              searchTerm: naturalLanguageQuery,
              regex: regexPattern,
            });
          }
          setExportDialogOpen(false);
        }}
      />
    </Paper>
  );
};

export default AdvancedFilter;