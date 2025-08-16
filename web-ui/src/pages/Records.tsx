import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  IconButton,
  Chip,
  TextField,
  InputAdornment,
  Menu,
  MenuItem,
  Dialog,
  Select,
  FormControl,
  InputLabel,
  Tooltip,
  Alert,
} from '@mui/material';
import { DataGrid, GridColDef, GridRenderCellParams } from '@mui/x-data-grid';
import {
  Add,
  Search,
  FilterList,
  MoreVert,
  Edit,
  Delete,
  ContentCopy,
  ArrowBack,
  Upload,
  Download,
} from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { recordApi, zoneApi } from '../services/api';
import RecordFormDialog from '../components/records/RecordFormDialog';
import BulkImportDialog from '../components/records/BulkImportDialog';
import { useSnackbar } from 'notistack';
import { AdvancedFilter } from '../components/filtering';
import { useAdvancedFiltering } from '../hooks/useAdvancedFiltering';
import { QueryBuilderField, Facet } from '../types/filtering';
import { InlineHelpBubble, SmartFAQ, NaturalLanguageSearch } from '../components/HelpSystem';

interface DNSRecord {
  id: string;
  name: string;
  type: string;
  value: string;
  ttl: number;
  priority?: number;
  weight?: number;
  port?: number;
  target?: string;
  enabled: boolean;
  comment?: string;
  createdAt: string;
  modifiedAt: string;
}

const Records: React.FC = () => {
  const { zoneId } = useParams<{ zoneId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  
  const [searchTerm, setSearchTerm] = useState('');
  const [recordTypeFilter, setRecordTypeFilter] = useState('ALL');
  const [selectedRecords, setSelectedRecords] = useState<string[]>([]);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedRecord, setSelectedRecord] = useState<DNSRecord | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [bulkImportOpen, setBulkImportOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);

  // Advanced filtering
  const {
    filterState,
    updateFilter,
    clearFilters,
    savedFilters,
    saveFilter,
    deleteFilter,
    searchHistory,
    addToHistory,
    exportData,
  } = useAdvancedFiltering({
    persistToUrl: true,
    storageKey: 'recordsFilter',
  });

  // Query builder fields
  const queryBuilderFields: QueryBuilderField[] = [
    {
      name: 'name',
      label: 'Name',
      type: 'text',
      operators: ['=', '!=', 'contains', 'beginsWith', 'endsWith'],
    },
    {
      name: 'type',
      label: 'Type',
      type: 'select',
      values: [
        { name: 'A', label: 'A' },
        { name: 'AAAA', label: 'AAAA' },
        { name: 'CNAME', label: 'CNAME' },
        { name: 'MX', label: 'MX' },
        { name: 'TXT', label: 'TXT' },
        { name: 'NS', label: 'NS' },
        { name: 'SOA', label: 'SOA' },
        { name: 'PTR', label: 'PTR' },
        { name: 'SRV', label: 'SRV' },
        { name: 'CAA', label: 'CAA' },
      ],
      operators: ['=', '!=', 'in', 'notIn'],
    },
    {
      name: 'value',
      label: 'Value',
      type: 'text',
      operators: ['=', '!=', 'contains', 'doesNotContain'],
    },
    {
      name: 'ttl',
      label: 'TTL',
      type: 'number',
      operators: ['=', '!=', '>', '>=', '<', '<='],
    },
    {
      name: 'priority',
      label: 'Priority',
      type: 'number',
      operators: ['=', '!=', '>', '>=', '<', '<='],
    },
    {
      name: 'enabled',
      label: 'Status',
      type: 'boolean',
      operators: ['='],
    },
    {
      name: 'createdAt',
      label: 'Created Date',
      type: 'date',
      operators: ['=', '!=', '>', '>=', '<', '<='],
    },
    {
      name: 'modifiedAt',
      label: 'Modified Date',
      type: 'date',
      operators: ['=', '!=', '>', '>=', '<', '<='],
    },
  ];

  // Generate facets from records data
  const facets: Facet[] = useMemo(() => {
    if (!records || records.length === 0) return [];
    
    // Count occurrences for each facet
    const typeCounts: Record<string, number> = {};
    const statusCounts: Record<string, number> = {};
    
    records.forEach((record: DNSRecord) => {
      typeCounts[record.type] = (typeCounts[record.type] || 0) + 1;
      statusCounts[record.enabled ? 'Active' : 'Inactive'] = 
        (statusCounts[record.enabled ? 'Active' : 'Inactive'] || 0) + 1;
    });

    return [
      {
        field: 'type',
        label: 'Record Type',
        type: 'checkbox',
        values: Object.entries(typeCounts).map(([value, count]) => ({
          value,
          count,
          selected: false,
        })),
      },
      {
        field: 'status',
        label: 'Status',
        type: 'checkbox',
        values: Object.entries(statusCounts).map(([value, count]) => ({
          value,
          count,
          selected: false,
        })),
      },
      {
        field: 'ttl',
        label: 'TTL Range',
        type: 'range',
        values: [],
      },
      {
        field: 'dateRange',
        label: 'Date Created',
        type: 'date',
        values: [],
      },
    ];
  }, [records]);

  // Fetch zone details
  const { data: zone } = useQuery({
    queryKey: ['zone', zoneId],
    queryFn: async () => {
      if (!zoneId) return null;
      const response = await zoneApi.get(zoneId);
      return response.data;
    },
    enabled: !!zoneId,
  });

  // Fetch records with advanced filtering
  const { data: records, isLoading, refetch } = useQuery({
    queryKey: ['records', zoneId, filterState],
    queryFn: async () => {
      if (!zoneId) return [];
      const params: any = {};
      
      // Apply advanced filters
      if (filterState.searchTerm) {
        params.search = filterState.searchTerm;
      }
      
      if (filterState.query && filterState.query.rules.length > 0) {
        params.filter = JSON.stringify(filterState.query);
      }
      
      if (filterState.quickFilters.length > 0) {
        params.quickFilters = filterState.quickFilters;
      }
      
      if (filterState.timeRange.start && filterState.timeRange.end) {
        params.startDate = filterState.timeRange.start;
        params.endDate = filterState.timeRange.end;
      }
      
      if (filterState.regex) {
        params.regex = filterState.regex;
      }
      
      if (Object.keys(filterState.columnFilters).length > 0) {
        params.facets = filterState.columnFilters;
      }
      
      const response = await recordApi.list(zoneId, params);
      const data = response.data.records || [];
      
      // Add to search history if we have results
      if (filterState.searchTerm && data.length > 0) {
        addToHistory(filterState.searchTerm, data.length);
      }
      
      return data;
    },
    enabled: !!zoneId,
  });

  // Delete record mutation
  const deleteRecord = useMutation({
    mutationFn: async (recordId: string) => {
      if (!zoneId) throw new Error('No zone ID');
      return await recordApi.delete(zoneId, recordId);
    },
    onSuccess: () => {
      enqueueSnackbar('Record deleted successfully', { variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['records', zoneId] });
      setDeleteDialogOpen(false);
    },
    onError: () => {
      enqueueSnackbar('Failed to delete record', { variant: 'error' });
    },
  });

  // Bulk delete mutation
  const bulkDelete = useMutation({
    mutationFn: async (recordIds: string[]) => {
      if (!zoneId) throw new Error('No zone ID');
      return await recordApi.bulkDelete(zoneId, { ids: recordIds });
    },
    onSuccess: () => {
      enqueueSnackbar('Records deleted successfully', { variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['records', zoneId] });
      setSelectedRecords([]);
    },
    onError: () => {
      enqueueSnackbar('Failed to delete records', { variant: 'error' });
    },
  });

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, record: DNSRecord) => {
    setAnchorEl(event.currentTarget);
    setSelectedRecord(record);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleEditRecord = () => {
    setEditDialogOpen(true);
    handleMenuClose();
  };

  const handleDeleteRecord = () => {
    setDeleteDialogOpen(true);
    handleMenuClose();
  };

  const handleCloneRecord = () => {
    if (selectedRecord) {
      const { id, ...recordWithoutId } = selectedRecord;
      const clonedRecord = { ...recordWithoutId, name: `${selectedRecord.name}-copy` };
      setSelectedRecord(null); // Clear selected record first
      setCreateDialogOpen(true);
    }
    handleMenuClose();
  };

  const handleExport = async (format: string, options: any) => {
    if (records && records.length > 0) {
      await exportData(records, format, options);
      enqueueSnackbar(`Exported ${records.length} records to ${format.toUpperCase()}`, { variant: 'success' });
    } else {
      enqueueSnackbar('No records to export', { variant: 'warning' });
    }
  };

  const getRecordTypeColor = (type: string) => {
    const colors: { [key: string]: any } = {
      'A': 'primary',
      'AAAA': 'primary',
      'CNAME': 'secondary',
      'MX': 'warning',
      'TXT': 'info',
      'NS': 'success',
      'SOA': 'error',
      'PTR': 'default',
      'SRV': 'default',
    };
    return colors[type] || 'default';
  };

  const columns: GridColDef[] = [
    {
      field: 'name',
      headerName: 'Name',
      flex: 1,
      minWidth: 200,
      renderCell: (params: GridRenderCellParams) => (
        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
          {params.value || '@'}
        </Typography>
      ),
    },
    {
      field: 'type',
      headerName: 'Type',
      width: 100,
      renderCell: (params: GridRenderCellParams) => (
        <Chip
          label={params.value}
          size="small"
          color={getRecordTypeColor(params.value)}
        />
      ),
    },
    {
      field: 'value',
      headerName: 'Value',
      flex: 2,
      minWidth: 250,
      renderCell: (params: GridRenderCellParams) => (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography
            variant="body2"
            sx={{
              fontFamily: 'monospace',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {params.value}
          </Typography>
          <Tooltip title="Copy value">
            <IconButton
              size="small"
              onClick={(e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(params.value);
                enqueueSnackbar('Copied to clipboard', { variant: 'success' });
              }}
            >
              <ContentCopy fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      ),
    },
    {
      field: 'ttl',
      headerName: 'TTL',
      width: 100,
      renderCell: (params: GridRenderCellParams) => (
        <Typography variant="body2">
          {params.value}s
        </Typography>
      ),
    },
    {
      field: 'priority',
      headerName: 'Priority',
      width: 100,
      renderCell: (params: GridRenderCellParams) => (
        params.value ? (
          <Typography variant="body2">{params.value}</Typography>
        ) : '-'
      ),
    },
    {
      field: 'enabled',
      headerName: 'Status',
      width: 100,
      renderCell: (params: GridRenderCellParams) => (
        <Chip
          label={params.value ? 'Active' : 'Disabled'}
          size="small"
          color={params.value ? 'success' : 'default'}
        />
      ),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 80,
      sortable: false,
      renderCell: (params: GridRenderCellParams) => (
        <IconButton
          size="small"
          onClick={(e) => handleMenuOpen(e, params.row as DNSRecord)}
        >
          <MoreVert />
        </IconButton>
      ),
    },
  ];

  const recordTypes = ['ALL', 'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'];

  return (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <IconButton onClick={() => navigate('/zones')}>
          <ArrowBack />
        </IconButton>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h4" fontWeight="bold">
            DNS Records
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Zone: {zone?.name}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<Upload />}
            onClick={() => setBulkImportOpen(true)}
          >
            Bulk Import
          </Button>
          <Button
            variant="outlined"
            startIcon={<Download />}
            onClick={handleExport}
          >
            Export
          </Button>
          <InlineHelpBubble
            content={{
              title: 'Add DNS Record',
              description: 'Create a new DNS record for this zone. Choose the appropriate record type based on your needs.',
              tips: [
                'A records map domains to IPv4 addresses',
                'AAAA records map domains to IPv6 addresses',
                'CNAME records create aliases to other domains',
                'MX records define mail servers',
                'TXT records store text data for verification'
              ],
              checklist: [
                { label: 'Choose the correct record type' },
                { label: 'Enter valid hostname (@ for root)' },
                { label: 'Set appropriate TTL value' },
                { label: 'Test after creating' }
              ],
              videoUrl: '#',
              docsUrl: '#',
            }}
            position="left"
            interactive={true}
            pulseAnimation={true}
          >
            <Button
              variant="contained"
              startIcon={<Add />}
              onClick={() => setCreateDialogOpen(true)}
            >
              Add Record
            </Button>
          </InlineHelpBubble>
        </Box>
      </Box>

      <AdvancedFilter
        fields={queryBuilderFields}
        onFilterChange={updateFilter}
        onExport={handleExport}
        showTimeRange={true}
        showNaturalLanguage={true}
        showRegex={true}
        showFacets={true}
        facets={facets}
        savedFilters={savedFilters}
        onSaveFilter={saveFilter}
        onDeleteFilter={deleteFilter}
        searchHistory={searchHistory}
      />

      <Paper sx={{ p: 2, mb: 2 }}>
<<<<<<< HEAD
=======
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <InlineHelpBubble
            content={{
              title: 'Search DNS Records',
              description: 'Search by record name, value, or type. Use wildcards (*) for partial matches.',
              tips: [
                'Search by subdomain: "api" or "www"',
                'Search by IP address: "192.168"',
                'Use * for wildcard: "*.example.com"'
              ],
              examples: [
                { label: 'Find all A records', value: 'type:A', copyable: true },
                { label: 'Find MX records', value: 'type:MX', copyable: true },
              ],
            }}
            position="bottom"
            interactive={true}
          >
            <TextField
              placeholder="Search records..."
              variant="outlined"
              size="small"
              fullWidth
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Search />
                  </InputAdornment>
                ),
              }}
            />
          </InlineHelpBubble>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Type</InputLabel>
            <Select
              value={recordTypeFilter}
              onChange={(e) => setRecordTypeFilter(e.target.value)}
              label="Type"
            >
              {recordTypes.map(type => (
                <MenuItem key={type} value={type}>{type}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <Tooltip title="Filter">
            <IconButton>
              <FilterList />
            </IconButton>
          </Tooltip>
        </Box>
>>>>>>> origin/master

        {selectedRecords.length > 0 && (
          <Alert severity="info" sx={{ mb: 2 }}>
            {selectedRecords.length} record(s) selected
            <Button
              size="small"
              color="error"
              onClick={() => bulkDelete.mutate(selectedRecords)}
              sx={{ ml: 2 }}
            >
              Delete Selected
            </Button>
          </Alert>
        )}

        <DataGrid
          rows={records || []}
          columns={columns}
          loading={isLoading}
          checkboxSelection
          onRowSelectionModelChange={(selection) => setSelectedRecords(selection as string[])}
          rowSelectionModel={selectedRecords}
          autoHeight
          disableRowSelectionOnClick
          pageSizeOptions={[10, 25, 50, 100]}
          initialState={{
            pagination: {
              paginationModel: { pageSize: 25 },
            },
          }}
          sx={{
            '& .MuiDataGrid-cell:focus': {
              outline: 'none',
            },
          }}
        />
      </Paper>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={handleEditRecord}>
          <Edit sx={{ mr: 1 }} fontSize="small" />
          Edit Record
        </MenuItem>
        <MenuItem onClick={handleCloneRecord}>
          <ContentCopy sx={{ mr: 1 }} fontSize="small" />
          Clone Record
        </MenuItem>
        <MenuItem onClick={handleDeleteRecord} sx={{ color: 'error.main' }}>
          <Delete sx={{ mr: 1 }} fontSize="small" />
          Delete Record
        </MenuItem>
      </Menu>

      <RecordFormDialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        mode="create"
        zoneId={zoneId!}
        record={selectedRecord}
      />

      <RecordFormDialog
        open={editDialogOpen}
        onClose={() => setEditDialogOpen(false)}
        mode="edit"
        zoneId={zoneId!}
        record={selectedRecord}
      />

      <BulkImportDialog
        open={bulkImportOpen}
        onClose={() => setBulkImportOpen(false)}
        zoneId={zoneId!}
      />

      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <Box sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Delete Record
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Are you sure you want to delete this record? This action cannot be undone.
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
            <Button
              variant="contained"
              color="error"
              onClick={() => selectedRecord && deleteRecord.mutate(selectedRecord.id)}
            >
              Delete
            </Button>
          </Box>
        </Box>
      </Dialog>
    </Box>
  );
};

export default Records;