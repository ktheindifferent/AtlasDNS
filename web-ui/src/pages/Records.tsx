import React, { useState, useEffect } from 'react';
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

  // Fetch records
  const { data: records, isLoading, refetch } = useQuery({
    queryKey: ['records', zoneId, searchTerm, recordTypeFilter],
    queryFn: async () => {
      if (!zoneId) return [];
      const params: any = {};
      if (searchTerm) params.search = searchTerm;
      if (recordTypeFilter !== 'ALL') params.type = recordTypeFilter;
      
      const response = await recordApi.list(zoneId, params);
      return response.data.records || [];
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

  const handleExport = () => {
    // TODO: Implement export functionality
    enqueueSnackbar('Export functionality coming soon', { variant: 'info' });
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
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setCreateDialogOpen(true)}
          >
            Add Record
          </Button>
        </Box>
      </Box>

      <Paper sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
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