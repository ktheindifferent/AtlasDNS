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
  Tooltip,
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
  Security,
  Download,
  Upload,
  Refresh,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { RootState, AppDispatch } from '../store';
import { fetchZones, deleteZone, Zone } from '../store/slices/zonesSlice';
import ZoneFormDialog from '../components/zones/ZoneFormDialog';
import ZoneImportDialog from '../components/zones/ZoneImportDialog';
import { useSnackbar } from 'notistack';
import { format } from 'date-fns';
import LiveCursors from '../components/collaboration/LiveCursors';
import ActivityFeed from '../components/collaboration/ActivityFeed';
import CommentSystem from '../components/collaboration/CommentSystem';
import { useCollaboration } from '../contexts/CollaborationContext';

const Zones: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch<AppDispatch>();
  const { enqueueSnackbar } = useSnackbar();
  const { zones, loading, totalCount } = useSelector((state: RootState) => state.zones);
  const { trackActivity, trackChange } = useCollaboration();
  const { user: currentUser } = useSelector((state: RootState) => state.auth);
  const containerRef = React.useRef<HTMLDivElement>(null);
  
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedZones, setSelectedZones] = useState<string[]>([]);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedZone, setSelectedZone] = useState<Zone | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [showActivityFeed, setShowActivityFeed] = useState(false);
  const [showComments, setShowComments] = useState(false);
  const [paginationModel, setPaginationModel] = useState({
    page: 0,
    pageSize: 10,
  });

  useEffect(() => {
    dispatch(fetchZones({
      page: paginationModel.page + 1,
      limit: paginationModel.pageSize,
      search: searchTerm,
    }));
  }, [dispatch, paginationModel, searchTerm]);

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, zone: Zone) => {
    setAnchorEl(event.currentTarget);
    setSelectedZone(zone);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleEditZone = () => {
    setEditDialogOpen(true);
    handleMenuClose();
  };

  const handleDeleteZone = async () => {
    if (selectedZone) {
      try {
        await dispatch(deleteZone(selectedZone.id)).unwrap();
        enqueueSnackbar('Zone deleted successfully', { variant: 'success' });
        
        // Track the deletion in collaboration system
        trackActivity({
          userId: currentUser?.id || '',
          user: {
            id: currentUser?.id || '',
            name: currentUser?.name || currentUser?.email || '',
            email: currentUser?.email || '',
            color: '#2196F3',
          },
          action: 'delete',
          entityType: 'zone',
          entityId: selectedZone.id,
          entityName: selectedZone.name,
          details: `Deleted DNS zone ${selectedZone.name}`,
        });
        
        trackChange({
          userId: currentUser?.id || '',
          user: {
            id: currentUser?.id || '',
            name: currentUser?.name || currentUser?.email || '',
            email: currentUser?.email || '',
            color: '#2196F3',
          },
          action: 'delete',
          entityType: 'zone',
          entityId: selectedZone.id,
          changes: [{
            field: 'zone',
            oldValue: selectedZone,
            newValue: null,
          }],
          description: `Deleted zone ${selectedZone.name}`,
        });
      } catch (error) {
        enqueueSnackbar('Failed to delete zone', { variant: 'error' });
      }
    }
    setDeleteDialogOpen(false);
    handleMenuClose();
  };

  const handleCloneZone = () => {
    // TODO: Implement zone cloning
    enqueueSnackbar('Zone cloning not yet implemented', { variant: 'info' });
    handleMenuClose();
  };

  const handleViewRecords = () => {
    if (selectedZone) {
      navigate(`/zones/${selectedZone.id}/records`);
    }
    handleMenuClose();
  };

  const handleEnableDNSSEC = () => {
    if (selectedZone) {
      navigate(`/dnssec?zone=${selectedZone.id}`);
    }
    handleMenuClose();
  };

  const handleExportZone = () => {
    // TODO: Implement zone export
    enqueueSnackbar('Zone export not yet implemented', { variant: 'info' });
    handleMenuClose();
  };

  const columns: GridColDef[] = [
    {
      field: 'name',
      headerName: 'Zone Name',
      flex: 1,
      minWidth: 200,
      renderCell: (params: GridRenderCellParams) => (
        <Typography
          variant="body2"
          sx={{
            fontWeight: 500,
            cursor: 'pointer',
            '&:hover': { textDecoration: 'underline' },
          }}
          onClick={() => navigate(`/zones/${params.row.id}/records`)}
        >
          {params.value}
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
          color={params.value === 'master' ? 'primary' : 'default'}
        />
      ),
    },
    {
      field: 'status',
      headerName: 'Status',
      width: 120,
      renderCell: (params: GridRenderCellParams) => (
        <Chip
          label={params.value}
          size="small"
          color={
            params.value === 'active' ? 'success' :
            params.value === 'error' ? 'error' : 'default'
          }
        />
      ),
    },
    {
      field: 'records',
      headerName: 'Records',
      width: 100,
      align: 'center',
    },
    {
      field: 'dnssecEnabled',
      headerName: 'DNSSEC',
      width: 100,
      renderCell: (params: GridRenderCellParams) => (
        params.value ? (
          <Chip icon={<Security />} label="Enabled" size="small" color="success" />
        ) : (
          <Chip label="Disabled" size="small" variant="outlined" />
        )
      ),
    },
    {
      field: 'lastModified',
      headerName: 'Last Modified',
      width: 180,
      renderCell: (params: GridRenderCellParams) => (
        <Typography variant="body2" color="text.secondary">
          {format(new Date(params.value), 'MMM dd, yyyy HH:mm')}
        </Typography>
      ),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 100,
      sortable: false,
      renderCell: (params: GridRenderCellParams) => (
        <IconButton
          size="small"
          onClick={(e) => handleMenuOpen(e, params.row as Zone)}
        >
          <MoreVert />
        </IconButton>
      ),
    },
  ];

  return (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" fontWeight="bold">
          DNS Zones
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<Upload />}
            onClick={() => setImportDialogOpen(true)}
          >
            Import
          </Button>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setCreateDialogOpen(true)}
          >
            Add Zone
          </Button>
        </Box>
      </Box>

      <Paper sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <TextField
            placeholder="Search zones..."
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
          <Tooltip title="Filter">
            <IconButton>
              <FilterList />
            </IconButton>
          </Tooltip>
          <Tooltip title="Refresh">
            <IconButton onClick={() => dispatch(fetchZones())}>
              <Refresh />
            </IconButton>
          </Tooltip>
        </Box>

        {selectedZones.length > 0 && (
          <Box sx={{ mb: 2, display: 'flex', gap: 2 }}>
            <Typography variant="body2" color="text.secondary">
              {selectedZones.length} zone(s) selected
            </Typography>
            <Button size="small" startIcon={<Download />}>
              Export Selected
            </Button>
            <Button size="small" color="error" startIcon={<Delete />}>
              Delete Selected
            </Button>
          </Box>
        )}

        <DataGrid
          rows={zones}
          columns={columns}
          loading={loading}
          paginationModel={paginationModel}
          onPaginationModelChange={setPaginationModel}
          pageSizeOptions={[10, 25, 50]}
          checkboxSelection
          onRowSelectionModelChange={(selection) => setSelectedZones(selection as string[])}
          rowSelectionModel={selectedZones}
          autoHeight
          disableRowSelectionOnClick
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
        <MenuItem onClick={handleViewRecords}>
          <Edit sx={{ mr: 1 }} fontSize="small" />
          View Records
        </MenuItem>
        <MenuItem onClick={handleEditZone}>
          <Edit sx={{ mr: 1 }} fontSize="small" />
          Edit Zone
        </MenuItem>
        <MenuItem onClick={handleCloneZone}>
          <ContentCopy sx={{ mr: 1 }} fontSize="small" />
          Clone Zone
        </MenuItem>
        <MenuItem onClick={handleEnableDNSSEC}>
          <Security sx={{ mr: 1 }} fontSize="small" />
          DNSSEC Settings
        </MenuItem>
        <MenuItem onClick={handleExportZone}>
          <Download sx={{ mr: 1 }} fontSize="small" />
          Export Zone
        </MenuItem>
        <MenuItem onClick={() => setDeleteDialogOpen(true)} sx={{ color: 'error.main' }}>
          <Delete sx={{ mr: 1 }} fontSize="small" />
          Delete Zone
        </MenuItem>
      </Menu>

      <ZoneFormDialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        mode="create"
      />

      <ZoneFormDialog
        open={editDialogOpen}
        onClose={() => setEditDialogOpen(false)}
        mode="edit"
        zone={selectedZone}
      />

      <ZoneImportDialog
        open={importDialogOpen}
        onClose={() => setImportDialogOpen(false)}
      />

      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <Box sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Delete Zone
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Are you sure you want to delete the zone "{selectedZone?.name}"? This action cannot be undone.
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
            <Button variant="contained" color="error" onClick={handleDeleteZone}>
              Delete
            </Button>
          </Box>
        </Box>
      </Dialog>
    </Box>
  );
};

export default Zones;