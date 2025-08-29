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
  LinearProgress,
  Backdrop,
  CircularProgress,
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
import { fetchZones, deleteZone, exportZone, Zone } from '../store/slices/zonesSlice';
import ZoneFormDialog from '../components/zones/ZoneFormDialog';
import ZoneImportDialog from '../components/zones/ZoneImportDialog';
import ZoneCloneDialog from '../components/zones/ZoneCloneDialog';
import errorMonitoring from '../services/errorMonitoring';
import { format } from 'date-fns';
import LiveCursors from '../components/collaboration/LiveCursors';
import ActivityFeed from '../components/collaboration/ActivityFeed';
import CommentSystem from '../components/collaboration/CommentSystem';
import { useCollaboration } from '../contexts/CollaborationContext';
import useErrorToast from '../hooks/useErrorToast';

const Zones: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch<AppDispatch>();
  const { showError, showSuccess, showInfo, showWarning } = useErrorToast();
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
  const [cloneDialogOpen, setCloneDialogOpen] = useState(false);
  const [showActivityFeed, setShowActivityFeed] = useState(false);
  const [showComments, setShowComments] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [loadingZones, setLoadingZones] = useState<string[]>([]);
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
      setIsDeleting(true);
      setLoadingZones(prev => [...prev, selectedZone.id]);
      
      try {
        await dispatch(deleteZone(selectedZone.id)).unwrap();
        showSuccess(`Zone "${selectedZone.name}" deleted successfully`);
        
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
        showError(error instanceof Error ? error : 'Failed to delete zone');
      } finally {
        setIsDeleting(false);
        setLoadingZones(prev => prev.filter(id => id !== selectedZone.id));
      }
    }
    setDeleteDialogOpen(false);
    handleMenuClose();
  };

  const handleCloneZone = () => {
    setCloneDialogOpen(true);
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

  const handleExportZone = async () => {
    if (!selectedZone) {
      return;
    }
    
    handleMenuClose();
    setIsExporting(true);
    
    try {
      // Add breadcrumb for monitoring
      errorMonitoring.addBreadcrumb({
        message: `Exporting zone: ${selectedZone.name}`,
        category: 'zone-operations',
        level: 'info',
        data: { zoneId: selectedZone.id, zoneName: selectedZone.name },
      });
      
      const result = await dispatch(exportZone(selectedZone.id)).unwrap();
      
      // Create a blob with the zone data
      const blob = new Blob([result.content || JSON.stringify(result)], { 
        type: result.mimeType || 'text/plain' 
      });
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${selectedZone.name}_${new Date().toISOString().split('T')[0]}.zone`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      showSuccess(`Zone "${selectedZone.name}" exported successfully`);
      
      // Track activity
      trackActivity({
        userId: currentUser?.id || '',
        user: {
          id: currentUser?.id || '',
          name: currentUser?.name || currentUser?.email || '',
          email: currentUser?.email || '',
          color: '#2196F3',
        },
        action: 'export',
        entityType: 'zone',
        entityId: selectedZone.id,
        entityName: selectedZone.name,
        details: `Exported DNS zone ${selectedZone.name}`,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to export zone';
      
      // Log error to monitoring
      errorMonitoring.captureException(error instanceof Error ? error : new Error(errorMessage), {
        context: 'zone-export',
        zoneId: selectedZone.id,
        zoneName: selectedZone.name,
      });
      
      showError(errorMessage);
    } finally {
      setIsExporting(false);
    }
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
      renderCell: (params: GridRenderCellParams) => {
        const isLoading = loadingZones.includes(params.row.id);
        return isLoading ? (
          <CircularProgress size={20} />
        ) : (
          <IconButton
            size="small"
            onClick={(e) => handleMenuOpen(e, params.row as Zone)}
          >
            <MoreVert />
          </IconButton>
        );
      },
    },
  ];

  return (
    <Box>
      {/* Loading overlay for export operation */}
      <Backdrop
        sx={{ color: '#fff', zIndex: (theme) => theme.zIndex.drawer + 1 }}
        open={isExporting}
      >
        <Box sx={{ textAlign: 'center' }}>
          <CircularProgress color="inherit" />
          <Typography variant="h6" sx={{ mt: 2 }}>
            Exporting zone...
          </Typography>
        </Box>
      </Backdrop>
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

      <Paper sx={{ p: 2, mb: 2, position: 'relative' }}>
        {/* Loading bar for async operations */}
        {(loading || isDeleting || isExporting || loadingZones.length > 0) && (
          <LinearProgress 
            sx={{ 
              position: 'absolute', 
              top: 0, 
              left: 0, 
              right: 0,
              zIndex: 1,
            }} 
          />
        )}
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
      
      <ZoneCloneDialog
        open={cloneDialogOpen}
        onClose={() => setCloneDialogOpen(false)}
        zone={selectedZone}
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
            <Button onClick={() => setDeleteDialogOpen(false)} disabled={isDeleting}>
              Cancel
            </Button>
            <Button 
              variant="contained" 
              color="error" 
              onClick={handleDeleteZone}
              disabled={isDeleting}
              startIcon={isDeleting ? <CircularProgress size={16} color="inherit" /> : null}
            >
              {isDeleting ? 'Deleting...' : 'Delete'}
            </Button>
          </Box>
        </Box>
      </Dialog>
    </Box>
  );
};

export default Zones;