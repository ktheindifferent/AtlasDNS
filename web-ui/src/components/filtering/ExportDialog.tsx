import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  RadioGroup,
  FormControlLabel,
  Radio,
  FormControl,
  FormLabel,
  Checkbox,
  Typography,
  Box,
  Stack,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
} from '@mui/material';
import {
  Download,
  Description,
  TableChart,
  Code,
  PictureAsPdf,
  ArticleOutlined,
} from '@mui/icons-material';
import { ExportFormat } from '../../types/filtering';

interface ExportDialogProps {
  open: boolean;
  onClose: () => void;
  onExport: (format: string, options: ExportOptions) => void;
  availableColumns?: string[];
  recordCount?: number;
}

interface ExportOptions {
  format: string;
  includeHeaders: boolean;
  selectedColumns: string[];
  dateFormat: string;
  delimiter?: string;
  includeMetadata: boolean;
}

const ExportDialog: React.FC<ExportDialogProps> = ({
  open,
  onClose,
  onExport,
  availableColumns = [
    'id',
    'name',
    'type',
    'value',
    'ttl',
    'priority',
    'weight',
    'port',
    'enabled',
    'comment',
    'createdAt',
    'modifiedAt',
  ],
  recordCount = 0,
}) => {
  const [format, setFormat] = useState('csv');
  const [includeHeaders, setIncludeHeaders] = useState(true);
  const [selectedColumns, setSelectedColumns] = useState<string[]>(availableColumns);
  const [dateFormat, setDateFormat] = useState('iso');
  const [delimiter, setDelimiter] = useState(',');
  const [includeMetadata, setIncludeMetadata] = useState(false);

  const formats = [
    {
      value: 'csv',
      label: 'CSV',
      icon: <TableChart />,
      description: 'Comma-separated values, compatible with Excel',
    },
    {
      value: 'json',
      label: 'JSON',
      icon: <Code />,
      description: 'JavaScript Object Notation, ideal for APIs',
    },
    {
      value: 'xml',
      label: 'XML',
      icon: <ArticleOutlined />,
      description: 'Extensible Markup Language',
    },
    {
      value: 'excel',
      label: 'Excel',
      icon: <Description />,
      description: 'Microsoft Excel format (.xlsx)',
    },
    {
      value: 'pdf',
      label: 'PDF',
      icon: <PictureAsPdf />,
      description: 'Portable Document Format for reports',
    },
  ];

  const handleColumnToggle = (column: string) => {
    if (selectedColumns.includes(column)) {
      setSelectedColumns(selectedColumns.filter(c => c !== column));
    } else {
      setSelectedColumns([...selectedColumns, column]);
    }
  };

  const handleSelectAll = () => {
    if (selectedColumns.length === availableColumns.length) {
      setSelectedColumns([]);
    } else {
      setSelectedColumns(availableColumns);
    }
  };

  const handleExport = () => {
    const options: ExportOptions = {
      format,
      includeHeaders,
      selectedColumns,
      dateFormat,
      delimiter: format === 'csv' ? delimiter : undefined,
      includeMetadata,
    };
    
    onExport(format, options);
    onClose();
  };

  const getEstimatedSize = () => {
    // Rough estimation based on format and record count
    const baseSize = recordCount * selectedColumns.length * 20; // bytes per field
    const multiplier = {
      csv: 1,
      json: 1.5,
      xml: 2,
      excel: 1.2,
      pdf: 3,
    }[format] || 1;
    
    const sizeInBytes = baseSize * multiplier;
    
    if (sizeInBytes < 1024) {
      return `${sizeInBytes} bytes`;
    } else if (sizeInBytes < 1024 * 1024) {
      return `${(sizeInBytes / 1024).toFixed(1)} KB`;
    } else {
      return `${(sizeInBytes / (1024 * 1024)).toFixed(1)} MB`;
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Export Filtered Results</DialogTitle>
      
      <DialogContent>
        <Stack spacing={3}>
          {recordCount > 0 && (
            <Alert severity="info">
              Exporting {recordCount.toLocaleString()} records
              {selectedColumns.length < availableColumns.length && 
                ` with ${selectedColumns.length} of ${availableColumns.length} columns`}
            </Alert>
          )}

          <FormControl component="fieldset">
            <FormLabel component="legend">Export Format</FormLabel>
            <RadioGroup value={format} onChange={(e) => setFormat(e.target.value)}>
              {formats.map((fmt) => (
                <FormControlLabel
                  key={fmt.value}
                  value={fmt.value}
                  control={<Radio />}
                  label={
                    <Box display="flex" alignItems="center" gap={1}>
                      {fmt.icon}
                      <Box>
                        <Typography variant="body2">{fmt.label}</Typography>
                        <Typography variant="caption" color="textSecondary">
                          {fmt.description}
                        </Typography>
                      </Box>
                    </Box>
                  }
                />
              ))}
            </RadioGroup>
          </FormControl>

          <Divider />

          <Box>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
              <Typography variant="subtitle2">Select Columns</Typography>
              <Button size="small" onClick={handleSelectAll}>
                {selectedColumns.length === availableColumns.length ? 'Deselect All' : 'Select All'}
              </Button>
            </Box>
            <List dense sx={{ maxHeight: 200, overflow: 'auto' }}>
              {availableColumns.map((column) => (
                <ListItem key={column} dense button onClick={() => handleColumnToggle(column)}>
                  <ListItemIcon>
                    <Checkbox
                      edge="start"
                      checked={selectedColumns.includes(column)}
                      tabIndex={-1}
                      disableRipple
                    />
                  </ListItemIcon>
                  <ListItemText primary={column} />
                </ListItem>
              ))}
            </List>
          </Box>

          <Divider />

          <Stack spacing={2}>
            {format === 'csv' && (
              <FormControl size="small">
                <FormLabel>Delimiter</FormLabel>
                <RadioGroup row value={delimiter} onChange={(e) => setDelimiter(e.target.value)}>
                  <FormControlLabel value="," control={<Radio />} label="Comma (,)" />
                  <FormControlLabel value=";" control={<Radio />} label="Semicolon (;)" />
                  <FormControlLabel value="\t" control={<Radio />} label="Tab" />
                </RadioGroup>
              </FormControl>
            )}

            <FormControlLabel
              control={
                <Checkbox
                  checked={includeHeaders}
                  onChange={(e) => setIncludeHeaders(e.target.checked)}
                />
              }
              label="Include column headers"
              disabled={format === 'json' || format === 'xml'}
            />

            <FormControlLabel
              control={
                <Checkbox
                  checked={includeMetadata}
                  onChange={(e) => setIncludeMetadata(e.target.checked)}
                />
              }
              label="Include export metadata (timestamp, filters, etc.)"
            />

            <FormControl size="small">
              <FormLabel>Date Format</FormLabel>
              <RadioGroup row value={dateFormat} onChange={(e) => setDateFormat(e.target.value)}>
                <FormControlLabel value="iso" control={<Radio />} label="ISO 8601" />
                <FormControlLabel value="locale" control={<Radio />} label="Locale" />
                <FormControlLabel value="unix" control={<Radio />} label="Unix timestamp" />
              </RadioGroup>
            </FormControl>
          </Stack>

          <Alert severity="success">
            <Typography variant="caption">
              Estimated file size: {getEstimatedSize()}
            </Typography>
          </Alert>
        </Stack>
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          startIcon={<Download />}
          onClick={handleExport}
          disabled={selectedColumns.length === 0}
        >
          Export
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ExportDialog;