import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  Alert,
  LinearProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
} from '@mui/material';
import { CheckCircle, Error } from '@mui/icons-material';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { recordApi } from '../../services/api';
import { useSnackbar } from 'notistack';

interface BulkImportDialogProps {
  open: boolean;
  onClose: () => void;
  zoneId: string;
}

interface ParsedRecord {
  name: string;
  type: string;
  value: string;
  ttl?: number;
  priority?: number;
  valid: boolean;
  error?: string;
}

const BulkImportDialog: React.FC<BulkImportDialogProps> = ({
  open,
  onClose,
  zoneId,
}) => {
  const queryClient = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  const [recordsText, setRecordsText] = useState('');
  const [parsedRecords, setParsedRecords] = useState<ParsedRecord[]>([]);
  const [showPreview, setShowPreview] = useState(false);

  const bulkCreate = useMutation({
    mutationFn: async (records: any[]) => {
      return await recordApi.bulkCreate(zoneId, { records });
    },
    onSuccess: (data) => {
      enqueueSnackbar(`Successfully imported ${data.data.created} records`, { variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['records', zoneId] });
      handleClose();
    },
    onError: () => {
      enqueueSnackbar('Failed to import records', { variant: 'error' });
    },
  });

  const parseRecords = () => {
    const lines = recordsText.trim().split('\n');
    const records: ParsedRecord[] = [];

    lines.forEach((line) => {
      const trimmedLine = line.trim();
      if (!trimmedLine || trimmedLine.startsWith(';') || trimmedLine.startsWith('#')) {
        return; // Skip empty lines and comments
      }

      try {
        // Simple parsing - expects format: name type value [ttl] [priority]
        const parts = trimmedLine.split(/\s+/);
        if (parts.length < 3) {
          records.push({
            name: trimmedLine,
            type: '',
            value: '',
            valid: false,
            error: 'Invalid format: minimum 3 fields required',
          });
          return;
        }

        const [name, type, ...rest] = parts;
        let value = '';
        let ttl: number | undefined;
        let priority: number | undefined;

        // Handle different record types
        if (type === 'MX' && rest.length >= 2) {
          priority = parseInt(rest[0]);
          value = rest.slice(1).join(' ');
        } else if (type === 'TXT') {
          // Join all remaining parts for TXT records
          value = rest.join(' ');
          // Remove quotes if present
          if (value.startsWith('"') && value.endsWith('"')) {
            value = value.slice(1, -1);
          }
        } else {
          value = rest[0] || '';
          // Check if next part is TTL (numeric)
          if (rest[1] && !isNaN(parseInt(rest[1]))) {
            ttl = parseInt(rest[1]);
          }
        }

        records.push({
          name: name === '@' ? '' : name,
          type: type.toUpperCase(),
          value,
          ttl,
          priority,
          valid: true,
        });
      } catch (error) {
        records.push({
          name: trimmedLine,
          type: '',
          value: '',
          valid: false,
          error: 'Failed to parse line',
        });
      }
    });

    setParsedRecords(records);
    setShowPreview(true);
  };

  const handleImport = () => {
    const validRecords = parsedRecords
      .filter(r => r.valid)
      .map(r => {
        const record: any = {
          name: r.name,
          type: r.type,
          value: r.value,
          ttl: r.ttl || 3600,
          enabled: true,
        };
        if (r.priority !== undefined) {
          record.priority = r.priority;
        }
        return record;
      });

    if (validRecords.length === 0) {
      enqueueSnackbar('No valid records to import', { variant: 'warning' });
      return;
    }

    bulkCreate.mutate(validRecords);
  };

  const handleClose = () => {
    setRecordsText('');
    setParsedRecords([]);
    setShowPreview(false);
    onClose();
  };

  const sampleFormat = `; Example DNS records format
; Comments start with semicolon
; Format: name type value [ttl] [priority for MX]

@           A       192.0.2.1
www         A       192.0.2.2
mail        A       192.0.2.3
@           MX      10 mail.example.com
@           TXT     "v=spf1 include:_spf.example.com ~all"
ftp         CNAME   www.example.com
ns1         A       192.0.2.10
ns2         A       192.0.2.11
@           NS      ns1.example.com
@           NS      ns2.example.com`;

  const validRecordsCount = parsedRecords.filter(r => r.valid).length;
  const invalidRecordsCount = parsedRecords.filter(r => !r.valid).length;

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="lg" fullWidth>
      <DialogTitle>Bulk Import DNS Records</DialogTitle>
      <DialogContent>
        {!showPreview ? (
          <>
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                Paste your DNS records below. Each record should be on a new line.
                Format: <strong>name type value [ttl] [priority]</strong>
              </Typography>
            </Alert>
            <TextField
              multiline
              rows={15}
              fullWidth
              variant="outlined"
              placeholder={sampleFormat}
              value={recordsText}
              onChange={(e) => setRecordsText(e.target.value)}
              sx={{ fontFamily: 'monospace' }}
            />
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              Supported types: A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, CAA
            </Typography>
          </>
        ) : (
          <>
            <Box sx={{ mb: 2, display: 'flex', gap: 2 }}>
              <Chip
                icon={<CheckCircle />}
                label={`${validRecordsCount} valid`}
                color="success"
                variant="outlined"
              />
              {invalidRecordsCount > 0 && (
                <Chip
                  icon={<Error />}
                  label={`${invalidRecordsCount} invalid`}
                  color="error"
                  variant="outlined"
                />
              )}
            </Box>
            <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
              <Table stickyHeader size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Status</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Value</TableCell>
                    <TableCell>TTL</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>Error</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {parsedRecords.map((record, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        {record.valid ? (
                          <CheckCircle color="success" fontSize="small" />
                        ) : (
                          <Error color="error" fontSize="small" />
                        )}
                      </TableCell>
                      <TableCell>{record.name || '@'}</TableCell>
                      <TableCell>{record.type}</TableCell>
                      <TableCell>{record.value}</TableCell>
                      <TableCell>{record.ttl || '3600'}</TableCell>
                      <TableCell>{record.priority || '-'}</TableCell>
                      <TableCell>
                        {record.error && (
                          <Typography variant="caption" color="error">
                            {record.error}
                          </Typography>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </>
        )}
        {bulkCreate.isPending && <LinearProgress sx={{ mt: 2 }} />}
      </DialogContent>
      <DialogActions>
        {!showPreview ? (
          <>
            <Button onClick={handleClose}>Cancel</Button>
            <Button
              onClick={parseRecords}
              variant="contained"
              disabled={!recordsText.trim()}
            >
              Preview
            </Button>
          </>
        ) : (
          <>
            <Button onClick={() => setShowPreview(false)}>Back</Button>
            <Button onClick={handleClose}>Cancel</Button>
            <Button
              onClick={handleImport}
              variant="contained"
              disabled={validRecordsCount === 0 || bulkCreate.isPending}
            >
              Import {validRecordsCount} Records
            </Button>
          </>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default BulkImportDialog;