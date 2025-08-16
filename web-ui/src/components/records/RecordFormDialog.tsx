import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  Switch,
  FormControlLabel,
  Alert,
} from '@mui/material';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { recordApi } from '../../services/api';
import { useSnackbar } from 'notistack';

interface RecordFormDialogProps {
  open: boolean;
  onClose: () => void;
  mode: 'create' | 'edit';
  zoneId: string;
  record?: any;
}

const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SRV', 'CAA'];

const getValidationSchema = (recordType: string) => {
  const baseSchema = {
    name: Yup.string().required('Name is required'),
    type: Yup.string().required('Type is required'),
    ttl: Yup.number()
      .required('TTL is required')
      .min(60, 'TTL must be at least 60 seconds')
      .max(604800, 'TTL cannot exceed 604800 seconds'),
    enabled: Yup.boolean(),
  };

  const typeSpecificSchema: any = {
    A: {
      value: Yup.string()
        .required('IP address is required')
        .matches(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/, 'Invalid IPv4 address'),
    },
    AAAA: {
      value: Yup.string()
        .required('IPv6 address is required')
        .matches(/^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i, 'Invalid IPv6 address'),
    },
    CNAME: {
      value: Yup.string()
        .required('Target domain is required')
        .matches(/^[a-zA-Z0-9.-]+$/, 'Invalid domain format'),
    },
    MX: {
      value: Yup.string()
        .required('Mail server is required')
        .matches(/^[a-zA-Z0-9.-]+$/, 'Invalid domain format'),
      priority: Yup.number()
        .required('Priority is required')
        .min(0, 'Priority must be 0 or greater')
        .max(65535, 'Priority cannot exceed 65535'),
    },
    TXT: {
      value: Yup.string().required('Text value is required'),
    },
    NS: {
      value: Yup.string()
        .required('Nameserver is required')
        .matches(/^[a-zA-Z0-9.-]+$/, 'Invalid nameserver format'),
    },
    PTR: {
      value: Yup.string()
        .required('Domain name is required')
        .matches(/^[a-zA-Z0-9.-]+$/, 'Invalid domain format'),
    },
    SRV: {
      priority: Yup.number()
        .required('Priority is required')
        .min(0, 'Priority must be 0 or greater'),
      weight: Yup.number()
        .required('Weight is required')
        .min(0, 'Weight must be 0 or greater'),
      port: Yup.number()
        .required('Port is required')
        .min(1, 'Port must be between 1 and 65535')
        .max(65535, 'Port must be between 1 and 65535'),
      target: Yup.string()
        .required('Target is required')
        .matches(/^[a-zA-Z0-9.-]+$/, 'Invalid target format'),
    },
    CAA: {
      value: Yup.string().required('CAA value is required'),
    },
  };

  return Yup.object({
    ...baseSchema,
    ...(typeSpecificSchema[recordType] || {}),
  });
};

const RecordFormDialog: React.FC<RecordFormDialogProps> = ({
  open,
  onClose,
  mode,
  zoneId,
  record,
}) => {
  const queryClient = useQueryClient();
  const { enqueueSnackbar } = useSnackbar();
  const [recordType, setRecordType] = useState(record?.type || 'A');

  const initialValues = {
    name: record?.name || '',
    type: record?.type || 'A',
    value: record?.value || '',
    ttl: record?.ttl || 3600,
    priority: record?.priority || '',
    weight: record?.weight || '',
    port: record?.port || '',
    target: record?.target || '',
    enabled: record?.enabled !== undefined ? record.enabled : true,
    comment: record?.comment || '',
  };

  // Create record mutation
  const createRecord = useMutation({
    mutationFn: async (values: any) => {
      return await recordApi.create(zoneId, values);
    },
    onSuccess: () => {
      enqueueSnackbar('Record created successfully', { variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['records', zoneId] });
      onClose();
    },
    onError: () => {
      enqueueSnackbar('Failed to create record', { variant: 'error' });
    },
  });

  // Update record mutation
  const updateRecord = useMutation({
    mutationFn: async (values: any) => {
      if (!record?.id) throw new Error('No record ID');
      return await recordApi.update(zoneId, record.id, values);
    },
    onSuccess: () => {
      enqueueSnackbar('Record updated successfully', { variant: 'success' });
      queryClient.invalidateQueries({ queryKey: ['records', zoneId] });
      onClose();
    },
    onError: () => {
      enqueueSnackbar('Failed to update record', { variant: 'error' });
    },
  });

  const handleSubmit = async (values: typeof initialValues) => {
    const cleanedValues = { ...values };
    
    // Remove empty optional fields
    if (!cleanedValues.priority) delete cleanedValues.priority;
    if (!cleanedValues.weight) delete cleanedValues.weight;
    if (!cleanedValues.port) delete cleanedValues.port;
    if (!cleanedValues.target) delete cleanedValues.target;
    if (!cleanedValues.comment) delete cleanedValues.comment;

    if (mode === 'create') {
      createRecord.mutate(cleanedValues);
    } else {
      updateRecord.mutate(cleanedValues);
    }
  };

  const renderTypeSpecificFields = (type: string, errors: any, touched: any) => {
    switch (type) {
      case 'A':
      case 'AAAA':
        return (
          <Grid item xs={12}>
            <Field
              as={TextField}
              name="value"
              label={type === 'A' ? 'IPv4 Address' : 'IPv6 Address'}
              fullWidth
              error={touched.value && !!errors.value}
              helperText={touched.value && errors.value}
              placeholder={type === 'A' ? '192.0.2.1' : '2001:0db8:85a3:0000:0000:8a2e:0370:7334'}
            />
          </Grid>
        );
      case 'CNAME':
      case 'NS':
        return (
          <Grid item xs={12}>
            <Field
              as={TextField}
              name="value"
              label={type === 'CNAME' ? 'Target Domain' : 'Nameserver'}
              fullWidth
              error={touched.value && !!errors.value}
              helperText={touched.value && errors.value}
              placeholder="example.com"
            />
          </Grid>
        );
      case 'MX':
        return (
          <>
            <Grid item xs={12} md={4}>
              <Field
                as={TextField}
                name="priority"
                label="Priority"
                type="number"
                fullWidth
                error={touched.priority && !!errors.priority}
                helperText={touched.priority && errors.priority}
              />
            </Grid>
            <Grid item xs={12} md={8}>
              <Field
                as={TextField}
                name="value"
                label="Mail Server"
                fullWidth
                error={touched.value && !!errors.value}
                helperText={touched.value && errors.value}
                placeholder="mail.example.com"
              />
            </Grid>
          </>
        );
      case 'TXT':
        return (
          <Grid item xs={12}>
            <Field
              as={TextField}
              name="value"
              label="Text Value"
              fullWidth
              multiline
              rows={3}
              error={touched.value && !!errors.value}
              helperText={touched.value && errors.value}
              placeholder="v=spf1 include:_spf.example.com ~all"
            />
          </Grid>
        );
      case 'SRV':
        return (
          <>
            <Grid item xs={6} md={3}>
              <Field
                as={TextField}
                name="priority"
                label="Priority"
                type="number"
                fullWidth
                error={touched.priority && !!errors.priority}
                helperText={touched.priority && errors.priority}
              />
            </Grid>
            <Grid item xs={6} md={3}>
              <Field
                as={TextField}
                name="weight"
                label="Weight"
                type="number"
                fullWidth
                error={touched.weight && !!errors.weight}
                helperText={touched.weight && errors.weight}
              />
            </Grid>
            <Grid item xs={6} md={3}>
              <Field
                as={TextField}
                name="port"
                label="Port"
                type="number"
                fullWidth
                error={touched.port && !!errors.port}
                helperText={touched.port && errors.port}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <Field
                as={TextField}
                name="target"
                label="Target"
                fullWidth
                error={touched.target && !!errors.target}
                helperText={touched.target && errors.target}
                placeholder="server.example.com"
              />
            </Grid>
          </>
        );
      case 'PTR':
        return (
          <Grid item xs={12}>
            <Field
              as={TextField}
              name="value"
              label="Domain Name"
              fullWidth
              error={touched.value && !!errors.value}
              helperText={touched.value && errors.value}
              placeholder="host.example.com"
            />
          </Grid>
        );
      case 'CAA':
        return (
          <Grid item xs={12}>
            <Field
              as={TextField}
              name="value"
              label="CAA Value"
              fullWidth
              error={touched.value && !!errors.value}
              helperText={touched.value && errors.value}
              placeholder='0 issue "ca.example.com"'
            />
          </Grid>
        );
      default:
        return (
          <Grid item xs={12}>
            <Field
              as={TextField}
              name="value"
              label="Value"
              fullWidth
              error={touched.value && !!errors.value}
              helperText={touched.value && errors.value}
            />
          </Grid>
        );
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        {mode === 'create' ? 'Create DNS Record' : 'Edit DNS Record'}
      </DialogTitle>
      <Formik
        initialValues={initialValues}
        validationSchema={getValidationSchema(recordType)}
        onSubmit={handleSubmit}
        enableReinitialize
      >
        {({ errors, touched, values, setFieldValue }) => (
          <Form>
            <DialogContent>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Field
                    as={TextField}
                    name="name"
                    label="Name"
                    fullWidth
                    error={touched.name && !!errors.name}
                    helperText={touched.name && errors.name}
                    placeholder="@ for root or subdomain"
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth error={touched.type && !!errors.type}>
                    <InputLabel>Record Type</InputLabel>
                    <Field
                      as={Select}
                      name="type"
                      label="Record Type"
                      onChange={(e: any) => {
                        setFieldValue('type', e.target.value);
                        setRecordType(e.target.value);
                      }}
                      disabled={mode === 'edit'}
                    >
                      {recordTypes.map(type => (
                        <MenuItem key={type} value={type}>{type}</MenuItem>
                      ))}
                    </Field>
                    {touched.type && errors.type && (
                      <FormHelperText>{errors.type as string}</FormHelperText>
                    )}
                  </FormControl>
                </Grid>

                {renderTypeSpecificFields(values.type, errors, touched)}

                <Grid item xs={12} md={6}>
                  <Field
                    as={TextField}
                    name="ttl"
                    label="TTL (seconds)"
                    type="number"
                    fullWidth
                    error={touched.ttl && !!errors.ttl}
                    helperText={touched.ttl && errors.ttl}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <FormControlLabel
                    control={
                      <Field
                        as={Switch}
                        name="enabled"
                        checked={values.enabled}
                        onChange={(e: any) => setFieldValue('enabled', e.target.checked)}
                      />
                    }
                    label="Enabled"
                  />
                </Grid>
                <Grid item xs={12}>
                  <Field
                    as={TextField}
                    name="comment"
                    label="Comment (optional)"
                    fullWidth
                    multiline
                    rows={2}
                    placeholder="Add a comment for this record"
                  />
                </Grid>
              </Grid>

              {values.type === 'CNAME' && values.name === '@' && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  CNAME records cannot be created at the zone apex (@).
                </Alert>
              )}
            </DialogContent>
            <DialogActions>
              <Button onClick={onClose}>Cancel</Button>
              <Button
                type="submit"
                variant="contained"
                disabled={createRecord.isPending || updateRecord.isPending}
              >
                {mode === 'create' ? 'Create' : 'Update'}
              </Button>
            </DialogActions>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default RecordFormDialog;