import React from 'react';
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
  Box,
  Typography,
} from '@mui/material';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { useDispatch } from 'react-redux';
import { AppDispatch } from '../../store';
import { createZone, updateZone, Zone } from '../../store/slices/zonesSlice';
import { useSnackbar } from 'notistack';

interface ZoneFormDialogProps {
  open: boolean;
  onClose: () => void;
  mode: 'create' | 'edit';
  zone?: Zone | null;
}

const validationSchema = Yup.object({
  name: Yup.string()
    .required('Zone name is required')
    .matches(/^[a-zA-Z0-9.-]+$/, 'Invalid zone name format'),
  type: Yup.string().required('Zone type is required'),
  primaryNs: Yup.string()
    .required('Primary nameserver is required')
    .matches(/^[a-zA-Z0-9.-]+$/, 'Invalid nameserver format'),
  adminEmail: Yup.string()
    .required('Admin email is required')
    .email('Invalid email format'),
  ttl: Yup.number()
    .required('TTL is required')
    .min(60, 'TTL must be at least 60 seconds')
    .max(604800, 'TTL cannot exceed 604800 seconds'),
  refresh: Yup.number()
    .required('Refresh interval is required')
    .min(3600, 'Refresh must be at least 3600 seconds'),
  retry: Yup.number()
    .required('Retry interval is required')
    .min(600, 'Retry must be at least 600 seconds'),
  expire: Yup.number()
    .required('Expire time is required')
    .min(86400, 'Expire must be at least 86400 seconds'),
  minimum: Yup.number()
    .required('Minimum TTL is required')
    .min(60, 'Minimum TTL must be at least 60 seconds'),
});

const ZoneFormDialog: React.FC<ZoneFormDialogProps> = ({
  open,
  onClose,
  mode,
  zone,
}) => {
  const dispatch = useDispatch<AppDispatch>();
  const { enqueueSnackbar } = useSnackbar();

  const initialValues = {
    name: zone?.name || '',
    type: zone?.type || 'master',
    primaryNs: zone?.primaryNs || '',
    adminEmail: zone?.adminEmail || '',
    ttl: zone?.ttl || 86400,
    refresh: zone?.refresh || 10800,
    retry: zone?.retry || 3600,
    expire: zone?.expire || 604800,
    minimum: zone?.minimum || 86400,
  };

  const handleSubmit = async (values: typeof initialValues) => {
    try {
      if (mode === 'create') {
        await dispatch(createZone(values)).unwrap();
        enqueueSnackbar('Zone created successfully', { variant: 'success' });
      } else if (zone) {
        await dispatch(updateZone({ zoneId: zone.id, data: values })).unwrap();
        enqueueSnackbar('Zone updated successfully', { variant: 'success' });
      }
      onClose();
    } catch (error) {
      enqueueSnackbar(
        mode === 'create' ? 'Failed to create zone' : 'Failed to update zone',
        { variant: 'error' }
      );
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        {mode === 'create' ? 'Create New Zone' : 'Edit Zone'}
      </DialogTitle>
      <Formik
        initialValues={initialValues}
        validationSchema={validationSchema}
        onSubmit={handleSubmit}
      >
        {({ errors, touched, isSubmitting }) => (
          <Form>
            <DialogContent>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Field
                    as={TextField}
                    name="name"
                    label="Zone Name"
                    fullWidth
                    error={touched.name && !!errors.name}
                    helperText={touched.name && errors.name}
                    disabled={mode === 'edit'}
                    placeholder="example.com"
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth error={touched.type && !!errors.type}>
                    <InputLabel>Zone Type</InputLabel>
                    <Field
                      as={Select}
                      name="type"
                      label="Zone Type"
                    >
                      <MenuItem value="master">Master</MenuItem>
                      <MenuItem value="slave">Slave</MenuItem>
                      <MenuItem value="forward">Forward</MenuItem>
                    </Field>
                    {touched.type && errors.type && (
                      <FormHelperText>{errors.type}</FormHelperText>
                    )}
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Field
                    as={TextField}
                    name="primaryNs"
                    label="Primary Nameserver"
                    fullWidth
                    error={touched.primaryNs && !!errors.primaryNs}
                    helperText={touched.primaryNs && errors.primaryNs}
                    placeholder="ns1.example.com"
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <Field
                    as={TextField}
                    name="adminEmail"
                    label="Admin Email"
                    fullWidth
                    error={touched.adminEmail && !!errors.adminEmail}
                    helperText={touched.adminEmail && errors.adminEmail}
                    placeholder="admin@example.com"
                  />
                </Grid>
                <Grid item xs={12}>
                  <Box sx={{ mt: 2, mb: 1 }}>
                    <Typography variant="subtitle2" color="text.secondary">
                      SOA Record Settings
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Field
                    as={TextField}
                    name="ttl"
                    label="TTL"
                    type="number"
                    fullWidth
                    error={touched.ttl && !!errors.ttl}
                    helperText={touched.ttl && errors.ttl}
                  />
                </Grid>
                <Grid item xs={6} md={3}>
                  <Field
                    as={TextField}
                    name="refresh"
                    label="Refresh"
                    type="number"
                    fullWidth
                    error={touched.refresh && !!errors.refresh}
                    helperText={touched.refresh && errors.refresh}
                  />
                </Grid>
                <Grid item xs={6} md={3}>
                  <Field
                    as={TextField}
                    name="retry"
                    label="Retry"
                    type="number"
                    fullWidth
                    error={touched.retry && !!errors.retry}
                    helperText={touched.retry && errors.retry}
                  />
                </Grid>
                <Grid item xs={6} md={3}>
                  <Field
                    as={TextField}
                    name="expire"
                    label="Expire"
                    type="number"
                    fullWidth
                    error={touched.expire && !!errors.expire}
                    helperText={touched.expire && errors.expire}
                  />
                </Grid>
                <Grid item xs={12}>
                  <Field
                    as={TextField}
                    name="minimum"
                    label="Minimum TTL"
                    type="number"
                    fullWidth
                    error={touched.minimum && !!errors.minimum}
                    helperText={touched.minimum && errors.minimum}
                  />
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={onClose}>Cancel</Button>
              <Button
                type="submit"
                variant="contained"
                disabled={isSubmitting}
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

export default ZoneFormDialog;