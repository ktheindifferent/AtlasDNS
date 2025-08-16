import React from 'react';
import {
  Box,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Typography,
  Checkbox,
  FormControlLabel,
  Slider,
  TextField,
  Chip,
  Stack,
  Badge,
  Button,
} from '@mui/material';
import { ExpandMore, FilterList } from '@mui/icons-material';
import { Facet, FacetValue } from '../../types/filtering';

interface FacetedSearchProps {
  facets: Facet[];
  selectedFacets: Record<string, any>;
  onChange: (facets: Record<string, any>) => void;
}

const FacetedSearch: React.FC<FacetedSearchProps> = ({
  facets,
  selectedFacets,
  onChange,
}) => {
  const handleCheckboxChange = (facetField: string, value: string, checked: boolean) => {
    const currentValues = selectedFacets[facetField] || [];
    const newValues = checked
      ? [...currentValues, value]
      : currentValues.filter((v: string) => v !== value);
    
    const newFacets = { ...selectedFacets };
    if (newValues.length > 0) {
      newFacets[facetField] = newValues;
    } else {
      delete newFacets[facetField];
    }
    onChange(newFacets);
  };

  const handleRangeChange = (facetField: string, value: number[]) => {
    onChange({
      ...selectedFacets,
      [facetField]: value,
    });
  };

  const handleDateChange = (facetField: string, type: 'start' | 'end', value: string) => {
    const currentRange = selectedFacets[facetField] || { start: '', end: '' };
    onChange({
      ...selectedFacets,
      [facetField]: {
        ...currentRange,
        [type]: value,
      },
    });
  };

  const clearFacet = (facetField: string) => {
    const newFacets = { ...selectedFacets };
    delete newFacets[facetField];
    onChange(newFacets);
  };

  const clearAllFacets = () => {
    onChange({});
  };

  const getSelectedCount = (facetField: string) => {
    const values = selectedFacets[facetField];
    if (!values) return 0;
    if (Array.isArray(values)) return values.length;
    if (typeof values === 'object' && (values.start || values.end)) return 1;
    return values ? 1 : 0;
  };

  const totalSelectedCount = Object.keys(selectedFacets).reduce(
    (sum, field) => sum + getSelectedCount(field),
    0
  );

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h6" display="flex" alignItems="center" gap={1}>
          <FilterList />
          Faceted Search
          {totalSelectedCount > 0 && (
            <Chip label={`${totalSelectedCount} active`} size="small" color="primary" />
          )}
        </Typography>
        {totalSelectedCount > 0 && (
          <Button size="small" onClick={clearAllFacets}>
            Clear All
          </Button>
        )}
      </Box>

      {facets.map((facet) => {
        const selectedCount = getSelectedCount(facet.field);
        
        return (
          <Accordion key={facet.field} defaultExpanded={selectedCount > 0}>
            <AccordionSummary expandIcon={<ExpandMore />}>
              <Box display="flex" alignItems="center" gap={1} width="100%">
                <Badge badgeContent={selectedCount} color="primary">
                  <Typography>{facet.label}</Typography>
                </Badge>
                {selectedCount > 0 && (
                  <Button
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      clearFacet(facet.field);
                    }}
                  >
                    Clear
                  </Button>
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {facet.type === 'checkbox' && (
                <Stack spacing={1}>
                  {facet.values.map((facetValue: FacetValue) => {
                    const isChecked = (selectedFacets[facet.field] || []).includes(facetValue.value);
                    return (
                      <FormControlLabel
                        key={facetValue.value}
                        control={
                          <Checkbox
                            checked={isChecked}
                            onChange={(e) =>
                              handleCheckboxChange(facet.field, facetValue.value, e.target.checked)
                            }
                            size="small"
                          />
                        }
                        label={
                          <Box display="flex" alignItems="center" gap={1}>
                            <Typography variant="body2">{facetValue.value}</Typography>
                            <Chip label={facetValue.count} size="small" variant="outlined" />
                          </Box>
                        }
                      />
                    );
                  })}
                </Stack>
              )}

              {facet.type === 'range' && (
                <Box sx={{ px: 2 }}>
                  <Slider
                    value={selectedFacets[facet.field] || [0, 100]}
                    onChange={(_, value) => handleRangeChange(facet.field, value as number[])}
                    valueLabelDisplay="auto"
                    min={0}
                    max={100}
                    marks={[
                      { value: 0, label: '0' },
                      { value: 50, label: '50' },
                      { value: 100, label: '100' },
                    ]}
                  />
                </Box>
              )}

              {facet.type === 'date' && (
                <Stack spacing={2}>
                  <TextField
                    label="Start Date"
                    type="date"
                    size="small"
                    fullWidth
                    value={selectedFacets[facet.field]?.start || ''}
                    onChange={(e) => handleDateChange(facet.field, 'start', e.target.value)}
                    InputLabelProps={{ shrink: true }}
                  />
                  <TextField
                    label="End Date"
                    type="date"
                    size="small"
                    fullWidth
                    value={selectedFacets[facet.field]?.end || ''}
                    onChange={(e) => handleDateChange(facet.field, 'end', e.target.value)}
                    InputLabelProps={{ shrink: true }}
                  />
                </Stack>
              )}
            </AccordionDetails>
          </Accordion>
        );
      })}
    </Box>
  );
};

export default FacetedSearch;