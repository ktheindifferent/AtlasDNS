import React, { useEffect, useState } from 'react';
import { Box } from '@mui/material';
import { DataGrid, GridColDef } from '@mui/x-data-grid';
import { TableData, WidgetConfig } from '../types';
import { generateMockData } from '../utils';

interface TableWidgetProps {
  config: WidgetConfig;
  onUpdate?: (updates: Partial<WidgetConfig>) => void;
}

const TableWidget: React.FC<TableWidgetProps> = ({ config, onUpdate }) => {
  const [data, setData] = useState<TableData | null>(null);

  useEffect(() => {
    const mockData = config.data || generateMockData('table');
    setData(mockData);
    
    if (!config.data && onUpdate) {
      onUpdate({ data: mockData });
    }

    if (config.refreshInterval) {
      const interval = setInterval(() => {
        const newData = generateMockData('table');
        setData(newData);
        onUpdate?.({ data: newData });
      }, config.refreshInterval * 1000);
      
      return () => clearInterval(interval);
    }
  }, [config.data, config.refreshInterval]);

  if (!data) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        Loading...
      </Box>
    );
  }

  return (
    <Box sx={{ height: '100%', width: '100%' }}>
      <DataGrid
        rows={data.rows}
        columns={data.columns as GridColDef[]}
        pageSizeOptions={[5, 10, 25]}
        initialState={{
          pagination: {
            paginationModel: { pageSize: 10, page: 0 }
          }
        }}
        checkboxSelection={config.customSettings?.enableSelection}
        disableRowSelectionOnClick
        density="compact"
        sx={{
          border: 'none',
          '& .MuiDataGrid-cell': {
            borderBottom: '1px solid rgba(224, 224, 224, 0.5)'
          }
        }}
      />
    </Box>
  );
};

export default TableWidget;