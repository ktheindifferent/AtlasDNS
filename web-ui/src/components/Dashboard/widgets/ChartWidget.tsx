import React, { useEffect, useState } from 'react';
import { Box, FormControl, Select, MenuItem } from '@mui/material';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js';
import { Line, Bar, Pie, Doughnut } from 'react-chartjs-2';
import { ChartData, WidgetConfig } from '../types';
import { generateMockData } from '../utils';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

interface ChartWidgetProps {
  config: WidgetConfig;
  onUpdate?: (updates: Partial<WidgetConfig>) => void;
}

const ChartWidget: React.FC<ChartWidgetProps> = ({ config, onUpdate }) => {
  const [data, setData] = useState<ChartData | null>(null);
  const [chartType, setChartType] = useState<'line' | 'bar' | 'pie' | 'doughnut'>(
    config.customSettings?.chartType || 'line'
  );

  useEffect(() => {
    const mockData = config.data || generateMockData('chart');
    setData(mockData);
    
    if (!config.data && onUpdate) {
      onUpdate({ data: mockData });
    }

    if (config.refreshInterval) {
      const interval = setInterval(() => {
        const newData = generateMockData('chart');
        setData(newData);
        onUpdate?.({ data: newData });
      }, config.refreshInterval * 1000);
      
      return () => clearInterval(interval);
    }
  }, [config.data, config.refreshInterval]);

  const handleChartTypeChange = (type: string) => {
    setChartType(type as any);
    onUpdate?.({
      customSettings: {
        ...config.customSettings,
        chartType: type
      }
    });
  };

  if (!data) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        Loading...
      </Box>
    );
  }

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      }
    }
  };

  const renderChart = () => {
    switch (chartType) {
      case 'bar':
        return <Bar data={data} options={options} />;
      case 'pie':
        return <Pie data={data} options={options} />;
      case 'doughnut':
        return <Doughnut data={data} options={options} />;
      default:
        return <Line data={data} options={options} />;
    }
  };

  return (
    <Box sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ mb: 1 }}>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <Select
            value={chartType}
            onChange={(e) => handleChartTypeChange(e.target.value)}
            displayEmpty
          >
            <MenuItem value="line">Line</MenuItem>
            <MenuItem value="bar">Bar</MenuItem>
            <MenuItem value="pie">Pie</MenuItem>
            <MenuItem value="doughnut">Doughnut</MenuItem>
          </Select>
        </FormControl>
      </Box>
      <Box sx={{ flex: 1, position: 'relative' }}>
        {renderChart()}
      </Box>
    </Box>
  );
};

export default ChartWidget;