export const generateId = (): string => {
  return `widget_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

export const formatNumber = (value: number, decimals: number = 0): string => {
  if (value >= 1000000) {
    return `${(value / 1000000).toFixed(decimals)}M`;
  } else if (value >= 1000) {
    return `${(value / 1000).toFixed(decimals)}K`;
  }
  return value.toFixed(decimals);
};

export const getRandomColor = (): string => {
  const colors = [
    '#FF6384',
    '#36A2EB',
    '#FFCE56',
    '#4BC0C0',
    '#9966FF',
    '#FF9F40',
    '#FF6384',
    '#C9CBCF'
  ];
  return colors[Math.floor(Math.random() * colors.length)];
};

export const generateMockData = (type: string): any => {
  switch (type) {
    case 'metric':
      return {
        value: Math.floor(Math.random() * 10000),
        label: 'Total Sales',
        trend: ['up', 'down', 'stable'][Math.floor(Math.random() * 3)],
        change: Math.random() * 20 - 10,
        unit: '$'
      };
    
    case 'chart':
      const labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'];
      return {
        labels,
        datasets: [
          {
            label: 'Dataset 1',
            data: labels.map(() => Math.floor(Math.random() * 100)),
            backgroundColor: getRandomColor(),
            borderColor: getRandomColor()
          },
          {
            label: 'Dataset 2',
            data: labels.map(() => Math.floor(Math.random() * 100)),
            backgroundColor: getRandomColor(),
            borderColor: getRandomColor()
          }
        ]
      };
    
    case 'table':
      return {
        columns: [
          { field: 'id', headerName: 'ID', width: 70 },
          { field: 'name', headerName: 'Name', width: 130 },
          { field: 'status', headerName: 'Status', width: 100 },
          { field: 'value', headerName: 'Value', width: 100, type: 'number' }
        ],
        rows: Array.from({ length: 10 }, (_, i) => ({
          id: i + 1,
          name: `Item ${i + 1}`,
          status: ['Active', 'Inactive', 'Pending'][Math.floor(Math.random() * 3)],
          value: Math.floor(Math.random() * 1000)
        }))
      };
    
    case 'gauge':
      return {
        value: Math.floor(Math.random() * 100),
        min: 0,
        max: 100,
        label: 'Performance',
        unit: '%',
        thresholds: {
          low: 30,
          medium: 60,
          high: 90
        }
      };
    
    default:
      return null;
  }
};

export const debounce = <T extends (...args: any[]) => any>(
  func: T,
  delay: number
): ((...args: Parameters<T>) => void) => {
  let timeoutId: NodeJS.Timeout;
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), delay);
  };
};