# Atlas DNS - Advanced Data Visualization Dashboard

## Overview

This is the web UI for Atlas DNS Server, featuring sophisticated data visualization components for comprehensive DNS analytics.

## Advanced Visualization Components

### 1. Geographic Heat Map
- **Location**: `src/components/visualizations/GeographicHeatMap.tsx`
- **Features**:
  - Interactive map showing DNS query origins using Leaflet
  - Heat intensity visualization based on query volume or response time
  - Zoom and pan capabilities
  - Click handlers for detailed location information
  - Adjustable intensity slider

### 2. Real-time Query Rate Graph
- **Location**: `src/components/visualizations/RealTimeQueryGraph.tsx`
- **Features**:
  - Live updating query metrics with D3.js
  - Zoom and pan functionality
  - Multiple time range selections (1m, 5m, 15m, 1h)
  - Anomaly detection and highlighting
  - Pause/resume capabilities
  - Shows queries, cached, blocked, and response time metrics

### 3. DNS Response Time Distribution Histogram
- **Location**: `src/components/visualizations/ResponseTimeHistogram.tsx`
- **Features**:
  - Response time distribution visualization
  - Adjustable bin sizes (5ms, 10ms, 20ms, 50ms)
  - Percentile markers (P25, P50, P75, P90, P95, P99)
  - Cumulative distribution overlay
  - Statistical metrics display (mean, median, P95, P99)

### 4. Top Queried Domains Treemap
- **Location**: `src/components/visualizations/DomainsTreemap.tsx`
- **Features**:
  - Hierarchical visualization of domain queries
  - Color coding by category, query volume, response time, or cache hit rate
  - Interactive drill-down capabilities
  - Hover tooltips with detailed metrics
  - Responsive sizing based on query volume

### 5. Network Topology Diagram
- **Location**: `src/components/visualizations/NetworkTopology.tsx`
- **Features**:
  - Force-directed graph visualization of DNS infrastructure
  - Multiple layout modes (Force, Hierarchy, Radial)
  - Node types: Client, Resolver, Authoritative, Root, Cache
  - Health status indicators
  - Interactive drag and zoom
  - Link visualization with latency and traffic volume

### 6. Query Type Breakdown
- **Location**: `src/components/visualizations/QueryTypeBreakdown.tsx`
- **Features**:
  - Interactive pie/donut/sunburst charts
  - Query type distribution (A, AAAA, CNAME, MX, TXT, etc.)
  - Trend indicators for each query type
  - Animated transitions
  - Top query types summary

### 7. Time Series Analysis with Anomaly Detection
- **Location**: `src/components/visualizations/TimeSeriesAnalysis.tsx`
- **Features**:
  - Advanced time series visualization
  - Statistical and ML-based anomaly detection
  - Confidence bands visualization
  - Brush selection for time range zooming
  - Anomaly period identification
  - Predictive analytics overlay

## Installation

```bash
cd web-ui
npm install --legacy-peer-deps
```

## Development

```bash
npm start
```

The development server will start at http://localhost:3000

## Build

```bash
npm run build
```

## Dependencies

### Core Libraries
- **React 18.2** - UI Framework
- **TypeScript 5.1** - Type safety
- **Material-UI 5.14** - Component library
- **React Router 6.14** - Routing

### Visualization Libraries
- **D3.js 7.9** - Advanced data visualization
- **Leaflet 1.9.4** - Geographic mapping
- **React-Leaflet 4.2.1** - React wrapper for Leaflet
- **Recharts 2.7.2** - React charts library

### State Management
- **Redux Toolkit 1.9.5** - State management
- **React Query 4.32** - Server state management

### Real-time Communication
- **Socket.io-client 4.7.1** - WebSocket connections

## Features

### Dashboard Views
1. **Overview Tab** - Real-time metrics and key visualizations
2. **Geographic Analysis** - Location-based query analysis
3. **Performance Metrics** - Response time and performance analysis
4. **Network Topology** - Infrastructure visualization
5. **Time Series Analysis** - Historical trends and anomaly detection

### Key Capabilities
- **Real-time Updates** - Live data streaming via WebSocket
- **Interactive Visualizations** - All charts support interaction
- **Responsive Design** - Adapts to different screen sizes
- **Performance Optimized** - Efficient rendering for large datasets
- **Anomaly Detection** - Automatic identification of unusual patterns

## API Integration

The dashboard integrates with the Atlas DNS Server API endpoints:
- `/api/v2/analytics/geography` - Geographic query data
- `/api/v2/analytics/queries` - Query metrics
- `/api/v2/analytics/performance` - Performance metrics
- `/api/v2/analytics/top-domains` - Domain statistics
- `/api/v2/analytics/response-codes` - Response code distribution

## Configuration

Environment variables:
- `REACT_APP_API_URL` - API base URL (default: http://localhost:5380/api/v2)
- `REACT_APP_WS_URL` - WebSocket URL (default: ws://localhost:5380)

## Performance Considerations

- **Virtualization** - Large lists use virtualization for performance
- **Debouncing** - User interactions are debounced to prevent excessive updates
- **Memoization** - Complex calculations are memoized
- **Lazy Loading** - Components are lazy loaded for faster initial load
- **Data Sampling** - Large datasets are sampled for visualization

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## License

See LICENSE file in the root directory.