# Interactive Dashboard Widget System

A customizable, drag-and-drop dashboard system built with React, TypeScript, and Material-UI, featuring real-time data streaming and custom widget creation.

## Features

### Core Dashboard Functionality
- **Drag & Drop Layout**: Rearrange widgets by dragging them to new positions
- **Resizable Widgets**: Adjust widget sizes by dragging corners
- **Responsive Grid**: Automatic layout adjustments for different screen sizes
- **Edit/View Modes**: Toggle between editing and viewing modes
- **Layout Persistence**: Saves dashboard configurations to localStorage

### Widget Management
- **Add/Remove Widgets**: Dynamic widget creation and deletion
- **Widget Types**:
  - Metric Cards: Display KPIs with trends
  - Charts: Line, Bar, Pie, Doughnut visualizations
  - Data Tables: Sortable, paginated data grids
  - Gauges: Visual performance indicators
  - Text/Notes: Editable text widgets
  - Alerts: System notifications and warnings
  - Real-time Data: WebSocket-connected live data streams
  - Custom Widgets: Build your own with HTML/CSS/JS

### Data & Configuration
- **Export/Import**: Save and load dashboard configurations as JSON
- **WebSocket Support**: Real-time data streaming for live updates
- **API Integration**: Connect widgets to external data sources
- **Custom Widget Builder**: Create widgets with custom HTML, CSS, and JavaScript

## Getting Started

### Prerequisites
- Node.js 16+ 
- npm or yarn

### Installation

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm start
```

3. Open http://localhost:3000 in your browser

## Usage

### Basic Operations

1. **Adding Widgets**
   - Click the floating action button (FAB) in the bottom-right corner
   - Select "Add Widget" from the speed dial menu
   - Choose widget type and enter a title
   - Widget appears at the top-left of the dashboard

2. **Arranging Widgets**
   - Enter edit mode (toggle with lock icon in bottom-left)
   - Drag widgets by their headers to new positions
   - Resize by dragging the bottom-right corner

3. **Configuring Widgets**
   - Click the menu icon (⋮) on any widget
   - Select settings to configure widget properties
   - Some widgets (like charts) have type selectors

4. **Saving Layouts**
   - Layouts auto-save to localStorage
   - Export configuration via speed dial menu
   - Import saved configurations to restore layouts

### Custom Widget Development

The Custom Widget builder allows you to create widgets with:

1. **HTML Template**
   - Use `{{variable}}` syntax for data binding
   - Full HTML5 support

2. **CSS Styling**
   - Scoped styles for your widget
   - Access to Material-UI theme variables

3. **JavaScript Logic**
   - Access widget data via `data` object
   - Update widget with `widget.update()`
   - Handle events and interactions

Example custom widget:
```html
<div class="custom-widget">
  <h2>{{title}}</h2>
  <p class="value">{{value}}</p>
</div>
```

```css
.custom-widget {
  text-align: center;
  padding: 16px;
}
.value {
  font-size: 2em;
  color: #1976d2;
}
```

```javascript
// Update widget every 5 seconds
setInterval(() => {
  widget.update({
    data: { value: Math.random() * 100 }
  });
}, 5000);
```

### WebSocket Integration

Real-time widgets connect to WebSocket servers for live data:

```javascript
// Configure in widget settings
{
  websocketUrl: 'ws://localhost:3001',
  channel: 'metrics',
  maxDataPoints: 20
}
```

## Project Structure

```
src/
├── components/
│   └── Dashboard/
│       ├── Dashboard.tsx       # Main dashboard component
│       ├── Widget.tsx          # Base widget wrapper
│       ├── types.ts           # TypeScript definitions
│       ├── utils.ts           # Helper functions
│       ├── Dashboard.css      # Dashboard styles
│       └── widgets/           # Individual widget components
│           ├── MetricWidget.tsx
│           ├── ChartWidget.tsx
│           ├── TableWidget.tsx
│           ├── GaugeWidget.tsx
│           ├── TextWidget.tsx
│           ├── AlertWidget.tsx
│           ├── RealtimeWidget.tsx
│           └── CustomWidget.tsx
└── pages/
    └── DashboardDemo.tsx      # Demo page with examples
```

## API Reference

### Dashboard Component Props

```typescript
interface DashboardProps {
  dashboardId?: string;           // Unique dashboard identifier
  initialConfig?: DashboardConfig; // Initial configuration
  onSave?: (config: DashboardConfig) => void; // Save callback
  readOnly?: boolean;             // Disable editing
}
```

### Widget Configuration

```typescript
interface WidgetConfig {
  id: string;                    // Unique widget ID
  type: string;                  // Widget type
  title: string;                 // Display title
  data?: any;                    // Widget data
  refreshInterval?: number;      // Auto-refresh (seconds)
  customSettings?: Record<string, any>; // Custom settings
}
```

### Dashboard Layout

```typescript
interface DashboardLayout {
  i: string;    // Widget ID
  x: number;    // X position (grid units)
  y: number;    // Y position (grid units)
  w: number;    // Width (grid units)
  h: number;    // Height (grid units)
  minW?: number; // Minimum width
  maxW?: number; // Maximum width
  minH?: number; // Minimum height
  maxH?: number; // Maximum height
  static?: boolean; // Lock position
}
```

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Performance Considerations

- Widgets render independently to prevent cascading updates
- WebSocket connections are managed per-widget with auto-reconnect
- LocalStorage used for persistence (consider IndexedDB for larger datasets)
- Virtual scrolling in data tables for large datasets

## Future Enhancements

- [ ] Backend persistence API
- [ ] User authentication & multi-user support
- [ ] Widget marketplace/sharing
- [ ] Advanced data transformations
- [ ] Dashboard templates
- [ ] Mobile-optimized layouts
- [ ] Collaborative editing
- [ ] Widget permissions & access control
- [ ] Export to PDF/Image
- [ ] Scheduled reports

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.