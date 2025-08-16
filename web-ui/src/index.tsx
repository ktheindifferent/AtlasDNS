import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import DashboardDemo from './pages/DashboardDemo';

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

root.render(
  <React.StrictMode>
    <DashboardDemo />
  </React.StrictMode>
);