import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import * as serviceWorkerRegistration from './serviceWorkerRegistration';
import { SnackbarProvider } from 'notistack';

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

root.render(
  <React.StrictMode>
    <SnackbarProvider maxSnack={3} anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}>
      <App />
    </SnackbarProvider>
  </React.StrictMode>
);

// Register service worker for PWA functionality
serviceWorkerRegistration.register({
  onSuccess: (registration) => {
    console.log('PWA service worker registered successfully:', registration);
  },
  onUpdate: (registration) => {
    console.log('New content available, please refresh:', registration);
    // Optionally show a notification to the user about the update
    const updateEvent = new CustomEvent('sw-update', { detail: registration });
    window.dispatchEvent(updateEvent);
  }
});

// Hide app shell loader once React is mounted
window.addEventListener('load', () => {
  const loader = document.getElementById('app-shell-loader');
  if (loader) {
    setTimeout(() => {
      loader.style.display = 'none';
    }, 300);
  }
});