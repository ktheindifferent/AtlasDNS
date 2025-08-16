import React from 'react';

const LoadingScreen: React.FC = () => {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      height: '100vh',
      fontSize: '18px',
      color: '#6b7280'
    }}>
      Loading...
    </div>
  );
};

export default LoadingScreen;