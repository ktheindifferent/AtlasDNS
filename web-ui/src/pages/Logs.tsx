import React from 'react';

const Logs: React.FC = () => {
  return (
    <div style={{ padding: '20px' }}>
      <h1>Logs</h1>
      <input 
        type="text" 
        placeholder="Search logs..." 
        data-search="logs"
        style={{ padding: '8px', width: '300px', marginTop: '10px' }}
      />
      <p>View system logs</p>
    </div>
  );
};

export default Logs;