import React from 'react';

const Zones: React.FC = () => {
  return (
    <div style={{ padding: '20px' }}>
      <h1>DNS Zones</h1>
      <input 
        type="text" 
        placeholder="Search zones..." 
        data-search="zones"
        style={{ padding: '8px', width: '300px', marginTop: '10px' }}
      />
      <p>Manage your DNS zones here</p>
    </div>
  );
};

export default Zones;