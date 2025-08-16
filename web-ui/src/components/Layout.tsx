import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import CommandPalette from './CommandPalette';

const Layout: React.FC = () => {
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  return (
    <div className="layout">
      <CommandPalette 
        open={commandPaletteOpen} 
        onOpenChange={setCommandPaletteOpen} 
      />
      <div className="layout-content">
        <Outlet />
      </div>
    </div>
  );
};

export default Layout;