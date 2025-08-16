import React, { useEffect, useRef, useState } from 'react';
import { Box, Tooltip, Avatar } from '@mui/material';
import { useSelector } from 'react-redux';
import { RootState } from '../../store';
import { useCollaboration } from '../../contexts/CollaborationContext';
import { Cursor } from '../../store/slices/collaborationSlice';

interface LiveCursorsProps {
  containerRef?: React.RefObject<HTMLElement>;
  page: string;
}

const LiveCursors: React.FC<LiveCursorsProps> = ({ containerRef, page }) => {
  const { sendCursor } = useCollaboration();
  const { cursors, activeUsers } = useSelector((state: RootState) => state.collaboration);
  const { user: currentUser } = useSelector((state: RootState) => state.auth);
  const [localCursors, setLocalCursors] = useState<{ [userId: string]: { x: number; y: number } }>({});
  const lastSentRef = useRef<{ x: number; y: number; time: number }>({ x: 0, y: 0, time: 0 });

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      const now = Date.now();
      const timeSinceLastSent = now - lastSentRef.current.time;
      const distance = Math.sqrt(
        Math.pow(e.clientX - lastSentRef.current.x, 2) +
        Math.pow(e.clientY - lastSentRef.current.y, 2)
      );

      if (timeSinceLastSent > 50 && distance > 5) {
        const rect = containerRef?.current?.getBoundingClientRect();
        const x = rect ? e.clientX - rect.left : e.clientX;
        const y = rect ? e.clientY - rect.top : e.clientY;
        
        sendCursor(x, y, page);
        lastSentRef.current = { x: e.clientX, y: e.clientY, time: now };
      }
    };

    const handleMouseLeave = () => {
      sendCursor(-1, -1, page);
    };

    const element = containerRef?.current || document;
    element.addEventListener('mousemove', handleMouseMove as any);
    element.addEventListener('mouseleave', handleMouseLeave as any);

    return () => {
      element.removeEventListener('mousemove', handleMouseMove as any);
      element.removeEventListener('mouseleave', handleMouseLeave as any);
    };
  }, [containerRef, page, sendCursor]);

  useEffect(() => {
    const pageCursors = cursors.filter(c => c.page === page && c.userId !== currentUser?.id);
    const newLocalCursors: { [userId: string]: { x: number; y: number } } = {};
    
    pageCursors.forEach(cursor => {
      if (cursor.x >= 0 && cursor.y >= 0) {
        newLocalCursors[cursor.userId] = { x: cursor.x, y: cursor.y };
      }
    });
    
    setLocalCursors(newLocalCursors);
  }, [cursors, page, currentUser]);

  return (
    <>
      {Object.entries(localCursors).map(([userId, position]) => {
        const user = activeUsers.find(u => u.id === userId);
        if (!user) return null;

        return (
          <CursorPointer
            key={userId}
            user={user}
            x={position.x}
            y={position.y}
          />
        );
      })}
    </>
  );
};

interface CursorPointerProps {
  user: {
    id: string;
    name: string;
    color: string;
    avatar?: string;
  };
  x: number;
  y: number;
}

const CursorPointer: React.FC<CursorPointerProps> = ({ user, x, y }) => {
  return (
    <Box
      sx={{
        position: 'fixed',
        left: x,
        top: y,
        pointerEvents: 'none',
        zIndex: 9999,
        transform: 'translate(-50%, -50%)',
        transition: 'all 0.1s linear',
      }}
    >
      <svg
        width="24"
        height="24"
        viewBox="0 0 24 24"
        fill="none"
        style={{ filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.2))' }}
      >
        <path
          d="M5 3L19 12L12 13L8 21L5 3Z"
          fill={user.color}
          stroke="white"
          strokeWidth="1"
        />
      </svg>
      <Tooltip title={user.name} open placement="right">
        <Box
          sx={{
            position: 'absolute',
            left: 20,
            top: 15,
            display: 'flex',
            alignItems: 'center',
            gap: 0.5,
            backgroundColor: user.color,
            color: 'white',
            padding: '2px 8px',
            borderRadius: '12px',
            fontSize: '12px',
            fontWeight: 500,
            whiteSpace: 'nowrap',
          }}
        >
          {user.avatar ? (
            <Avatar
              src={user.avatar}
              sx={{ width: 16, height: 16 }}
            />
          ) : (
            user.name.charAt(0).toUpperCase()
          )}
          <span>{user.name}</span>
        </Box>
      </Tooltip>
    </Box>
  );
};

export default LiveCursors;