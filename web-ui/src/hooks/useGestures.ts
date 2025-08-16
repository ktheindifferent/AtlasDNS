import { useRef, useCallback, useState } from 'react';
import { useGesture } from '@use-gesture/react';
import { useSpring, animated } from '@react-spring/web';

// Haptic feedback utility
export const triggerHaptic = (duration: number = 10) => {
  if ('vibrate' in navigator) {
    navigator.vibrate(duration);
  }
};

// Pull to refresh hook
export const usePullToRefresh = (onRefresh: () => Promise<void>) => {
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [pullDistance, setPullDistance] = useState(0);
  const threshold = 80;

  const bind = useGesture({
    onDrag: ({ down, movement: [, my], memo = 0 }) => {
      if (down && my > 0) {
        setPullDistance(Math.min(my, threshold * 1.5));
        if (my > threshold && memo === 0) {
          triggerHaptic(20);
          return 1;
        }
      }
      return memo;
    },
    onDragEnd: async ({ movement: [, my], memo }) => {
      if (memo === 1 && my > threshold && !isRefreshing) {
        setIsRefreshing(true);
        triggerHaptic(30);
        await onRefresh();
        setIsRefreshing(false);
      }
      setPullDistance(0);
    },
  }, {
    drag: {
      axis: 'y',
      filterTaps: true,
      from: () => [0, pullDistance],
    }
  });

  return { bind, isRefreshing, pullDistance };
};

// Long press hook with context menu
export const useLongPress = (
  onLongPress: (event: React.MouseEvent | React.TouchEvent) => void,
  options = { delay: 500 }
) => {
  const [isPressed, setIsPressed] = useState(false);
  const timeoutRef = useRef<NodeJS.Timeout>();
  const targetRef = useRef<EventTarget | null>(null);

  const start = useCallback((event: React.MouseEvent | React.TouchEvent) => {
    targetRef.current = event.currentTarget;
    setIsPressed(true);
    
    timeoutRef.current = setTimeout(() => {
      triggerHaptic(50);
      onLongPress(event);
      setIsPressed(false);
    }, options.delay);
  }, [onLongPress, options.delay]);

  const clear = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      setIsPressed(false);
    }
  }, []);

  return {
    onMouseDown: start,
    onTouchStart: start,
    onMouseUp: clear,
    onMouseLeave: clear,
    onTouchEnd: clear,
    onTouchCancel: clear,
    isPressed,
  };
};

// Pinch to zoom hook
export const usePinchZoom = (
  minScale: number = 0.5,
  maxScale: number = 3
) => {
  const [scale, setScale] = useState(1);
  const [position, setPosition] = useState({ x: 0, y: 0 });

  const bind = useGesture({
    onPinch: ({ offset: [d], origin: [ox, oy], first, active }) => {
      if (first) {
        triggerHaptic(5);
      }
      const newScale = Math.max(minScale, Math.min(maxScale, 1 + d / 200));
      setScale(newScale);
    },
    onPinchEnd: () => {
      if (scale < 1) {
        setScale(1);
        setPosition({ x: 0, y: 0 });
      }
    },
    onDrag: ({ offset: [x, y], pinching }) => {
      if (!pinching && scale > 1) {
        setPosition({ x, y });
      }
    },
  }, {
    pinch: {
      scaleBounds: { min: minScale, max: maxScale },
    },
    drag: {
      enabled: scale > 1,
    }
  });

  const reset = () => {
    setScale(1);
    setPosition({ x: 0, y: 0 });
  };

  return { bind, scale, position, reset };
};

// Double tap hook
export const useDoubleTap = (
  onDoubleTap: () => void,
  options = { delay: 300 }
) => {
  const [tapCount, setTapCount] = useState(0);
  const timeoutRef = useRef<NodeJS.Timeout>();

  const handleTap = useCallback(() => {
    if (tapCount === 0) {
      setTapCount(1);
      timeoutRef.current = setTimeout(() => {
        setTapCount(0);
      }, options.delay);
    } else if (tapCount === 1) {
      clearTimeout(timeoutRef.current);
      setTapCount(0);
      triggerHaptic(10);
      onDoubleTap();
    }
  }, [tapCount, onDoubleTap, options.delay]);

  return {
    onClick: handleTap,
    onTouchEnd: (e: React.TouchEvent) => {
      e.preventDefault();
      handleTap();
    }
  };
};

// Three finger swipe hook
export const useThreeFingerSwipe = (
  onSwipeUp?: () => void,
  onSwipeDown?: () => void,
  onSwipeLeft?: () => void,
  onSwipeRight?: () => void
) => {
  const bind = useGesture({
    onDrag: ({ direction: [dx, dy], distance: [distX, distY], touches, cancel }) => {
      const distance = Math.sqrt(distX * distX + distY * distY);
      if (touches === 3 && distance > 50) {
        const absDx = Math.abs(dx);
        const absDy = Math.abs(dy);
        
        triggerHaptic(20);
        
        if (absDx > absDy) {
          if (dx > 0 && onSwipeRight) {
            onSwipeRight();
          } else if (dx < 0 && onSwipeLeft) {
            onSwipeLeft();
          }
        } else {
          if (dy > 0 && onSwipeDown) {
            onSwipeDown();
          } else if (dy < 0 && onSwipeUp) {
            onSwipeUp();
          }
        }
        cancel();
      }
    }
  }, {
    drag: {
      filterTaps: true,
      threshold: 30,
    }
  });

  return bind;
};

// Swipeable item hook (for list items)
export const useSwipeableItem = (
  onSwipeLeft?: () => void,
  onSwipeRight?: () => void,
  threshold: number = 100
) => {
  const [{ x }, api] = useSpring(() => ({ x: 0 }));
  const [swiped, setSwiped] = useState<'left' | 'right' | null>(null);

  const bind = useGesture({
    onDrag: ({ down, movement: [mx], velocity: [vx], direction: [dx], cancel }) => {
      if (!down) {
        if (Math.abs(mx) > threshold || Math.abs(vx) > 0.5) {
          if (mx < -threshold && onSwipeLeft) {
            setSwiped('left');
            triggerHaptic(20);
            onSwipeLeft();
            cancel();
          } else if (mx > threshold && onSwipeRight) {
            setSwiped('right');
            triggerHaptic(20);
            onSwipeRight();
            cancel();
          }
        }
        api.start({ x: 0 });
      } else {
        api.start({ x: mx, immediate: true });
      }
    },
  }, {
    drag: {
      axis: 'x',
      bounds: { left: -200, right: 200 },
      rubberband: true,
    }
  });

  const reset = () => {
    api.start({ x: 0 });
    setSwiped(null);
  };

  return { bind, x, swiped, reset };
};

// Hover/Touch gesture hook for unified interaction
export const useHoverTouch = (
  onStart?: () => void,
  onEnd?: () => void
) => {
  const [isActive, setIsActive] = useState(false);

  const handleStart = useCallback(() => {
    setIsActive(true);
    onStart?.();
  }, [onStart]);

  const handleEnd = useCallback(() => {
    setIsActive(false);
    onEnd?.();
  }, [onEnd]);

  return {
    onMouseEnter: handleStart,
    onMouseLeave: handleEnd,
    onTouchStart: handleStart,
    onTouchEnd: handleEnd,
    isActive,
  };
};

// Keyboard alternative hook for gestures
export const useKeyboardAlternative = (
  gestureMap: Record<string, () => void>
) => {
  const handleKeyDown = useCallback((event: React.KeyboardEvent) => {
    const key = event.key.toLowerCase();
    const ctrl = event.ctrlKey || event.metaKey;
    const shift = event.shiftKey;
    const alt = event.altKey;
    
    let keyCombo = '';
    if (ctrl) keyCombo += 'ctrl+';
    if (shift) keyCombo += 'shift+';
    if (alt) keyCombo += 'alt+';
    keyCombo += key;
    
    if (gestureMap[keyCombo]) {
      event.preventDefault();
      gestureMap[keyCombo]();
    }
  }, [gestureMap]);

  return { onKeyDown: handleKeyDown };
};