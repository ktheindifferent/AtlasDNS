# Dark Mode Flash Fix

## Problem
The Atlas DNS web interface had a dark mode feature, but it suffered from a "flash of light theme" (FOLT) issue where the light theme would briefly appear before JavaScript could apply the saved dark mode preference.

## Root Cause
The HTML templates were hardcoded with `data-bs-theme="light"` and the theme switching was handled by JavaScript that ran after the DOM was loaded. This meant:

1. HTML loads with `data-bs-theme="light"`
2. CSS renders the light theme
3. User sees light theme briefly
4. JavaScript executes and changes to saved dark mode
5. CSS re-renders with dark theme

## Solution
The fix involves moving the theme detection and application to run **before** any content is rendered:

### 1. Removed Hardcoded Theme
**Before:**
```html
<html lang="en" data-bs-theme="light">
```

**After:**
```html
<html lang="en">
```

### 2. Added Immediate Theme Loading Script
Added a script in the `<head>` section that runs immediately:

```html
<!-- Theme loading script - must run before any content renders -->
<script>
    (function() {
        let theme = localStorage.getItem('theme');
        if (!theme) {
            // Check system preference if no saved theme
            theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        }
        document.documentElement.setAttribute('data-bs-theme', theme);
    })();
</script>
```

### 3. Updated DOMContentLoaded Handler
Modified the existing JavaScript to only handle icon updates since the theme is already set:

**Before:**
```javascript
document.addEventListener('DOMContentLoaded', function() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
    const icon = document.getElementById('themeIcon');
    icon.className = savedTheme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
});
```

**After:**
```javascript
document.addEventListener('DOMContentLoaded', function() {
    let theme = localStorage.getItem('theme');
    if (!theme) {
        theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    const icon = document.getElementById('themeIcon');
    if (icon) {
        icon.className = theme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
    }
});
```

## Improvements Made

### 1. Zero Flash
- Theme is now applied immediately before any content renders
- No more light theme flash when dark mode is preferred

### 2. System Preference Detection
- If no saved theme preference exists, the application now respects the user's system dark mode preference
- Uses `window.matchMedia('(prefers-color-scheme: dark)')` to detect system preference

### 3. Error Handling
- Added null check for theme icon element to prevent JavaScript errors
- Graceful fallback to light theme if system preference detection fails

## Files Modified
- `/src/web/templates/layout.html` - Main application layout
- `/src/web/templates/login.html` - Login page layout

## Technical Details

### Execution Order
1. HTML `<head>` loads
2. **Theme script executes immediately** (new)
3. CSS loads with correct theme already applied
4. Page content renders with correct theme
5. DOMContentLoaded fires and updates theme icon

### Performance Impact
- **Positive**: Eliminates layout shift from theme changes
- **Minimal**: Adds ~150 bytes of inline JavaScript
- **No blocking**: Script executes synchronously but is very fast

### Browser Compatibility
- Modern browsers: Full support including system preference detection
- Older browsers: Falls back to light theme gracefully
- IE11+: Basic theme switching works (no system preference detection)

## Testing
The fix has been tested and verified to:
- ✅ Eliminate the light theme flash
- ✅ Respect saved theme preferences
- ✅ Detect system dark mode preference for new users
- ✅ Maintain all existing theme toggle functionality
- ✅ Work on both login and main application pages

## Future Enhancements
Potential improvements for the future:
1. **Theme transition animations** - Smooth transitions when manually toggling
2. **Auto theme switching** - Respond to system theme changes in real-time
3. **Theme customization** - Allow users to customize color schemes
4. **High contrast mode** - Accessibility improvements