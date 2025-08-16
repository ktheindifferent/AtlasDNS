# Internationalization (i18n) Translation Workflow

## Overview
This document outlines the workflow for managing translations in the Atlas DNS Manager UI.

## Supported Languages
- English (en) - Base language
- Spanish (es)
- French (fr)
- German (de)
- Chinese Simplified (zh)
- Arabic (ar) - RTL support
- Hebrew (he) - RTL support

## Directory Structure
```
public/
└── locales/
    ├── en/
    │   ├── common.json
    │   ├── dashboard.json
    │   ├── zones.json
    │   ├── auth.json
    │   └── ...
    ├── es/
    │   └── ...
    └── ...
```

## Translation Files
Each language has its translation files organized by namespace:
- `common.json` - Common UI elements, navigation, actions
- `dashboard.json` - Dashboard specific translations
- `zones.json` - DNS Zones page translations
- `auth.json` - Authentication related translations
- Additional namespaces as needed

## Adding New Translations

### 1. Add to English Base File
Always start by adding the key to the English translation file:
```json
{
  "newFeature": {
    "title": "New Feature",
    "description": "This is a new feature"
  }
}
```

### 2. Use in Component
```typescript
import { useTranslation } from 'react-i18next';

const Component = () => {
  const { t } = useTranslation('namespace');
  
  return <div>{t('newFeature.title')}</div>;
};
```

### 3. Add Translations for Other Languages
Update the corresponding keys in other language files.

## Translation Guidelines

### Key Naming Conventions
- Use camelCase for keys
- Use nested objects for related translations
- Keep keys descriptive and semantic

### Pluralization
Use i18next's built-in pluralization:
```json
{
  "items": "{{count}} item",
  "items_plural": "{{count}} items"
}
```

### Interpolation
Use interpolation for dynamic values:
```json
{
  "welcome": "Welcome, {{name}}!",
  "itemCount": "You have {{count}} items"
}
```

### Date/Time Formatting
Use the provided `dateFormatter` utility for locale-specific date formatting:
```typescript
import { formatDate, formatRelativeTime } from '../utils/dateFormatter';

const formattedDate = formatDate(date, 'PPP', i18n.language);
```

## RTL Language Support
Arabic and Hebrew are configured with RTL support. The application automatically:
- Sets document direction to RTL
- Applies RTL-specific styles
- Uses RTL-compatible fonts

## Testing Translations

### Language Switching
Test all languages using the language switcher in the header:
1. Click the language icon
2. Select a different language
3. Verify all text updates correctly
4. Check RTL layout for Arabic/Hebrew

### Missing Translations
In development mode, missing translations are logged to the console.

### Browser Language Detection
The app detects browser language on first load. Test by:
1. Clearing localStorage
2. Setting browser language preference
3. Refreshing the application

## Translation Management Tools

### Extract Untranslated Keys
Run in development to see missing translations in console.

### Translation Validation Script
```bash
# Check for missing keys across languages
node scripts/validate-translations.js
```

### Export for Translation Service
```bash
# Export keys for professional translation
node scripts/export-translations.js
```

## Best Practices

1. **Always provide English translations first** - English is the fallback language
2. **Keep translations concise** - UI space is limited
3. **Consider cultural context** - Some phrases don't translate directly
4. **Test with actual data** - Ensure translations work with real content
5. **Maintain consistency** - Use the same translation for the same term throughout
6. **Update all languages together** - Don't leave translations incomplete

## Adding a New Language

1. Add language configuration to `src/i18n/config.ts`:
```typescript
export const SUPPORTED_LANGUAGES = {
  // ... existing languages
  ja: { name: '日本語', flag: '🇯🇵', dir: 'ltr' },
};
```

2. Create translation directory: `public/locales/ja/`
3. Copy English files as templates
4. Add date-fns locale in `src/utils/dateFormatter.ts`
5. Translate all content
6. Test thoroughly

## Professional Translation Process

1. Export English keys to CSV/JSON
2. Send to translation service
3. Import translated content
4. Review and test in application
5. Make contextual adjustments as needed

## Maintenance

- Review translations quarterly
- Update for new features immediately
- Monitor user feedback for translation issues
- Keep terminology consistent across updates