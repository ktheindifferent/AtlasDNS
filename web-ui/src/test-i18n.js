// Test script to verify i18n setup
const fs = require('fs');
const path = require('path');

const languages = ['en', 'es', 'fr', 'de', 'zh', 'ar', 'he'];
const namespaces = ['common', 'dashboard', 'zones', 'auth'];

console.log('Checking i18n translation files...\n');

let allGood = true;

languages.forEach(lang => {
  console.log(`Checking language: ${lang}`);
  
  namespaces.forEach(ns => {
    const filePath = path.join(__dirname, '..', 'public', 'locales', lang, `${ns}.json`);
    
    if (fs.existsSync(filePath)) {
      try {
        const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        console.log(`  ✓ ${ns}.json exists and is valid JSON`);
      } catch (e) {
        console.log(`  ✗ ${ns}.json exists but has invalid JSON: ${e.message}`);
        allGood = false;
      }
    } else {
      if (lang === 'en' || ns === 'common') {
        console.log(`  ✗ ${ns}.json is missing (required)`);
        allGood = false;
      } else {
        console.log(`  ⚠ ${ns}.json is missing (optional)`);
      }
    }
  });
  
  console.log('');
});

if (allGood) {
  console.log('✅ All required translation files are present and valid!');
} else {
  console.log('❌ Some required translation files are missing or invalid.');
  process.exit(1);
}

// Check i18n configuration
console.log('\nChecking i18n configuration...');
if (fs.existsSync(path.join(__dirname, 'i18n', 'config.ts'))) {
  console.log('✓ i18n config file exists');
} else {
  console.log('✗ i18n config file is missing');
  allGood = false;
}

// Check key components
const components = [
  'components/LanguageSwitcher.tsx',
  'providers/RTLProvider.tsx',
  'utils/dateFormatter.ts'
];

console.log('\nChecking i18n components...');
components.forEach(comp => {
  if (fs.existsSync(path.join(__dirname, comp))) {
    console.log(`✓ ${comp} exists`);
  } else {
    console.log(`✗ ${comp} is missing`);
    allGood = false;
  }
});

console.log('\n' + (allGood ? '✅ i18n setup is complete!' : '❌ i18n setup has issues.'));