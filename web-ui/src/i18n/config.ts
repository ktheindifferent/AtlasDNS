import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import Backend from 'i18next-http-backend';

export const SUPPORTED_LANGUAGES = {
  en: { name: 'English', flag: '🇬🇧', dir: 'ltr' },
  es: { name: 'Español', flag: '🇪🇸', dir: 'ltr' },
  fr: { name: 'Français', flag: '🇫🇷', dir: 'ltr' },
  de: { name: 'Deutsch', flag: '🇩🇪', dir: 'ltr' },
  zh: { name: '中文', flag: '🇨🇳', dir: 'ltr' },
  ar: { name: 'العربية', flag: '🇸🇦', dir: 'rtl' },
  he: { name: 'עברית', flag: '🇮🇱', dir: 'rtl' },
} as const;

export type SupportedLanguage = keyof typeof SUPPORTED_LANGUAGES;

const detectionOptions = {
  order: ['localStorage', 'navigator', 'htmlTag', 'path', 'subdomain'],
  caches: ['localStorage'],
  lookupLocalStorage: 'i18nextLng',
  lookupFromPathIndex: 0,
  lookupFromSubdomainIndex: 0,
  checkWhitelist: true,
};

i18n
  .use(Backend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: 'en',
    debug: process.env.NODE_ENV === 'development',
    
    detection: detectionOptions,
    
    interpolation: {
      escapeValue: false,
    },
    
    backend: {
      loadPath: '/locales/{{lng}}/{{ns}}.json',
    },
    
    ns: ['common', 'dashboard', 'zones', 'records', 'settings', 'auth', 'errors'],
    defaultNS: 'common',
    
    react: {
      useSuspense: true,
    },
    
    supportedLngs: Object.keys(SUPPORTED_LANGUAGES),
    
    load: 'languageOnly',
    
    saveMissing: process.env.NODE_ENV === 'development',
    missingKeyHandler: (lng, ns, key, fallbackValue) => {
      if (process.env.NODE_ENV === 'development') {
        console.warn(`Missing translation: ${lng}/${ns}:${key}`);
      }
    },
  });

export default i18n;

export const getLanguageDirection = (language: string): 'ltr' | 'rtl' => {
  const lang = language.split('-')[0] as SupportedLanguage;
  return SUPPORTED_LANGUAGES[lang]?.dir || 'ltr';
};

export const isRTLLanguage = (language: string): boolean => {
  return getLanguageDirection(language) === 'rtl';
};