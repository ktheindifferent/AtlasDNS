import { format, formatDistance, formatRelative, parseISO, isValid } from 'date-fns';
import { enUS, es, fr, de, zhCN, ar, he } from 'date-fns/locale';

const locales = {
  en: enUS,
  es: es,
  fr: fr,
  de: de,
  zh: zhCN,
  ar: ar,
  he: he,
};

export type DateLocale = keyof typeof locales;

export const getDateLocale = (language: string): typeof enUS => {
  const lang = language.split('-')[0] as DateLocale;
  return locales[lang] || enUS;
};

export const formatDate = (
  date: Date | string | number,
  formatString: string = 'PPP',
  language: string = 'en'
): string => {
  const dateObj = typeof date === 'string' ? parseISO(date) : new Date(date);
  
  if (!isValid(dateObj)) {
    return 'Invalid Date';
  }
  
  return format(dateObj, formatString, {
    locale: getDateLocale(language),
  });
};

export const formatDateTime = (
  date: Date | string | number,
  language: string = 'en'
): string => {
  return formatDate(date, 'PPpp', language);
};

export const formatShortDate = (
  date: Date | string | number,
  language: string = 'en'
): string => {
  return formatDate(date, 'P', language);
};

export const formatTime = (
  date: Date | string | number,
  language: string = 'en'
): string => {
  return formatDate(date, 'p', language);
};

export const formatRelativeTime = (
  date: Date | string | number,
  language: string = 'en'
): string => {
  const dateObj = typeof date === 'string' ? parseISO(date) : new Date(date);
  
  if (!isValid(dateObj)) {
    return 'Invalid Date';
  }
  
  return formatDistance(dateObj, new Date(), {
    addSuffix: true,
    locale: getDateLocale(language),
  });
};

export const formatRelativeDate = (
  date: Date | string | number,
  baseDate: Date = new Date(),
  language: string = 'en'
): string => {
  const dateObj = typeof date === 'string' ? parseISO(date) : new Date(date);
  
  if (!isValid(dateObj)) {
    return 'Invalid Date';
  }
  
  return formatRelative(dateObj, baseDate, {
    locale: getDateLocale(language),
  });
};

export const getLocaleFormats = (language: string = 'en') => {
  const locale = getDateLocale(language);
  
  return {
    dateFormat: locale.formatLong?.date({ width: 'short' }) || 'MM/dd/yyyy',
    timeFormat: locale.formatLong?.time({ width: 'short' }) || 'HH:mm',
    dateTimeFormat: 'PPpp',
    firstDayOfWeek: locale.options?.weekStartsOn || 0,
  };
};

export const formatNumber = (
  value: number,
  language: string = 'en',
  options?: Intl.NumberFormatOptions
): string => {
  const lang = language.split('-')[0];
  return new Intl.NumberFormat(lang, options).format(value);
};

export const formatCurrency = (
  value: number,
  currency: string = 'USD',
  language: string = 'en'
): string => {
  const lang = language.split('-')[0];
  return new Intl.NumberFormat(lang, {
    style: 'currency',
    currency,
  }).format(value);
};

export const formatPercent = (
  value: number,
  language: string = 'en',
  decimals: number = 2
): string => {
  const lang = language.split('-')[0];
  return new Intl.NumberFormat(lang, {
    style: 'percent',
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  }).format(value / 100);
};