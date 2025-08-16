export enum NotificationPriority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  URGENT = 'urgent',
}

export enum NotificationCategory {
  SYSTEM = 'system',
  SECURITY = 'security',
  ZONE = 'zone',
  RECORD = 'record',
  HEALTH = 'health',
  PERFORMANCE = 'performance',
  USER = 'user',
  ALERT = 'alert',
  INFO = 'info',
}

export enum NotificationChannel {
  IN_APP = 'in_app',
  EMAIL = 'email',
  SMS = 'sms',
  SLACK = 'slack',
  WEBHOOK = 'webhook',
  PUSH = 'push',
}

export enum NotificationStatus {
  PENDING = 'pending',
  DELIVERED = 'delivered',
  READ = 'read',
  SNOOZED = 'snoozed',
  ARCHIVED = 'archived',
  FAILED = 'failed',
}

export interface NotificationAction {
  id: string;
  label: string;
  icon?: string;
  primary?: boolean;
  handler?: string;
  data?: Record<string, any>;
}

export interface NotificationMetadata {
  source?: string;
  entity?: string;
  entityId?: string;
  userId?: string;
  sessionId?: string;
  ip?: string;
  userAgent?: string;
  [key: string]: any;
}

export interface NotificationRule {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  conditions: NotificationCondition[];
  actions: NotificationRuleAction[];
  priority?: NotificationPriority;
  category?: NotificationCategory;
  cooldown?: number;
  maxOccurrences?: number;
  schedule?: NotificationSchedule;
}

export interface NotificationCondition {
  field: string;
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than' | 'regex' | 'in' | 'not_in';
  value: any;
  combineWith?: 'AND' | 'OR';
}

export interface NotificationRuleAction {
  type: 'notify' | 'email' | 'sms' | 'slack' | 'webhook' | 'log';
  config: Record<string, any>;
}

export interface NotificationSchedule {
  timezone?: string;
  daysOfWeek?: number[];
  startTime?: string;
  endTime?: string;
  excludeDates?: string[];
}

export interface DoNotDisturbConfig {
  enabled: boolean;
  schedule?: NotificationSchedule;
  allowUrgent: boolean;
  allowedCategories?: NotificationCategory[];
  overrideKeywords?: string[];
}

export interface NotificationPreferences {
  channels: {
    [key in NotificationChannel]?: {
      enabled: boolean;
      categories?: NotificationCategory[];
      priorities?: NotificationPriority[];
    };
  };
  doNotDisturb: DoNotDisturbConfig;
  grouping: {
    enabled: boolean;
    timeWindow: number;
    maxGroupSize: number;
  };
  sound: boolean;
  vibration: boolean;
  desktop: boolean;
}

export interface Notification {
  id: string;
  title: string;
  message: string;
  category: NotificationCategory;
  priority: NotificationPriority;
  status: NotificationStatus;
  channels: NotificationChannel[];
  timestamp: number;
  expiresAt?: number;
  scheduledFor?: number;
  snoozedUntil?: number;
  groupId?: string;
  parentId?: string;
  read: boolean;
  readAt?: number;
  actions?: NotificationAction[];
  metadata?: NotificationMetadata;
  deliveryStatus?: {
    [key in NotificationChannel]?: {
      status: 'pending' | 'sent' | 'failed';
      timestamp?: number;
      error?: string;
    };
  };
}

export interface NotificationGroup {
  id: string;
  title: string;
  category: NotificationCategory;
  count: number;
  notifications: Notification[];
  firstTimestamp: number;
  lastTimestamp: number;
  read: boolean;
  collapsed: boolean;
}

export interface NotificationFilter {
  categories?: NotificationCategory[];
  priorities?: NotificationPriority[];
  statuses?: NotificationStatus[];
  channels?: NotificationChannel[];
  search?: string;
  dateFrom?: number;
  dateTo?: number;
  read?: boolean;
  groupId?: string;
}

export interface NotificationStats {
  total: number;
  unread: number;
  byCategory: Record<NotificationCategory, number>;
  byPriority: Record<NotificationPriority, number>;
  byChannel: Record<NotificationChannel, number>;
  todayCount: number;
  weekCount: number;
}