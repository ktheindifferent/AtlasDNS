import { store } from '../store';
import {
  addNotification,
  processSnoozedNotifications,
  processScheduledNotifications,
} from '../store/slices/notificationSlice';
import {
  Notification,
  NotificationChannel,
  NotificationCategory,
  NotificationPriority,
  NotificationRule,
  NotificationCondition,
  NotificationRuleAction,
} from '../types/notification.types';
import axios from 'axios';

export class NotificationService {
  private static instance: NotificationService;
  private socket: any = null;
  private rulesEngine: RulesEngine;
  private channelHandlers: Map<NotificationChannel, ChannelHandler>;
  private processingInterval: NodeJS.Timeout | null = null;

  private constructor() {
    this.rulesEngine = new RulesEngine();
    this.channelHandlers = new Map();
    this.initializeChannelHandlers();
    this.startProcessingInterval();
  }

  static getInstance(): NotificationService {
    if (!NotificationService.instance) {
      NotificationService.instance = new NotificationService();
    }
    return NotificationService.instance;
  }

  setSocket(socket: any) {
    this.socket = socket;
    this.setupSocketListeners();
  }

  private setupSocketListeners() {
    if (!this.socket) return;

    this.socket.on('notification', (data: any) => {
      this.handleIncomingNotification(data);
    });

    this.socket.on('notification-batch', (data: any[]) => {
      data.forEach(notification => this.handleIncomingNotification(notification));
    });

    this.socket.on('rule-triggered', (data: any) => {
      this.handleRuleTriggered(data);
    });
  }

  private initializeChannelHandlers() {
    this.channelHandlers.set(NotificationChannel.IN_APP, new InAppChannelHandler());
    this.channelHandlers.set(NotificationChannel.EMAIL, new EmailChannelHandler());
    this.channelHandlers.set(NotificationChannel.SMS, new SMSChannelHandler());
    this.channelHandlers.set(NotificationChannel.SLACK, new SlackChannelHandler());
    this.channelHandlers.set(NotificationChannel.PUSH, new PushChannelHandler());
    this.channelHandlers.set(NotificationChannel.WEBHOOK, new WebhookChannelHandler());
  }

  private startProcessingInterval() {
    this.processingInterval = setInterval(() => {
      store.dispatch(processSnoozedNotifications());
      store.dispatch(processScheduledNotifications());
    }, 60000); // Check every minute
  }

  private async handleIncomingNotification(data: any) {
    const notification = await this.processNotification(data);
    
    // Apply rules
    const rules = store.getState().notifications.rules;
    const applicableRules = this.rulesEngine.evaluate(notification, rules);
    
    for (const rule of applicableRules) {
      await this.executeRuleActions(rule, notification);
    }
    
    // Send through channels
    await this.sendNotification(notification);
  }

  private async handleRuleTriggered(data: any) {
    const { ruleId, context } = data;
    const rule = store.getState().notifications.rules.find(r => r.id === ruleId);
    
    if (rule) {
      const notification = this.createNotificationFromRule(rule, context);
      await this.sendNotification(notification);
    }
  }

  private async processNotification(data: any): Promise<Notification> {
    return {
      id: data.id || `notif-${Date.now()}`,
      title: data.title,
      message: data.message,
      category: data.category || NotificationCategory.INFO,
      priority: data.priority || NotificationPriority.MEDIUM,
      channels: data.channels || [NotificationChannel.IN_APP],
      timestamp: Date.now(),
      read: false,
      status: data.status,
      actions: data.actions,
      metadata: data.metadata,
    } as Notification;
  }

  private createNotificationFromRule(rule: NotificationRule, context: any): Notification {
    return {
      id: `rule-notif-${Date.now()}`,
      title: this.interpolate(rule.name, context),
      message: this.interpolate(rule.description || '', context),
      category: rule.category || NotificationCategory.ALERT,
      priority: rule.priority || NotificationPriority.MEDIUM,
      channels: [NotificationChannel.IN_APP],
      timestamp: Date.now(),
      read: false,
      status: 'pending' as any,
      metadata: {
        ruleId: rule.id,
        context,
      },
    } as Notification;
  }

  private interpolate(template: string, context: any): string {
    return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      return context[key] || match;
    });
  }

  private async executeRuleActions(rule: NotificationRule, notification: Notification) {
    for (const action of rule.actions) {
      switch (action.type) {
        case 'notify':
          store.dispatch(addNotification(notification));
          break;
        case 'email':
          await this.channelHandlers.get(NotificationChannel.EMAIL)?.send(notification, action.config);
          break;
        case 'sms':
          await this.channelHandlers.get(NotificationChannel.SMS)?.send(notification, action.config);
          break;
        case 'slack':
          await this.channelHandlers.get(NotificationChannel.SLACK)?.send(notification, action.config);
          break;
        case 'webhook':
          await this.channelHandlers.get(NotificationChannel.WEBHOOK)?.send(notification, action.config);
          break;
        case 'log':
          console.log('[Notification Rule]', rule.name, notification);
          break;
      }
    }
  }

  async sendNotification(notification: Notification) {
    const preferences = store.getState().notifications.preferences;
    
    for (const channel of notification.channels) {
      const channelPrefs = preferences.channels[channel];
      
      if (!channelPrefs?.enabled) continue;
      
      if (channelPrefs.categories && !channelPrefs.categories.includes(notification.category)) {
        continue;
      }
      
      if (channelPrefs.priorities && !channelPrefs.priorities.includes(notification.priority)) {
        continue;
      }
      
      const handler = this.channelHandlers.get(channel);
      if (handler) {
        await handler.send(notification);
      }
    }
    
    // Always add to in-app notifications
    store.dispatch(addNotification(notification));
  }

  async sendTestNotification(channel: NotificationChannel) {
    const testNotification: Notification = {
      id: `test-${Date.now()}`,
      title: 'Test Notification',
      message: `This is a test notification for ${channel} channel`,
      category: NotificationCategory.INFO,
      priority: NotificationPriority.LOW,
      channels: [channel],
      timestamp: Date.now(),
      read: false,
      status: 'pending' as any,
    };
    
    await this.sendNotification(testNotification);
  }

  requestPermission(): Promise<NotificationPermission> {
    if ('Notification' in window) {
      return Notification.requestPermission();
    }
    return Promise.resolve('denied');
  }

  destroy() {
    if (this.processingInterval) {
      clearInterval(this.processingInterval);
    }
  }
}

class RulesEngine {
  evaluate(notification: Notification, rules: NotificationRule[]): NotificationRule[] {
    return rules.filter(rule => {
      if (!rule.enabled) return false;
      
      if (rule.cooldown) {
        const lastTriggered = this.getLastTriggeredTime(rule.id);
        if (lastTriggered && Date.now() - lastTriggered < rule.cooldown) {
          return false;
        }
      }
      
      if (rule.maxOccurrences) {
        const count = this.getOccurrenceCount(rule.id);
        if (count >= rule.maxOccurrences) {
          return false;
        }
      }
      
      if (rule.schedule && !this.isInSchedule(rule.schedule)) {
        return false;
      }
      
      return this.evaluateConditions(notification, rule.conditions);
    });
  }

  private evaluateConditions(notification: Notification, conditions: NotificationCondition[]): boolean {
    if (!conditions || conditions.length === 0) return true;
    
    let result = this.evaluateCondition(notification, conditions[0]);
    
    for (let i = 1; i < conditions.length; i++) {
      const condition = conditions[i];
      const conditionResult = this.evaluateCondition(notification, condition);
      
      if (condition.combineWith === 'OR') {
        result = result || conditionResult;
      } else {
        result = result && conditionResult;
      }
    }
    
    return result;
  }

  private evaluateCondition(notification: Notification, condition: NotificationCondition): boolean {
    const value = this.getFieldValue(notification, condition.field);
    
    switch (condition.operator) {
      case 'equals':
        return value === condition.value;
      case 'contains':
        return String(value).includes(String(condition.value));
      case 'greater_than':
        return Number(value) > Number(condition.value);
      case 'less_than':
        return Number(value) < Number(condition.value);
      case 'regex':
        return new RegExp(condition.value).test(String(value));
      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(value);
      case 'not_in':
        return Array.isArray(condition.value) && !condition.value.includes(value);
      default:
        return false;
    }
  }

  private getFieldValue(notification: Notification, field: string): any {
    const parts = field.split('.');
    let value: any = notification;
    
    for (const part of parts) {
      value = value?.[part];
    }
    
    return value;
  }

  private getLastTriggeredTime(ruleId: string): number | null {
    // Implementation would retrieve from storage
    return null;
  }

  private getOccurrenceCount(ruleId: string): number {
    // Implementation would retrieve from storage
    return 0;
  }

  private isInSchedule(schedule: any): boolean {
    const now = new Date();
    const currentDay = now.getDay();
    
    if (schedule.daysOfWeek && !schedule.daysOfWeek.includes(currentDay)) {
      return false;
    }
    
    if (schedule.startTime && schedule.endTime) {
      const [startHour, startMinute] = schedule.startTime.split(':').map(Number);
      const [endHour, endMinute] = schedule.endTime.split(':').map(Number);
      const currentMinutes = now.getHours() * 60 + now.getMinutes();
      const startMinutes = startHour * 60 + startMinute;
      const endMinutes = endHour * 60 + endMinute;
      
      return currentMinutes >= startMinutes && currentMinutes <= endMinutes;
    }
    
    return true;
  }
}

abstract class ChannelHandler {
  abstract send(notification: Notification, config?: any): Promise<void>;
}

class InAppChannelHandler extends ChannelHandler {
  async send(notification: Notification): Promise<void> {
    // In-app notifications are handled by the Redux store
    console.log('In-app notification sent:', notification.title);
  }
}

class EmailChannelHandler extends ChannelHandler {
  async send(notification: Notification, config?: any): Promise<void> {
    try {
      await axios.post('/api/notifications/email', {
        to: config?.to || 'user@example.com',
        subject: notification.title,
        body: notification.message,
        priority: notification.priority,
      });
    } catch (error) {
      console.error('Failed to send email notification:', error);
    }
  }
}

class SMSChannelHandler extends ChannelHandler {
  async send(notification: Notification, config?: any): Promise<void> {
    try {
      await axios.post('/api/notifications/sms', {
        to: config?.phoneNumber,
        message: `${notification.title}: ${notification.message}`,
      });
    } catch (error) {
      console.error('Failed to send SMS notification:', error);
    }
  }
}

class SlackChannelHandler extends ChannelHandler {
  async send(notification: Notification, config?: any): Promise<void> {
    try {
      const webhookUrl = config?.webhookUrl || process.env.REACT_APP_SLACK_WEBHOOK;
      
      if (!webhookUrl) {
        console.error('Slack webhook URL not configured');
        return;
      }
      
      await axios.post(webhookUrl, {
        text: notification.title,
        attachments: [{
          color: this.getPriorityColor(notification.priority),
          fields: [
            {
              title: 'Message',
              value: notification.message,
              short: false,
            },
            {
              title: 'Category',
              value: notification.category,
              short: true,
            },
            {
              title: 'Priority',
              value: notification.priority,
              short: true,
            },
          ],
          timestamp: Math.floor(notification.timestamp / 1000),
        }],
      });
    } catch (error) {
      console.error('Failed to send Slack notification:', error);
    }
  }

  private getPriorityColor(priority: NotificationPriority): string {
    switch (priority) {
      case NotificationPriority.URGENT:
        return '#FF0000';
      case NotificationPriority.HIGH:
        return '#FF9800';
      case NotificationPriority.MEDIUM:
        return '#2196F3';
      case NotificationPriority.LOW:
        return '#4CAF50';
      default:
        return '#9E9E9E';
    }
  }
}

class PushChannelHandler extends ChannelHandler {
  async send(notification: Notification): Promise<void> {
    if ('Notification' in window && Notification.permission === 'granted') {
      const options: NotificationOptions = {
        body: notification.message,
        icon: '/icon-192x192.png',
        badge: '/badge-72x72.png',
        tag: notification.id,
        requireInteraction: notification.priority === NotificationPriority.URGENT,
        data: {
          notificationId: notification.id,
          url: `/notifications/${notification.id}`,
        },
        actions: notification.actions?.map(action => ({
          action: action.id,
          title: action.label,
        })) || [],
      };
      
      if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
        navigator.serviceWorker.ready.then(registration => {
          registration.showNotification(notification.title, options);
        });
      } else {
        new Notification(notification.title, options);
      }
    }
  }
}

class WebhookChannelHandler extends ChannelHandler {
  async send(notification: Notification, config?: any): Promise<void> {
    try {
      const webhookUrl = config?.url;
      
      if (!webhookUrl) {
        console.error('Webhook URL not configured');
        return;
      }
      
      await axios.post(webhookUrl, {
        notification,
        timestamp: Date.now(),
        signature: this.generateSignature(notification, config?.secret),
      }, {
        headers: config?.headers || {},
      });
    } catch (error) {
      console.error('Failed to send webhook notification:', error);
    }
  }

  private generateSignature(notification: Notification, secret?: string): string {
    if (!secret) return '';
    
    // Simple signature generation - in production, use proper HMAC
    const payload = JSON.stringify(notification);
    return btoa(payload + secret);
  }
}

export default NotificationService;