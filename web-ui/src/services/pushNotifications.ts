// Push Notifications Service

export class PushNotificationService {
  private registration: ServiceWorkerRegistration | null = null;
  private subscription: PushSubscription | null = null;
  private vapidPublicKey: string = process.env.REACT_APP_VAPID_PUBLIC_KEY || '';

  constructor() {
    this.init();
  }

  private async init() {
    if ('serviceWorker' in navigator && 'PushManager' in window) {
      try {
        this.registration = await navigator.serviceWorker.ready;
        console.log('Push notifications initialized');
      } catch (error) {
        console.error('Failed to initialize push notifications:', error);
      }
    }
  }

  // Check if push notifications are supported and enabled
  public isSupported(): boolean {
    return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  }

  // Request permission for notifications
  public async requestPermission(): Promise<NotificationPermission> {
    if (!this.isSupported()) {
      throw new Error('Push notifications are not supported');
    }

    const permission = await Notification.requestPermission();
    
    if (permission === 'granted') {
      console.log('Notification permission granted');
      await this.subscribeToNotifications();
    } else if (permission === 'denied') {
      console.log('Notification permission denied');
    }
    
    return permission;
  }

  // Get current permission status
  public getPermissionStatus(): NotificationPermission {
    if (!this.isSupported()) {
      return 'denied';
    }
    return Notification.permission;
  }

  // Subscribe to push notifications
  private async subscribeToNotifications(): Promise<PushSubscription | null> {
    if (!this.registration) {
      await this.init();
    }

    if (!this.registration) {
      throw new Error('Service worker not registered');
    }

    try {
      // Check for existing subscription
      this.subscription = await this.registration.pushManager.getSubscription();
      
      if (!this.subscription) {
        // Create new subscription
        const applicationServerKey = this.urlBase64ToUint8Array(this.vapidPublicKey);
        
        this.subscription = await this.registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: applicationServerKey
        });

        // Send subscription to backend
        await this.sendSubscriptionToServer(this.subscription);
      }

      return this.subscription;
    } catch (error) {
      console.error('Failed to subscribe to notifications:', error);
      return null;
    }
  }

  // Unsubscribe from push notifications
  public async unsubscribe(): Promise<boolean> {
    if (!this.subscription) {
      const reg = await navigator.serviceWorker.ready;
      this.subscription = await reg.pushManager.getSubscription();
    }

    if (this.subscription) {
      try {
        await this.subscription.unsubscribe();
        await this.removeSubscriptionFromServer(this.subscription);
        this.subscription = null;
        return true;
      } catch (error) {
        console.error('Failed to unsubscribe:', error);
        return false;
      }
    }

    return false;
  }

  // Send subscription to backend server
  private async sendSubscriptionToServer(subscription: PushSubscription): Promise<void> {
    try {
      const response = await fetch('/api/notifications/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          subscription: subscription.toJSON(),
          userAgent: navigator.userAgent,
          timestamp: new Date().toISOString()
        })
      });

      if (!response.ok) {
        throw new Error('Failed to send subscription to server');
      }
    } catch (error) {
      console.error('Error sending subscription to server:', error);
    }
  }

  // Remove subscription from backend server
  private async removeSubscriptionFromServer(subscription: PushSubscription): Promise<void> {
    try {
      await fetch('/api/notifications/unsubscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          endpoint: subscription.endpoint
        })
      });
    } catch (error) {
      console.error('Error removing subscription from server:', error);
    }
  }

  // Show local notification
  public async showNotification(title: string, options?: NotificationOptions): Promise<void> {
    if (!this.registration) {
      await this.init();
    }

    if (this.registration && this.getPermissionStatus() === 'granted') {
      await this.registration.showNotification(title, {
        icon: '/icon-192x192.png',
        badge: '/icon-72x72.png',
        vibrate: [200, 100, 200],
        ...options
      });
    }
  }

  // Configure notification categories
  public configureNotificationCategories(categories: NotificationCategory[]): void {
    localStorage.setItem('notification-categories', JSON.stringify(categories));
  }

  // Get notification categories
  public getNotificationCategories(): NotificationCategory[] {
    const stored = localStorage.getItem('notification-categories');
    if (stored) {
      return JSON.parse(stored);
    }
    
    // Default categories
    return [
      { id: 'alerts', name: 'DNS Alerts', enabled: true },
      { id: 'monitoring', name: 'Monitoring Updates', enabled: true },
      { id: 'security', name: 'Security Notifications', enabled: true },
      { id: 'maintenance', name: 'Maintenance Windows', enabled: false }
    ];
  }

  // Update notification category preference
  public updateCategoryPreference(categoryId: string, enabled: boolean): void {
    const categories = this.getNotificationCategories();
    const category = categories.find(c => c.id === categoryId);
    
    if (category) {
      category.enabled = enabled;
      this.configureNotificationCategories(categories);
      
      // Update server preferences
      this.updateServerPreferences(categories);
    }
  }

  // Update server with notification preferences
  private async updateServerPreferences(categories: NotificationCategory[]): Promise<void> {
    try {
      await fetch('/api/notifications/preferences', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ categories })
      });
    } catch (error) {
      console.error('Failed to update notification preferences:', error);
    }
  }

  // Helper function to convert VAPID key
  private urlBase64ToUint8Array(base64String: string): Uint8Array {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }
    
    return outputArray;
  }
}

// Notification category interface
export interface NotificationCategory {
  id: string;
  name: string;
  enabled: boolean;
}

// Create singleton instance
export const pushNotificationService = new PushNotificationService();

// React Hook for push notifications
export function usePushNotifications() {
  const requestPermission = async () => {
    return await pushNotificationService.requestPermission();
  };

  const unsubscribe = async () => {
    return await pushNotificationService.unsubscribe();
  };

  const showNotification = async (title: string, options?: NotificationOptions) => {
    return await pushNotificationService.showNotification(title, options);
  };

  const getPermissionStatus = () => {
    return pushNotificationService.getPermissionStatus();
  };

  const isSupported = () => {
    return pushNotificationService.isSupported();
  };

  return {
    requestPermission,
    unsubscribe,
    showNotification,
    getPermissionStatus,
    isSupported
  };
}