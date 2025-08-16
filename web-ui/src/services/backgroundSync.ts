// Background Sync Service for offline actions

interface SyncRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body: any;
  timestamp: number;
  retryCount: number;
  type: 'dns-update' | 'config-change' | 'monitoring-action';
}

class BackgroundSyncService {
  private dbName = 'AtlasDNSSync';
  private dbVersion = 1;
  private storeName = 'pendingRequests';
  private db: IDBDatabase | null = null;

  constructor() {
    this.initDB();
  }

  // Initialize IndexedDB
  private async initDB(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion);

      request.onerror = () => {
        console.error('Failed to open IndexedDB');
        reject(request.error);
      };

      request.onsuccess = () => {
        this.db = request.result;
        console.log('IndexedDB initialized for background sync');
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        
        if (!db.objectStoreNames.contains(this.storeName)) {
          const store = db.createObjectStore(this.storeName, { keyPath: 'id' });
          store.createIndex('timestamp', 'timestamp', { unique: false });
          store.createIndex('type', 'type', { unique: false });
        }
      };
    });
  }

  // Ensure DB is ready
  private async ensureDB(): Promise<void> {
    if (!this.db) {
      await this.initDB();
    }
  }

  // Add request to sync queue
  public async addToSyncQueue(request: Omit<SyncRequest, 'id' | 'timestamp' | 'retryCount'>): Promise<string> {
    await this.ensureDB();

    const syncRequest: SyncRequest = {
      ...request,
      id: this.generateId(),
      timestamp: Date.now(),
      retryCount: 0
    };

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const addRequest = store.add(syncRequest);

      addRequest.onsuccess = async () => {
        console.log('Request added to sync queue:', syncRequest.id);
        
        // Trigger background sync if available
        await this.triggerBackgroundSync();
        
        resolve(syncRequest.id);
      };

      addRequest.onerror = () => {
        console.error('Failed to add request to sync queue');
        reject(addRequest.error);
      };
    });
  }

  // Get all pending requests
  public async getPendingRequests(): Promise<SyncRequest[]> {
    await this.ensureDB();

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      const transaction = this.db.transaction([this.storeName], 'readonly');
      const store = transaction.objectStore(this.storeName);
      const getRequest = store.getAll();

      getRequest.onsuccess = () => {
        resolve(getRequest.result || []);
      };

      getRequest.onerror = () => {
        reject(getRequest.error);
      };
    });
  }

  // Remove request from queue
  public async removeFromQueue(id: string): Promise<void> {
    await this.ensureDB();

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const deleteRequest = store.delete(id);

      deleteRequest.onsuccess = () => {
        console.log('Request removed from sync queue:', id);
        resolve();
      };

      deleteRequest.onerror = () => {
        reject(deleteRequest.error);
      };
    });
  }

  // Update retry count for failed request
  public async updateRetryCount(id: string): Promise<void> {
    await this.ensureDB();

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const getRequest = store.get(id);

      getRequest.onsuccess = () => {
        const request = getRequest.result;
        if (request) {
          request.retryCount++;
          const updateRequest = store.put(request);
          
          updateRequest.onsuccess = () => {
            resolve();
          };
          
          updateRequest.onerror = () => {
            reject(updateRequest.error);
          };
        } else {
          resolve();
        }
      };

      getRequest.onerror = () => {
        reject(getRequest.error);
      };
    });
  }

  // Trigger background sync
  private async triggerBackgroundSync(): Promise<void> {
    if ('serviceWorker' in navigator && 'sync' in ServiceWorkerRegistration.prototype) {
      try {
        const registration = await navigator.serviceWorker.ready;
        await (registration as any).sync.register('sync-dns-updates');
        console.log('Background sync triggered');
      } catch (error) {
        console.error('Failed to trigger background sync:', error);
        // Fallback to manual sync
        await this.manualSync();
      }
    } else {
      // Background sync not supported, use manual sync
      await this.manualSync();
    }
  }

  // Manual sync for browsers without background sync support
  private async manualSync(): Promise<void> {
    const requests = await this.getPendingRequests();
    
    for (const request of requests) {
      // Skip if too many retries
      if (request.retryCount >= 3) {
        await this.removeFromQueue(request.id);
        continue;
      }

      try {
        const response = await fetch(request.url, {
          method: request.method,
          headers: request.headers,
          body: JSON.stringify(request.body)
        });

        if (response.ok) {
          await this.removeFromQueue(request.id);
          this.notifySuccess(request);
        } else if (response.status >= 400 && response.status < 500) {
          // Client error, don't retry
          await this.removeFromQueue(request.id);
          this.notifyError(request, 'Client error');
        } else {
          // Server error, retry later
          await this.updateRetryCount(request.id);
        }
      } catch (error) {
        // Network error, retry later
        await this.updateRetryCount(request.id);
        console.error('Sync failed for request:', request.id, error);
      }
    }
  }

  // Clear all pending requests
  public async clearQueue(): Promise<void> {
    await this.ensureDB();

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const clearRequest = store.clear();

      clearRequest.onsuccess = () => {
        console.log('Sync queue cleared');
        resolve();
      };

      clearRequest.onerror = () => {
        reject(clearRequest.error);
      };
    });
  }

  // Get queue status
  public async getQueueStatus(): Promise<{ pending: number; types: Record<string, number> }> {
    const requests = await this.getPendingRequests();
    
    const types: Record<string, number> = {};
    requests.forEach(req => {
      types[req.type] = (types[req.type] || 0) + 1;
    });

    return {
      pending: requests.length,
      types
    };
  }

  // Notify success
  private notifySuccess(request: SyncRequest): void {
    window.dispatchEvent(new CustomEvent('sync-success', { 
      detail: { request } 
    }));
  }

  // Notify error
  private notifyError(request: SyncRequest, error: string): void {
    window.dispatchEvent(new CustomEvent('sync-error', { 
      detail: { request, error } 
    }));
  }

  // Generate unique ID
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Check online status and sync
  public startOnlineListener(): void {
    window.addEventListener('online', async () => {
      console.log('Connection restored, syncing pending requests...');
      await this.manualSync();
    });

    window.addEventListener('offline', () => {
      console.log('Connection lost, requests will be queued');
    });
  }
}

// Create singleton instance
export const backgroundSyncService = new BackgroundSyncService();

// React Hook for background sync
export function useBackgroundSync() {
  const queueRequest = async (
    url: string,
    method: string,
    body: any,
    type: 'dns-update' | 'config-change' | 'monitoring-action' = 'dns-update'
  ) => {
    return await backgroundSyncService.addToSyncQueue({
      url,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('auth-token') || ''}`
      },
      body,
      type
    });
  };

  const getPendingCount = async () => {
    const status = await backgroundSyncService.getQueueStatus();
    return status.pending;
  };

  const clearQueue = async () => {
    return await backgroundSyncService.clearQueue();
  };

  const getQueueStatus = async () => {
    return await backgroundSyncService.getQueueStatus();
  };

  return {
    queueRequest,
    getPendingCount,
    clearQueue,
    getQueueStatus
  };
}

// Initialize online listener
backgroundSyncService.startOnlineListener();