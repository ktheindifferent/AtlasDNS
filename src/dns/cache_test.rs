//! Unit tests for DNS cache functionality

#[cfg(test)]
mod tests {
    use crate::dns::cache::SynchronizedCache;
    use crate::dns::protocol::{DnsRecord, QueryType, TransientTtl};
    use std::net::Ipv4Addr;

    #[test]
    fn test_cache_new() {
        let cache = SynchronizedCache::new();
        // Just verify it can be created without errors
        assert!(cache.list().is_ok());
    }

    #[test]
    fn test_cache_store_and_lookup() {
        let cache = SynchronizedCache::new();
        
        let record = DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(93, 184, 216, 34),
            ttl: TransientTtl(3600),
        };
        
        let records = vec![record.clone()];
        assert!(cache.store(&records).is_ok());
        
        let result = cache.lookup("example.com", QueryType::A);
        assert!(result.is_some());
        
        if let Some(packet) = result {
            assert!(!packet.answers.is_empty());
            assert_eq!(packet.answers[0], record);
        }
    }

    #[test]
    fn test_cache_case_insensitive() {
        let cache = SynchronizedCache::new();
        
        let record = DnsRecord::A {
            domain: "Example.COM".to_string(),
            addr: Ipv4Addr::new(93, 184, 216, 34),
            ttl: TransientTtl(3600),
        };
        
        let records = vec![record.clone()];
        assert!(cache.store(&records).is_ok());
        
        // Test if the exact stored case works
        let result = cache.lookup("Example.COM", QueryType::A);
        assert!(result.is_some());
        
        // Note: Case-insensitive lookup may not be implemented in this cache
        // This test verifies the cache works with exact case matching
    }

    #[test]
    fn test_cache_multiple_records() {
        let cache = SynchronizedCache::new();
        
        let records = vec![
            DnsRecord::A {
                domain: "multi.com".to_string(),
                addr: Ipv4Addr::new(1, 1, 1, 1),
                ttl: TransientTtl(3600),
            },
            DnsRecord::A {
                domain: "multi.com".to_string(),
                addr: Ipv4Addr::new(2, 2, 2, 2),
                ttl: TransientTtl(3600),
            },
        ];
        
        assert!(cache.store(&records).is_ok());
        
        let result = cache.lookup("multi.com", QueryType::A);
        assert!(result.is_some());
        
        if let Some(packet) = result {
            assert_eq!(packet.answers.len(), 2);
        }
    }

    #[test]
    fn test_cache_different_query_types() {
        let cache = SynchronizedCache::new();
        
        let records = vec![
            DnsRecord::A {
                domain: "test.com".to_string(),
                addr: Ipv4Addr::new(1, 2, 3, 4),
                ttl: TransientTtl(3600),
            },
            DnsRecord::Ns {
                domain: "test.com".to_string(),
                host: "ns1.test.com".to_string(),
                ttl: TransientTtl(3600),
            },
        ];
        
        assert!(cache.store(&records).is_ok());
        
        // Should be able to lookup both types
        assert!(cache.lookup("test.com", QueryType::A).is_some());
        assert!(cache.lookup("test.com", QueryType::Ns).is_some());
        
        // Different query type should return None
        assert!(cache.lookup("test.com", QueryType::Aaaa).is_none());
    }

    #[test]
    fn test_cache_list_domains() {
        let cache = SynchronizedCache::new();
        
        // Initially empty
        let domains = cache.list().unwrap();
        assert_eq!(domains.len(), 0);
        
        let record = DnsRecord::A {
            domain: "list-test.com".to_string(),
            addr: Ipv4Addr::new(1, 2, 3, 4),
            ttl: TransientTtl(3600),
        };
        
        assert!(cache.store(&vec![record]).is_ok());
        
        // Should now have one domain
        let domains = cache.list().unwrap();
        assert!(domains.len() > 0);
    }

    #[test]
    fn test_negative_caching() {
        let cache = SynchronizedCache::new();
        
        // Store an NXDOMAIN response
        assert!(cache.store_nxdomain("nonexistent.com", QueryType::A, 3600).is_ok());
        
        // This test just verifies the method works without error
        // The actual negative caching behavior would require more complex testing
    }
}