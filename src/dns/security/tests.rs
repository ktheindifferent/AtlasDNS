//! Comprehensive tests for DNS security features

#[cfg(test)]
mod tests {
    use super::super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use crate::dns::protocol::{DnsPacket, DnsQuestion, QueryType};

    fn create_test_packet(domain: &str, qtype: QueryType) -> DnsPacket {
        let mut packet = DnsPacket::new();
        packet.questions.push(DnsQuestion {
            name: domain.to_string(),
            qtype,
        });
        packet
    }

    fn create_test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
    }

    mod firewall_tests {
        use super::*;
        use crate::dns::security::firewall::*;

        #[test]
        fn test_firewall_creation() {
            let config = FirewallConfig::default();
            let firewall = DnsFirewall::new(config);
            
            let packet = create_test_packet("example.com", QueryType::A);
            let result = firewall.check_query(&packet, create_test_ip());
            
            assert!(result.allowed);
            assert_eq!(result.action, SecurityAction::Allow);
        }

        #[test]
        fn test_firewall_rule_blocking() {
            let config = FirewallConfig::default();
            let firewall = DnsFirewall::new(config);
            
            // Add a blocking rule
            let rule = FirewallRule {
                id: "test-rule-1".to_string(),
                name: "Block test domain".to_string(),
                description: "Test rule".to_string(),
                enabled: true,
                priority: 1,
                action: FirewallAction::BlockNxDomain,
                match_type: MatchType::ExactDomain,
                match_value: "blocked.com".to_string(),
                categories: vec![ThreatCategory::Malware],
                source_ips: vec![],
                query_types: vec![],
                expires_at: None,
                hit_count: 0,
            };
            
            firewall.add_rule(rule).unwrap();
            
            // Test blocked domain
            let packet = create_test_packet("blocked.com", QueryType::A);
            let result = firewall.check_query(&packet, create_test_ip());
            
            assert!(!result.allowed);
            assert_eq!(result.action, SecurityAction::BlockNxDomain);
            assert!(result.reason.is_some());
        }

        #[test]
        fn test_wildcard_blocking() {
            let config = FirewallConfig::default();
            let firewall = DnsFirewall::new(config);
            
            let rule = FirewallRule {
                id: "wildcard-rule".to_string(),
                name: "Block wildcard domains".to_string(),
                description: "Test wildcard".to_string(),
                enabled: true,
                priority: 1,
                action: FirewallAction::BlockNxDomain,
                match_type: MatchType::WildcardDomain,
                match_value: "*.malicious.com".to_string(),
                categories: vec![ThreatCategory::Malware],
                source_ips: vec![],
                query_types: vec![],
                expires_at: None,
                hit_count: 0,
            };
            
            firewall.add_rule(rule).unwrap();
            
            // Test subdomain blocking
            let packet = create_test_packet("subdomain.malicious.com", QueryType::A);
            let result = firewall.check_query(&packet, create_test_ip());
            
            assert!(!result.allowed);
            
            // Test exact domain
            let packet = create_test_packet("malicious.com", QueryType::A);
            let result = firewall.check_query(&packet, create_test_ip());
            
            assert!(!result.allowed);
        }

        #[test]
        fn test_regex_pattern_matching() {
            let config = FirewallConfig {
                enable_regex_matching: true,
                ..FirewallConfig::default()
            };
            let firewall = DnsFirewall::new(config);
            
            // Add regex pattern for DGA detection
            firewall.add_pattern(
                r"^[a-z0-9]{32,}\.com$",
                FirewallAction::BlockNxDomain,
                ThreatCategory::Malware
            ).unwrap();
            
            // Test DGA-like domain
            let packet = create_test_packet("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4.com", QueryType::A);
            let result = firewall.check_query(&packet, create_test_ip());
            
            assert!(!result.allowed);
            assert_eq!(result.threat_level, ThreatLevel::High);
        }

        #[test]
        fn test_firewall_metrics() {
            let config = FirewallConfig::default();
            let firewall = DnsFirewall::new(config);
            
            // Process some queries
            for i in 0..10 {
                let domain = format!("test{}.com", i);
                let packet = create_test_packet(&domain, QueryType::A);
                firewall.check_query(&packet, create_test_ip());
            }
            
            let metrics = firewall.get_metrics();
            assert_eq!(metrics.total_queries, 10);
            assert_eq!(metrics.allowed_queries, 10);
            assert_eq!(metrics.blocked_queries, 0);
        }
    }

    mod rate_limiter_tests {
        use super::*;
        use crate::dns::security::rate_limiter::*;

        #[test]
        fn test_token_bucket_rate_limiting() {
            let config = RateLimitConfig {
                enabled: true,
                algorithm: RateLimitAlgorithm::TokenBucket,
                per_client_qps: 5,
                per_client_burst: 10,
                ..RateLimitConfig::default()
            };
            
            let limiter = EnhancedRateLimiter::new(config);
            let client_ip = create_test_ip();
            
            // Should allow burst of queries
            for i in 0..10 {
                let packet = create_test_packet(&format!("test{}.com", i), QueryType::A);
                let result = limiter.check_rate_limit(&packet, client_ip);
                assert!(result.allowed, "Query {} should be allowed", i);
            }
            
            // 11th query should be rate limited
            let packet = create_test_packet("test11.com", QueryType::A);
            let result = limiter.check_rate_limit(&packet, client_ip);
            assert!(!result.allowed);
            assert_eq!(result.action, SecurityAction::RateLimit);
        }

        #[test]
        fn test_sliding_window_rate_limiting() {
            let config = RateLimitConfig {
                enabled: true,
                algorithm: RateLimitAlgorithm::SlidingWindow,
                per_client_qps: 5,
                window_size: Duration::from_secs(1),
                ..RateLimitConfig::default()
            };
            
            let limiter = EnhancedRateLimiter::new(config);
            let client_ip = create_test_ip();
            
            // Should allow up to limit
            for i in 0..5 {
                let packet = create_test_packet(&format!("test{}.com", i), QueryType::A);
                let result = limiter.check_rate_limit(&packet, client_ip);
                assert!(result.allowed);
            }
            
            // 6th query should be rate limited
            let packet = create_test_packet("test6.com", QueryType::A);
            let result = limiter.check_rate_limit(&packet, client_ip);
            assert!(!result.allowed);
        }

        #[test]
        fn test_client_banning() {
            let config = RateLimitConfig {
                enabled: true,
                per_client_qps: 2,
                per_client_burst: 2,
                ban_threshold: 3,
                ban_duration: Duration::from_secs(60),
                ..RateLimitConfig::default()
            };
            
            let limiter = EnhancedRateLimiter::new(config);
            let client_ip = create_test_ip();
            
            // Trigger multiple violations to get banned
            for _ in 0..5 {
                for i in 0..5 {
                    let packet = create_test_packet(&format!("test{}.com", i), QueryType::A);
                    let _ = limiter.check_rate_limit(&packet, client_ip);
                }
            }
            
            // Client should now be banned
            let packet = create_test_packet("test.com", QueryType::A);
            let result = limiter.check_rate_limit(&packet, client_ip);
            assert!(!result.allowed);
            assert_eq!(result.action, SecurityAction::BlockRefused);
            assert!(result.reason.unwrap().contains("banned"));
        }

        #[test]
        fn test_query_type_rate_limiting() {
            let mut query_type_limits = std::collections::HashMap::new();
            query_type_limits.insert("ANY".to_string(), 2);
            
            let config = RateLimitConfig {
                enabled: true,
                query_type_limits,
                ..RateLimitConfig::default()
            };
            
            let limiter = EnhancedRateLimiter::new(config);
            let client_ip = create_test_ip();
            
            // First two ANY queries should pass
            for i in 0..2 {
                let packet = create_test_packet(&format!("test{}.com", i), QueryType::ANY);
                let result = limiter.check_rate_limit(&packet, client_ip);
                assert!(result.allowed);
            }
            
            // Third ANY query should be rate limited
            let packet = create_test_packet("test3.com", QueryType::ANY);
            let result = limiter.check_rate_limit(&packet, client_ip);
            assert!(!result.allowed);
            
            // A queries should still work
            let packet = create_test_packet("test4.com", QueryType::A);
            let result = limiter.check_rate_limit(&packet, client_ip);
            assert!(result.allowed);
        }

        #[test]
        fn test_unblock_client() {
            let config = RateLimitConfig {
                enabled: true,
                per_client_qps: 1,
                ban_duration: Duration::from_secs(3600),
                ..RateLimitConfig::default()
            };
            
            let limiter = EnhancedRateLimiter::new(config);
            let client_ip = create_test_ip();
            
            // Get client rate limited
            for _ in 0..10 {
                let packet = create_test_packet("test.com", QueryType::A);
                let _ = limiter.check_rate_limit(&packet, client_ip);
            }
            
            // Unblock the client
            limiter.unblock_client(client_ip);
            
            // Client should now be allowed
            let packet = create_test_packet("test.com", QueryType::A);
            let result = limiter.check_rate_limit(&packet, client_ip);
            assert!(result.allowed);
        }
    }

    mod ddos_protection_tests {
        use super::*;
        use crate::dns::security::ddos_protection::*;

        #[test]
        fn test_ddos_detection() {
            let config = DDoSConfig {
                enabled: true,
                detection_threshold: 10,
                ..DDoSConfig::default()
            };
            
            let ddos_protection = DDoSProtection::new(config);
            let client_ip = create_test_ip();
            
            // Simulate query flood
            let mut detected = false;
            for i in 0..15 {
                let packet = create_test_packet(&format!("test{}.com", i), QueryType::A);
                let result = ddos_protection.check_attack(&packet, client_ip);
                if !result.allowed {
                    detected = true;
                    assert_eq!(result.threat_level, ThreatLevel::High);
                    break;
                }
            }
            
            assert!(detected, "DDoS attack should be detected");
        }

        #[test]
        fn test_amplification_attack_detection() {
            let config = DDoSConfig {
                enabled: true,
                enable_pattern_analysis: true,
                amplification_threshold: 5.0,
                ..DDoSConfig::default()
            };
            
            let ddos_protection = DDoSProtection::new(config);
            let client_ip = create_test_ip();
            
            // Test ANY query (common in amplification attacks)
            let packet = create_test_packet("example.com", QueryType::A);
            let result = ddos_protection.check_attack(&packet, client_ip);
            
            // Should detect potential amplification
            assert!(result.events.iter().any(|e| {
                matches!(e, SecurityEvent::AmplificationAttackDetected { .. })
            }));
        }

        #[test]
        fn test_random_subdomain_attack() {
            let config = DDoSConfig {
                enabled: true,
                enable_entropy_detection: true,
                random_subdomain_threshold: 0.5,
                ..DDoSConfig::default()
            };
            
            let ddos_protection = DDoSProtection::new(config);
            let client_ip = create_test_ip();
            
            // Test high entropy domain (random subdomain attack)
            let packet = create_test_packet("a1b2c3d4e5f6g7h8i9j0.example.com", QueryType::A);
            let result = ddos_protection.check_attack(&packet, client_ip);
            
            // Should detect high entropy
            assert!(result.events.iter().any(|e| {
                matches!(e, SecurityEvent::RandomSubdomainAttack { .. })
            }));
        }

        #[test]
        fn test_connection_limiting() {
            let config = DDoSConfig {
                enabled: true,
                max_connections_per_ip: 5,
                ..DDoSConfig::default()
            };
            
            let ddos_protection = DDoSProtection::new(config);
            let client_ip = create_test_ip();
            
            // Simulate multiple connections
            for i in 0..10 {
                let packet = create_test_packet(&format!("test{}.com", i), QueryType::A);
                let result = ddos_protection.check_attack(&packet, client_ip);
                
                if i >= 5 {
                    // Should hit connection limit
                    assert!(result.events.iter().any(|e| {
                        matches!(e, SecurityEvent::ConnectionLimitExceeded { .. })
                    }));
                }
            }
        }

        #[test]
        fn test_whitelist() {
            let config = DDoSConfig {
                enabled: true,
                detection_threshold: 1,
                whitelist: vec![create_test_ip()],
                ..DDoSConfig::default()
            };
            
            let ddos_protection = DDoSProtection::new(config);
            let client_ip = create_test_ip();
            
            // Whitelisted IP should never be blocked
            for i in 0..100 {
                let packet = create_test_packet(&format!("test{}.com", i), QueryType::A);
                let result = ddos_protection.check_attack(&packet, client_ip);
                assert!(result.allowed);
            }
        }

        #[test]
        fn test_ddos_metrics() {
            let config = DDoSConfig::default();
            let ddos_protection = DDoSProtection::new(config);
            let client_ip = create_test_ip();
            
            // Process some queries
            for i in 0..10 {
                let packet = create_test_packet(&format!("test{}.com", i), QueryType::A);
                ddos_protection.check_attack(&packet, client_ip);
            }
            
            let metrics = ddos_protection.get_metrics();
            assert_eq!(metrics.total_queries, 10);
            assert_eq!(metrics.current_threat_level, ThreatLevel::None);
        }
    }

    mod security_manager_tests {
        use super::*;
        use crate::dns::security::manager::*;

        #[test]
        fn test_security_manager_integration() {
            let config = SecurityConfig::default();
            let manager = SecurityManager::new(config);
            
            let packet = create_test_packet("example.com", QueryType::A);
            let client_ip = create_test_ip();
            
            // Normal query should pass all checks
            let result = manager.check_request(&packet, client_ip);
            assert!(result.allowed);
            assert_eq!(result.action, SecurityAction::Allow);
            assert_eq!(result.threat_level, ThreatLevel::None);
        }

        #[test]
        fn test_security_manager_firewall_integration() {
            let config = SecurityConfig::default();
            let manager = SecurityManager::new(config);
            
            // Add firewall rule
            let rule = crate::dns::security::firewall::FirewallRule {
                id: "test-rule".to_string(),
                name: "Block test".to_string(),
                description: "Test".to_string(),
                enabled: true,
                priority: 1,
                action: crate::dns::security::firewall::FirewallAction::BlockNxDomain,
                match_type: crate::dns::security::firewall::MatchType::ExactDomain,
                match_value: "blocked.com".to_string(),
                categories: vec![],
                source_ips: vec![],
                query_types: vec![],
                expires_at: None,
                hit_count: 0,
            };
            
            manager.add_firewall_rule(rule).unwrap();
            
            // Test blocked domain
            let packet = create_test_packet("blocked.com", QueryType::A);
            let result = manager.check_request(&packet, create_test_ip());
            
            assert!(!result.allowed);
            assert_eq!(result.action, SecurityAction::BlockNxDomain);
        }

        #[test]
        fn test_security_metrics_collection() {
            let config = SecurityConfig::default();
            let manager = SecurityManager::new(config);
            
            // Process various queries
            for i in 0..100 {
                let domain = if i % 10 == 0 {
                    "blocked.com"
                } else {
                    "example.com"
                };
                let packet = create_test_packet(domain, QueryType::A);
                manager.check_request(&packet, create_test_ip());
            }
            
            let metrics = manager.get_metrics();
            assert!(metrics.total_queries > 0);
            
            let stats = manager.get_statistics();
            assert_eq!(stats.total_requests, metrics.total_queries);
        }

        #[test]
        fn test_security_alerts() {
            let config = SecurityConfig {
                alert_threshold: AlertSeverity::Info,
                ..SecurityConfig::default()
            };
            let manager = SecurityManager::new(config);
            
            // Add a blocking rule to trigger alerts
            let rule = crate::dns::security::firewall::FirewallRule {
                id: "alert-test".to_string(),
                name: "Alert test".to_string(),
                description: "Test".to_string(),
                enabled: true,
                priority: 1,
                action: crate::dns::security::firewall::FirewallAction::BlockNxDomain,
                match_type: crate::dns::security::firewall::MatchType::ExactDomain,
                match_value: "malware.com".to_string(),
                categories: vec![crate::dns::security::firewall::ThreatCategory::Malware],
                source_ips: vec![],
                query_types: vec![],
                expires_at: None,
                hit_count: 0,
            };
            
            manager.add_firewall_rule(rule).unwrap();
            
            // Trigger the rule
            let packet = create_test_packet("malware.com", QueryType::A);
            manager.check_request(&packet, create_test_ip());
            
            // Check alerts were generated
            let alerts = manager.get_alerts(10);
            assert!(!alerts.is_empty());
            assert_eq!(alerts[0].alert_type, AlertType::FirewallBlock);
        }

        #[test]
        fn test_security_events_logging() {
            let config = SecurityConfig {
                log_security_events: true,
                max_event_log_size: 100,
                ..SecurityConfig::default()
            };
            let manager = SecurityManager::new(config);
            
            // Generate some events
            for i in 0..10 {
                let packet = create_test_packet(&format!("test{}.com", i), QueryType::A);
                manager.check_request(&packet, create_test_ip());
            }
            
            let events = manager.get_events(100);
            assert!(!events.is_empty());
        }
    }

    mod performance_tests {
        use super::*;
        use std::time::Instant;

        #[test]
        fn test_security_check_performance() {
            let config = SecurityConfig::default();
            let manager = SecurityManager::new(config);
            
            let packet = create_test_packet("example.com", QueryType::A);
            let client_ip = create_test_ip();
            
            let start = Instant::now();
            for _ in 0..10000 {
                manager.check_request(&packet, client_ip);
            }
            let duration = start.elapsed();
            
            // Should process 10k queries in under 1 second
            assert!(duration.as_secs() < 1, "Security checks too slow: {:?}", duration);
            
            let per_query = duration.as_micros() / 10000;
            println!("Security check performance: {}μs per query", per_query);
            
            // Each query should take less than 100 microseconds
            assert!(per_query < 100);
        }

        #[test]
        fn test_concurrent_security_checks() {
            use std::sync::Arc;
            use std::thread;
            
            let config = SecurityConfig::default();
            let manager = Arc::new(SecurityManager::new(config));
            
            let mut handles = vec![];
            
            // Spawn multiple threads
            for thread_id in 0..10 {
                let manager_clone = Arc::clone(&manager);
                let handle = thread::spawn(move || {
                    let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, thread_id as u8));
                    
                    for i in 0..1000 {
                        let packet = create_test_packet(&format!("test{}.com", i), QueryType::A);
                        manager_clone.check_request(&packet, client_ip);
                    }
                });
                handles.push(handle);
            }
            
            // Wait for all threads
            for handle in handles {
                handle.join().unwrap();
            }
            
            let metrics = manager.get_metrics();
            assert_eq!(metrics.total_queries, 10000);
        }
    }
}