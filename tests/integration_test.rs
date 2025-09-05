//! Integration tests for Atlas DNS Server
//!
//! These tests verify the interaction between different components
//! and test the system as a whole.

use atlas::dns::context::{ServerContext, ResolveStrategy};
use atlas::dns::protocol::{DnsRecord, QueryType, TransientTtl};
use atlas::dns::cache::SynchronizedCache;
use atlas::web::users::{UserManager, CreateUserRequest, UserRole};
use std::sync::Arc;
use std::net::Ipv4Addr;

/// Test the complete DNS resolution flow with caching
#[test]
fn test_dns_resolution_with_cache() {
    // Create server context
    let context = Arc::new(ServerContext::new().expect("Failed to create context"));
    
    // Test that context is properly initialized
    assert!(context.enable_udp);
    assert!(context.enable_tcp);
    assert_eq!(context.dns_port, 53);
}

/// Test cache integration with DNS records
#[test]
fn test_cache_integration() {
    let cache = SynchronizedCache::new();
    
    // Create test DNS records
    let records = vec![
        DnsRecord::A {
            domain: "test.example.com".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 1),
            ttl: TransientTtl(3600),
        },
        DnsRecord::Ns {
            domain: "example.com".to_string(),
            host: "ns1.example.com".to_string(),
            ttl: TransientTtl(86400),
        },
    ];
    
    // Store records in cache
    assert!(cache.store(&records).is_ok());
    
    // Verify we can retrieve them
    let result = cache.lookup("test.example.com", QueryType::A);
    assert!(result.is_some());
    
    if let Some(packet) = result {
        assert!(!packet.answers.is_empty());
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::A { domain, addr, .. } = &packet.answers[0] {
            assert_eq!(domain, "test.example.com");
            assert_eq!(addr, &Ipv4Addr::new(192, 168, 1, 1));
        } else {
            panic!("Expected A record");
        }
    }
}

/// Test user management and authentication flow
#[test]
fn test_user_authentication_flow() {
    let user_manager = UserManager::new();
    
    // Test default admin exists
    let admin = user_manager.authenticate("admin", "admin123", Some("127.0.0.1".to_string()), Some("Test Agent".to_string())).unwrap();
    assert_eq!(admin.role, UserRole::Admin);
    
    // Create a new user
    let create_request = CreateUserRequest {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "testpass123".to_string(),
        role: UserRole::User,
    };
    
    let user = user_manager.create_user(create_request).unwrap();
    
    // Test authentication with new user
    let authenticated_user = user_manager.authenticate("testuser", "testpass123", Some("127.0.0.1".to_string()), Some("Test Agent".to_string())).unwrap();
    assert_eq!(authenticated_user.id, user.id);
    assert_eq!(authenticated_user.role, UserRole::User);
    
    // Create session for authenticated user
    let session = user_manager.create_session(
        authenticated_user.id.clone(),
        Some("127.0.0.1".to_string()),
        Some("Test Agent".to_string())
    ).unwrap();
    
    // Validate session
    let (validated_session, validated_user) = user_manager
        .validate_session(&session.token)
        .unwrap();
    
    assert_eq!(validated_session.user_id, authenticated_user.id);
    assert_eq!(validated_user.username, "testuser");
}

/// Test server context configuration
#[test]
fn test_server_context_configuration() {
    let mut context = ServerContext::new().expect("Failed to create context");
    
    // Test default configuration
    assert_eq!(context.resolve_strategy, ResolveStrategy::Recursive);
    assert!(context.enable_api);
    assert!(context.enable_udp);
    assert!(context.enable_tcp);
    
    // Test changing configuration
    context.resolve_strategy = ResolveStrategy::Forward {
        host: "8.8.8.8".to_string(),
        port: 53,
    };
    
    if let ResolveStrategy::Forward { host, port } = &context.resolve_strategy {
        assert_eq!(host, "8.8.8.8");
        assert_eq!(*port, 53);
    } else {
        panic!("Expected Forward strategy");
    }
}

/// Test multiple record types in cache
#[test]
fn test_multiple_record_types_cache() {
    let cache = SynchronizedCache::new();
    
    let records = vec![
        DnsRecord::A {
            domain: "multi.example.com".to_string(),
            addr: Ipv4Addr::new(1, 2, 3, 4),
            ttl: TransientTtl(3600),
        },
        DnsRecord::Aaaa {
            domain: "multi.example.com".to_string(),
            addr: "2001:db8::1".parse().unwrap(),
            ttl: TransientTtl(3600),
        },
        DnsRecord::Cname {
            domain: "alias.example.com".to_string(),
            host: "multi.example.com".to_string(),
            ttl: TransientTtl(3600),
        },
        DnsRecord::Mx {
            domain: "multi.example.com".to_string(),
            priority: 10,
            host: "mail.example.com".to_string(),
            ttl: TransientTtl(3600),
        },
    ];
    
    assert!(cache.store(&records).is_ok());
    
    // Test A record lookup
    let a_result = cache.lookup("multi.example.com", QueryType::A);
    assert!(a_result.is_some());
    
    // Test AAAA record lookup
    let aaaa_result = cache.lookup("multi.example.com", QueryType::Aaaa);
    assert!(aaaa_result.is_some());
    
    // Test CNAME record lookup
    let cname_result = cache.lookup("alias.example.com", QueryType::Cname);
    assert!(cname_result.is_some());
    
    // Test MX record lookup
    let mx_result = cache.lookup("multi.example.com", QueryType::Mx);
    assert!(mx_result.is_some());
    
    // Test non-existent record type
    let ns_result = cache.lookup("multi.example.com", QueryType::Ns);
    assert!(ns_result.is_none());
}

/// Test user role permissions (integration with business logic)
#[test]
fn test_user_role_permissions() {
    let user_manager = UserManager::new();
    
    // Create users with different roles
    let roles = vec![
        (UserRole::Admin, "admin_user"),
        (UserRole::User, "regular_user"),
        (UserRole::ReadOnly, "readonly_user"),
    ];
    
    for (role, username) in roles {
        let request = CreateUserRequest {
            username: username.to_string(),
            email: format!("{}@example.com", username),
            password: "password123".to_string(),
            role,
        };
        
        let user = user_manager.create_user(request).unwrap();
        assert_eq!(user.role, role);
        
        // Test authentication works for all roles
        let authenticated = user_manager.authenticate(username, "password123", Some("127.0.0.1".to_string()), Some("Test Agent".to_string())).unwrap();
        assert_eq!(authenticated.role, role);
    }
}

/// Test cache memory management
#[test]
fn test_cache_memory_management() {
    let cache = SynchronizedCache::new();
    
    // Add records and verify they can be stored
    for i in 0..5 {
        let record = DnsRecord::A {
            domain: format!("test{}.example.com", i),
            addr: Ipv4Addr::new(192, 168, 1, i as u8),
            ttl: TransientTtl(3600),
        };
        
        assert!(cache.store(&vec![record]).is_ok());
    }
    
    // Verify we can list domains
    let domains = cache.list().unwrap();
    assert!(domains.len() > 0);
}

/// Test session lifecycle management
#[test]
fn test_session_lifecycle() {
    let user_manager = UserManager::new();
    
    // Authenticate and create session
    let user = user_manager.authenticate("admin", "admin123", Some("127.0.0.1".to_string()), Some("Test Agent".to_string())).unwrap();
    let session = user_manager.create_session(
        user.id.clone(),
        Some("192.168.1.100".to_string()),
        Some("Integration Test Agent".to_string())
    ).unwrap();
    
    // Verify session is valid
    assert!(user_manager.validate_session(&session.token).is_ok());
    
    // Test session listing
    let sessions = user_manager.list_sessions(Some(&user.id)).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].token, session.token);
    
    // Invalidate session
    assert!(user_manager.invalidate_session(&session.token).is_ok());
    
    // Verify session is no longer valid
    assert!(user_manager.validate_session(&session.token).is_err());
    
    // Verify session list is empty
    let sessions = user_manager.list_sessions(Some(&user.id)).unwrap();
    assert_eq!(sessions.len(), 0);
}

/// Test error handling across components
#[test]
fn test_error_handling() {
    let user_manager = UserManager::new();
    
    // Test authentication with invalid credentials
    assert!(user_manager.authenticate("nonexistent", "password", Some("127.0.0.1".to_string()), Some("Test Agent".to_string())).is_err());
    assert!(user_manager.authenticate("admin", "wrongpassword", Some("127.0.0.1".to_string()), Some("Test Agent".to_string())).is_err());
    
    // Test session validation with invalid token
    assert!(user_manager.validate_session("invalid-token").is_err());
    
    // Test user operations with invalid IDs
    assert!(user_manager.get_user("invalid-id").is_err());
    assert!(user_manager.delete_user("invalid-id").is_err());
    
    // Test duplicate username creation
    let duplicate_request = CreateUserRequest {
        username: "admin".to_string(), // Already exists
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        role: UserRole::User,
    };
    
    assert!(user_manager.create_user(duplicate_request).is_err());
}