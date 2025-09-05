//! Unit tests for user management functionality

#[cfg(test)]
mod tests {
    use crate::web::users::*;
    use crate::web::util::FormDataDecodable;
    use chrono::Utc;

    #[test]
    fn test_user_manager_new() {
        let manager = UserManager::new();
        
        // Should have default admin user
        let users = manager.list_users().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[0].role, UserRole::Admin);
    }

    #[test]
    fn test_password_hashing() {
        let password = "test123";
        let hash1 = UserManager::hash_password(password);
        let hash2 = UserManager::hash_password(password);
        
        // Same password should produce same hash
        assert_eq!(hash1, hash2);
        
        // Different passwords should produce different hashes
        let different_hash = UserManager::hash_password("different");
        assert_ne!(hash1, different_hash);
    }

    #[test]
    fn test_password_verification() {
        let password = "test123";
        let hash = UserManager::hash_password(password);
        
        assert!(UserManager::verify_password(password, &hash));
        assert!(!UserManager::verify_password("wrong", &hash));
    }

    #[test]
    fn test_create_user() {
        let manager = UserManager::new();
        
        let request = CreateUserRequest {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: UserRole::User,
        };
        
        let user = manager.create_user(request).unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.role, UserRole::User);
        assert!(user.is_active);
        
        // Should now have 2 users (admin + new user)
        assert_eq!(manager.list_users().unwrap().len(), 2);
    }

    #[test]
    fn test_create_user_duplicate_username() {
        let manager = UserManager::new();
        
        let request = CreateUserRequest {
            username: "admin".to_string(), // Same as default admin
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: UserRole::User,
        };
        
        let result = manager.create_user(request);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Username already exists");
    }

    #[test]
    fn test_authentication_success() {
        let manager = UserManager::new();
        
        // Test default admin authentication
        let user = manager.authenticate("admin", "admin123", None, None).unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, UserRole::Admin);
    }

    #[test]
    fn test_authentication_failure() {
        let manager = UserManager::new();
        
        // Wrong password
        let result = manager.authenticate("admin", "wrongpassword");
        assert!(result.is_err());
        
        // Non-existent user
        let result = manager.authenticate("nonexistent", "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_session_creation() {
        let manager = UserManager::new();
        let user_id = "test-user-id".to_string();
        
        let session = manager.create_session(
            user_id.clone(),
            Some("127.0.0.1".to_string()),
            Some("Test User Agent".to_string())
        ).unwrap();
        
        assert_eq!(session.user_id, user_id);
        assert!(session.ip_address.is_some());
        assert!(session.user_agent.is_some());
        assert!(!session.token.is_empty());
        assert!(session.expires_at > Utc::now());
    }

    #[test]
    fn test_session_validation() {
        let manager = UserManager::new();
        
        // First authenticate to get a user
        let user = manager.authenticate("admin", "admin123", None, None).unwrap();
        
        // Create a session for the user
        let session = manager.create_session(
            user.id.clone(),
            None,
            None
        ).unwrap();
        
        // Validate the session
        let (validated_session, validated_user) = manager
            .validate_session(&session.token)
            .unwrap();
        
        assert_eq!(validated_session.token, session.token);
        assert_eq!(validated_user.id, user.id);
    }

    #[test]
    fn test_session_validation_invalid_token() {
        let manager = UserManager::new();
        
        let result = manager.validate_session("invalid-token");
        assert!(result.is_err());
    }

    #[test]
    fn test_session_invalidation() {
        let manager = UserManager::new();
        let user = manager.authenticate("admin", "admin123", None, None).unwrap();
        let session = manager.create_session(user.id, None, None).unwrap();
        
        // Session should be valid initially
        assert!(manager.validate_session(&session.token).is_ok());
        
        // Invalidate the session
        assert!(manager.invalidate_session(&session.token).is_ok());
        
        // Session should no longer be valid
        assert!(manager.validate_session(&session.token).is_err());
    }

    #[test]
    fn test_update_user() {
        let manager = UserManager::new();
        let user = manager.authenticate("admin", "admin123", None, None).unwrap();
        
        let update_request = UpdateUserRequest {
            email: Some("newemail@example.com".to_string()),
            password: Some("newpassword123".to_string()),
            role: Some(UserRole::User),
            is_active: Some(false),
        };
        
        let updated_user = manager.update_user(&user.id, update_request).unwrap();
        
        assert_eq!(updated_user.email, "newemail@example.com");
        assert_eq!(updated_user.role, UserRole::User);
        assert!(!updated_user.is_active);
        
        // Verify password was changed
        assert!(UserManager::verify_password("newpassword123", &updated_user.password_hash));
    }

    #[test]
    fn test_delete_user() {
        let manager = UserManager::new();
        
        // Create a test user
        let request = CreateUserRequest {
            username: "deletetest".to_string(),
            email: "delete@example.com".to_string(),
            password: "password123".to_string(),
            role: UserRole::User,
        };
        let user = manager.create_user(request).unwrap();
        
        // Create a session for the user
        let session = manager.create_session(user.id.clone(), None, None).unwrap();
        
        // Verify user and session exist
        assert!(manager.get_user(&user.id).is_ok());
        assert!(manager.validate_session(&session.token).is_ok());
        
        // Delete the user
        assert!(manager.delete_user(&user.id).is_ok());
        
        // Verify user and sessions are gone
        assert!(manager.get_user(&user.id).is_err());
        assert!(manager.validate_session(&session.token).is_err());
    }

    #[test]
    fn test_list_sessions() {
        let manager = UserManager::new();
        let user = manager.authenticate("admin", "admin123", None, None).unwrap();
        
        // Initially no sessions
        let sessions = manager.list_sessions(Some(&user.id)).unwrap();
        assert_eq!(sessions.len(), 0);
        
        // Create multiple sessions
        let _session1 = manager.create_session(user.id.clone(), None, None).unwrap();
        let _session2 = manager.create_session(user.id.clone(), None, None).unwrap();
        
        // Should now have 2 sessions
        let sessions = manager.list_sessions(Some(&user.id)).unwrap();
        assert_eq!(sessions.len(), 2);
        
        // List all sessions (across all users)
        let all_sessions = manager.list_sessions(None).unwrap();
        assert!(all_sessions.len() >= 2);
    }

    #[test]
    fn test_cleanup_expired_sessions() {
        let manager = UserManager::new();
        let user = manager.authenticate("admin", "admin123", None, None).unwrap();
        
        // Create a session
        let _session = manager.create_session(user.id, None, None).unwrap();
        
        // Initially, cleanup should return 0 (no expired sessions)
        let cleaned = manager.cleanup_expired_sessions().unwrap();
        assert_eq!(cleaned, 0);
        
        // In a real scenario, we'd need to create sessions with past expiration dates
        // For this test, we're just verifying the function runs without error
    }

    #[test]
    fn test_user_roles() {
        let manager = UserManager::new();
        
        // Test all role types
        for role in &[UserRole::Admin, UserRole::User, UserRole::ReadOnly] {
            let request = CreateUserRequest {
                username: format!("user_{:?}", role),
                email: format!("{:?}@example.com", role),
                password: "password123".to_string(),
                role: *role,
            };
            
            let user = manager.create_user(request).unwrap();
            assert_eq!(user.role, *role);
        }
    }

    #[test]
    fn test_form_data_login_request() {
        let fields = vec![
            ("username".to_string(), "testuser".to_string()),
            ("password".to_string(), "testpass".to_string()),
        ];
        
        let login_request = LoginRequest::from_formdata(fields).unwrap();
        assert_eq!(login_request.username, "testuser");
        assert_eq!(login_request.password, "testpass");
    }

    #[test]
    fn test_form_data_login_request_missing_field() {
        let fields = vec![
            ("username".to_string(), "testuser".to_string()),
            // Missing password field
        ];
        
        let result = LoginRequest::from_formdata(fields);
        assert!(result.is_err());
    }

    #[test]
    fn test_form_data_create_user_request() {
        let fields = vec![
            ("username".to_string(), "newuser".to_string()),
            ("email".to_string(), "new@example.com".to_string()),
            ("password".to_string(), "newpass".to_string()),
            ("role".to_string(), "Admin".to_string()),
        ];
        
        let create_request = CreateUserRequest::from_formdata(fields).unwrap();
        assert_eq!(create_request.username, "newuser");
        assert_eq!(create_request.email, "new@example.com");
        assert_eq!(create_request.password, "newpass");
        assert_eq!(create_request.role, UserRole::Admin);
    }

    #[test]
    fn test_form_data_create_user_request_default_role() {
        let fields = vec![
            ("username".to_string(), "newuser".to_string()),
            ("email".to_string(), "new@example.com".to_string()),
            ("password".to_string(), "newpass".to_string()),
            // No role specified - should default to User
        ];
        
        let create_request = CreateUserRequest::from_formdata(fields).unwrap();
        assert_eq!(create_request.role, UserRole::User);
    }
}