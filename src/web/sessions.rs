use crate::web::users::{UserManager, User, Session};
use tiny_http::{Request, Header};
use std::sync::Arc;

pub struct SessionMiddleware {
    user_manager: Arc<UserManager>,
}

impl SessionMiddleware {
    pub fn new(user_manager: Arc<UserManager>) -> Self {
        SessionMiddleware { user_manager }
    }
    
    pub fn extract_token(&self, request: &Request) -> Option<String> {
        // First try Authorization header
        let auth_result = request
            .headers()
            .iter()
            .find(|h| h.field.as_str() == "Authorization")
            .and_then(|h| {
                let value: String = h.value.clone().into();
                if value.starts_with("Bearer ") {
                    Some(value[7..].to_string())
                } else {
                    None
                }
            });
        
        if auth_result.is_some() {
            return auth_result;
        }
        
        // Then try Cookie header (case-insensitive)
        let cookie_result = request
            .headers()
            .iter()
            .find(|h| h.field.as_str().eq_ignore_ascii_case("cookie"))
            .and_then(|h| {
                let value: String = h.value.clone().into();
                log::debug!("Cookie header value: '{}'", value);
                
                let token = value
                    .split(';')
                    .find(|c| c.trim().starts_with("session_token="))
                    .map(|c| {
                        let trimmed = c.trim();
                        log::debug!("Found session_token cookie part: '{}'", trimmed);
                        // Extract the value after "session_token="
                        trimmed.strip_prefix("session_token=").unwrap_or("").to_string()
                    });
                
                log::debug!("Extracted token: {:?}", token);
                token
            });
            
        if cookie_result.is_none() {
            log::debug!("No Cookie header found or no session_token in cookie");
            // Log all headers for debugging
            log::debug!("All request headers:");
            for header in request.headers() {
                log::debug!("  {} = {}", header.field, header.value);
            }
        }
        
        cookie_result
    }
    
    pub fn validate_request(&self, request: &Request) -> Result<(Session, User), String> {
        let token = self.extract_token(request)
            .ok_or_else(|| {
                log::debug!("No session token found in request");
                "No session token provided".to_string()
            })?;
        
        log::debug!("Validating session token: '{}'", token);
        let result = self.user_manager.validate_session(&token);
        log::debug!("Session validation result: {:?}", result.is_ok());
        result
    }
    
    pub fn require_auth(&self, request: &Request) -> Result<(Session, User), String> {
        self.validate_request(request)
    }
    
    pub fn require_role(&self, request: &Request, allowed_roles: Vec<crate::web::users::UserRole>) -> Result<(Session, User), String> {
        let (session, user) = self.require_auth(request)?;
        
        if allowed_roles.contains(&user.role) {
            Ok((session, user))
        } else {
            Err("Insufficient permissions".to_string())
        }
    }
    
    pub fn get_ip_address(&self, request: &Request) -> Option<String> {
        request
            .headers()
            .iter()
            .find(|h| h.field.as_str() == "X-Forwarded-For" || h.field.as_str() == "X-Real-IP")
            .map(|h| h.value.as_str().to_string())
            .or_else(|| Some(request.remote_addr().to_string()))
    }
    
    pub fn get_user_agent(&self, request: &Request) -> Option<String> {
        request
            .headers()
            .iter()
            .find(|h| h.field.as_str() == "User-Agent")
            .map(|h| h.value.as_str().to_string())
    }
}

pub fn create_session_cookie(token: &str) -> Header {
    let cookie_value = format!(
        "session_token={}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax",
        token
    );
    log::debug!("Creating cookie: {}", cookie_value);
    Header::from_bytes(&b"Set-Cookie"[..], cookie_value.as_bytes())
        .expect("Failed to create session cookie header")
}

pub fn clear_session_cookie() -> Header {
    Header::from_bytes(
        &b"Set-Cookie"[..],
        b"session_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict"
    ).expect("Failed to create clear session cookie header")
}