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
        
        // Then try Cookie header (case-insensitive - HeaderField already does case-insensitive comparison)
        let cookie_result = request
            .headers()
            .iter()
            .find(|h| {
                let field_str: &str = h.field.as_str().as_ref();
                field_str.eq_ignore_ascii_case("cookie")
            })
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

pub fn create_session_cookie(token: &str, secure: bool) -> Header {
    let mut cookie_value = format!(
        "session_token={}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict",
        token
    );
    
    if secure {
        cookie_value.push_str("; Secure");
    }
    
    log::debug!("Creating cookie: {}", cookie_value);
    Header::from_bytes(&b"Set-Cookie"[..], cookie_value.as_bytes())
        .unwrap_or_else(|_| {
            log::error!("Failed to create session cookie header");
            // Fallback to a minimal working cookie
            Header::from_bytes(&b"Set-Cookie"[..], b"session_token=error; Path=/")
                .unwrap_or_else(|_| {
                    log::error!("Critical: Unable to create any session cookie");
                    // Create a minimal header as last resort
                    Header::from_bytes(&b"X-Error"[..], b"cookie-failed").unwrap()
                })
        })
}

// Backward compatibility function
pub fn create_session_cookie_legacy(token: &str) -> Header {
    create_session_cookie(token, false)
}

pub fn clear_session_cookie() -> Header {
    Header::from_bytes(
        &b"Set-Cookie"[..],
        b"session_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict"
    ).unwrap_or_else(|_| {
        log::error!("Failed to create clear session cookie header");
        // Fallback to basic clear cookie
        Header::from_bytes(&b"Set-Cookie"[..], b"session_token=; Path=/")
            .unwrap_or_else(|_| {
                log::error!("Critical: Unable to create clear cookie");
                // Last resort header
                Header::from_bytes(&b"Cache-Control"[..], b"no-cache").unwrap()
            })
    })
}