
pub mod activity;
pub mod authority;
pub mod cache;
pub mod index;
pub mod server;
pub mod sessions;
pub mod users;
pub mod util;
pub mod system_info;
pub mod graphql;
pub mod api_v2;
pub mod bulk_operations;
pub mod webhooks;
pub mod validation;

#[derive(Debug)]
pub enum WebError {
    Authority(crate::dns::authority::AuthorityError),
    Io(std::io::Error),
    MissingField(&'static str),
    Serialization(serde_json::Error),
    Template(handlebars::RenderError),
    ZoneNotFound,
    LockError,
    InvalidRequest,
    InvalidInput(String),
    AuthenticationError(String),
    AuthorizationError(String),
    SessionExpired,
    UserNotFound,
    InternalError(String),
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebError::Authority(e) => write!(f, "Authority error: {}", e),
            WebError::Io(e) => write!(f, "IO error: {}", e),
            WebError::MissingField(field) => write!(f, "Missing required field: {}", field),
            WebError::Serialization(e) => write!(f, "Serialization error: {}", e),
            WebError::Template(e) => write!(f, "Template error: {}", e),
            WebError::ZoneNotFound => write!(f, "Zone not found"),
            WebError::LockError => write!(f, "Lock error"),
            WebError::InvalidRequest => write!(f, "Invalid request"),
            WebError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            WebError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            WebError::AuthorizationError(msg) => write!(f, "Authorization error: {}", msg),
            WebError::SessionExpired => write!(f, "Session expired"),
            WebError::UserNotFound => write!(f, "User not found"),
            WebError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl WebError {
    /// Report this error to Sentry with appropriate context and severity
    pub fn report_to_sentry(&self) {
        let level = match self {
            WebError::Authority(_) | WebError::Io(_) | WebError::Serialization(_) 
            | WebError::Template(_) | WebError::LockError | WebError::InternalError(_) => sentry::Level::Error,
            WebError::AuthenticationError(_) | WebError::AuthorizationError(_) 
            | WebError::InvalidRequest | WebError::InvalidInput(_) => sentry::Level::Warning,
            WebError::MissingField(_) | WebError::ZoneNotFound | WebError::SessionExpired 
            | WebError::UserNotFound => sentry::Level::Info,
        };
        
        sentry::configure_scope(|scope| {
            scope.set_tag("error_type", match self {
                WebError::Authority(_) => "authority_error",
                WebError::Io(_) => "io_error",
                WebError::MissingField(_) => "missing_field",
                WebError::Serialization(_) => "serialization_error",
                WebError::Template(_) => "template_error",
                WebError::ZoneNotFound => "zone_not_found",
                WebError::LockError => "lock_error",
                WebError::InvalidRequest => "invalid_request",
                WebError::InvalidInput(_) => "invalid_input",
                WebError::AuthenticationError(_) => "authentication_error",
                WebError::AuthorizationError(_) => "authorization_error",
                WebError::SessionExpired => "session_expired",
                WebError::UserNotFound => "user_not_found",
                WebError::InternalError(_) => "internal_error",
            });
            
            scope.set_tag("component", "web");
            
            // Add specific context based on error type
            match self {
                WebError::MissingField(field) => {
                    scope.set_extra("field", (*field).into());
                }
                WebError::InvalidInput(msg) | WebError::AuthenticationError(msg) 
                | WebError::AuthorizationError(msg) | WebError::InternalError(msg) => {
                    scope.set_extra("message", msg.clone().into());
                }
                WebError::Authority(err) => {
                    scope.set_extra("authority_error", format!("{:?}", err).into());
                }
                WebError::Io(err) => {
                    scope.set_extra("io_error", err.to_string().into());
                    scope.set_extra("io_kind", format!("{:?}", err.kind()).into());
                }
                WebError::Serialization(err) => {
                    scope.set_extra("serde_error", err.to_string().into());
                }
                WebError::Template(err) => {
                    scope.set_extra("template_error", err.to_string().into());
                }
                _ => {}
            }
        });
        
        sentry::capture_message(&self.to_string(), level);
    }
}

impl From<crate::dns::authority::AuthorityError> for WebError {
    fn from(err: crate::dns::authority::AuthorityError) -> Self {
        WebError::Authority(err)
    }
}

/// Helper function to create JSON response
pub fn handle_json_response<T: serde::Serialize>(
    data: &T,
    status: tiny_http::StatusCode,
) -> Result<tiny_http::Response<std::io::Cursor<Vec<u8>>>> {
    let json = serde_json::to_string(data)
        .map_err(WebError::Serialization)?;
    
    let response = tiny_http::Response::from_string(json)
        .with_status_code(status)
        .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .unwrap());
    
    Ok(response)
}

impl From<std::io::Error> for WebError {
    fn from(err: std::io::Error) -> Self {
        WebError::Io(err)
    }
}

impl From<serde_json::Error> for WebError {
    fn from(err: serde_json::Error) -> Self {
        WebError::Serialization(err)
    }
}

impl From<handlebars::RenderError> for WebError {
    fn from(err: handlebars::RenderError) -> Self {
        WebError::Template(err)
    }
}

impl std::error::Error for WebError {}

pub type Result<T> = std::result::Result<T, WebError>;

#[cfg(test)]
mod users_test;
