
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
