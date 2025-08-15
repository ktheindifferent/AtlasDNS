use derive_more::Display;

pub mod authority;
pub mod cache;
pub mod index;
pub mod server;
pub mod sessions;
pub mod users;
pub mod util;
pub mod system_info;

#[derive(Debug, Display)]
pub enum WebError {
    Authority(crate::dns::authority::AuthorityError),
    Io(std::io::Error),
    MissingField(&'static str),
    Serialization(serde_json::Error),
    Template(handlebars::RenderError),
    ZoneNotFound,
    LockError,
    InvalidRequest,
    AuthenticationError(String),
    AuthorizationError(String),
    SessionExpired,
    UserNotFound,
}

impl From<crate::dns::authority::AuthorityError> for WebError {
    fn from(err: crate::dns::authority::AuthorityError) -> Self {
        WebError::Authority(err)
    }
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
