//! Common error handling utilities for DNS operations

/// Log an error and continue execution
#[macro_export]
macro_rules! log_error_continue {
    ($result:expr, $msg:expr) => {
        match $result {
            Ok(val) => val,
            Err(e) => {
                log::error!("{}: {:?}", $msg, e);
                continue;
            }
        }
    };
}

/// Log an error and return from function
#[macro_export]
macro_rules! log_error_return {
    ($result:expr, $msg:expr, $ret:expr) => {
        match $result {
            Ok(val) => val,
            Err(e) => {
                log::error!("{}: {:?}", $msg, e);
                return $ret;
            }
        }
    };
}

/// Handle validation errors with consistent logging
pub fn validate_with_logging<T, E: std::fmt::Debug>(
    result: Result<T, E>,
    context: &str,
) -> Result<T, E> {
    result.map_err(|e| {
        log::warn!("Validation failed in {}: {:?}", context, e);
        e
    })
}

/// Common error response builder for consistent error handling
pub struct ErrorResponseBuilder;

impl ErrorResponseBuilder {
    /// Create a standardized error response
    pub fn build_error_response(
        error_type: &str,
        message: &str,
        details: Option<&str>,
    ) -> String {
        let mut response = format!("Error [{}]: {}", error_type, message);
        if let Some(detail) = details {
            response.push_str(&format!("\nDetails: {}", detail));
        }
        response
    }

    /// Log and format error for client response
    pub fn log_and_format(error: &dyn std::error::Error, context: &str) -> String {
        log::error!("{}: {}", context, error);
        format!("Request failed: {}", error)
    }
}