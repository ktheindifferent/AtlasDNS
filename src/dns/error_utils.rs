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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug)]
    struct TestError {
        message: String,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl std::error::Error for TestError {}

    #[test]
    fn test_validate_with_logging_success() {
        let result: Result<i32, TestError> = Ok(42);
        let validated = validate_with_logging(result, "test_context");
        assert!(validated.is_ok());
        assert_eq!(validated.unwrap(), 42);
    }

    #[test]
    fn test_validate_with_logging_error() {
        let error = TestError {
            message: "Test error message".to_string(),
        };
        let result: Result<i32, TestError> = Err(error);
        let validated = validate_with_logging(result, "test_context");
        assert!(validated.is_err());
    }

    #[test]
    fn test_build_error_response_basic() {
        let response = ErrorResponseBuilder::build_error_response(
            "VALIDATION",
            "Invalid input",
            None,
        );
        assert!(response.contains("Error [VALIDATION]"));
        assert!(response.contains("Invalid input"));
        assert!(!response.contains("Details:"));
    }

    #[test]
    fn test_build_error_response_with_details() {
        let response = ErrorResponseBuilder::build_error_response(
            "NETWORK",
            "Connection failed",
            Some("Timeout after 30 seconds"),
        );
        assert!(response.contains("Error [NETWORK]"));
        assert!(response.contains("Connection failed"));
        assert!(response.contains("Details: Timeout after 30 seconds"));
    }

    #[test]
    fn test_log_and_format() {
        let error = TestError {
            message: "Test error for logging".to_string(),
        };
        let formatted = ErrorResponseBuilder::log_and_format(&error, "test_operation");
        assert!(formatted.contains("Request failed:"));
        assert!(formatted.contains("Test error for logging"));
    }

    #[test]
    fn test_log_error_continue_macro() {
        let mut iterations = 0;
        let results = vec![
            Err::<i32, &str>("error1"),
            Ok(42),
            Err::<i32, &str>("error2"),
            Ok(100),
        ];

        for result in results {
            iterations += 1;
            let _value = log_error_continue!(result, "Processing item");
        }
        
        // Should have processed all items despite errors
        assert_eq!(iterations, 4);
    }

    #[test]
    fn test_log_error_return_macro() {
        fn test_function(should_fail: bool) -> Option<i32> {
            let result = if should_fail {
                Err::<i32, &str>("test error")
            } else {
                Ok(42)
            };
            
            let value = log_error_return!(result, "Test operation failed", None);
            Some(value)
        }

        assert_eq!(test_function(false), Some(42));
        assert_eq!(test_function(true), None);
    }

    #[test]
    fn test_error_response_builder_different_types() {
        // Test with different error types
        let responses = vec![
            ErrorResponseBuilder::build_error_response("AUTH", "Unauthorized", None),
            ErrorResponseBuilder::build_error_response("DB", "Connection lost", Some("Check database status")),
            ErrorResponseBuilder::build_error_response("PARSE", "Invalid JSON", Some("Line 5, column 12")),
        ];

        assert!(responses[0].contains("[AUTH]"));
        assert!(responses[1].contains("[DB]"));
        assert!(responses[1].contains("Check database status"));
        assert!(responses[2].contains("[PARSE]"));
        assert!(responses[2].contains("Line 5, column 12"));
    }

    #[test]
    fn test_validate_with_different_error_types() {
        // Test with string error
        let result1: Result<&str, String> = Err("String error".to_string());
        let validated1 = validate_with_logging(result1, "string_context");
        assert!(validated1.is_err());

        // Test with custom error
        let result2: Result<bool, TestError> = Err(TestError {
            message: "Custom error".to_string(),
        });
        let validated2 = validate_with_logging(result2, "custom_context");
        assert!(validated2.is_err());

        // Test successful validation
        let result3: Result<Vec<i32>, &str> = Ok(vec![1, 2, 3]);
        let validated3 = validate_with_logging(result3, "vec_context");
        assert!(validated3.is_ok());
        assert_eq!(validated3.unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_error_response_builder_edge_cases() {
        // Empty strings
        let response1 = ErrorResponseBuilder::build_error_response("", "", None);
        assert_eq!(response1, "Error []: ");

        // Very long messages
        let long_msg = "a".repeat(1000);
        let response2 = ErrorResponseBuilder::build_error_response("LONG", &long_msg, Some(&long_msg));
        assert!(response2.len() > 2000);

        // Special characters
        let response3 = ErrorResponseBuilder::build_error_response(
            "SPECIAL",
            "Error with \n newline and \t tab",
            Some("Details with 'quotes' and \"double quotes\""),
        );
        assert!(response3.contains("\n"));
        assert!(response3.contains("\t"));
        assert!(response3.contains("'quotes'"));
    }
}