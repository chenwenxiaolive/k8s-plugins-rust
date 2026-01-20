// Copyright 2024 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Admission error types.

use std::fmt;
use thiserror::Error;

/// Result type for admission operations.
pub type AdmissionResult<T> = Result<T, AdmissionError>;

/// AdmissionError represents errors that can occur during admission.
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// BadRequest indicates a malformed request.
    #[error("{0}")]
    BadRequest(String),

    /// Forbidden indicates the request is not allowed.
    #[error("{0}")]
    Forbidden(ForbiddenError),

    /// Aggregate represents multiple errors.
    #[error("{0}")]
    Aggregate(AggregateError),

    /// Internal represents an internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// NotFound indicates a resource was not found.
    #[error("{kind} \"{name}\" not found")]
    NotFound { kind: String, name: String },
}

impl AdmissionError {
    /// Create a new BadRequest error.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        AdmissionError::BadRequest(msg.into())
    }

    /// Create a new Forbidden error.
    pub fn forbidden(
        name: impl Into<String>,
        namespace: impl Into<String>,
        resource: impl Into<String>,
        field_error: FieldError,
    ) -> Self {
        AdmissionError::Forbidden(ForbiddenError {
            name: name.into(),
            namespace: namespace.into(),
            resource: resource.into(),
            field_error,
        })
    }

    /// Create an aggregate error from multiple errors.
    pub fn aggregate(errors: Vec<AdmissionError>) -> Self {
        AdmissionError::Aggregate(AggregateError { errors })
    }

    /// Create a NotFound error.
    pub fn not_found(kind: impl Into<String>, name: impl Into<String>) -> Self {
        AdmissionError::NotFound {
            kind: kind.into(),
            name: name.into(),
        }
    }

    /// Create an Internal error.
    pub fn internal_error(msg: impl Into<String>) -> Self {
        AdmissionError::Internal(msg.into())
    }
}

/// ForbiddenError represents a forbidden admission error with field details.
#[derive(Debug)]
pub struct ForbiddenError {
    pub name: String,
    pub namespace: String,
    pub resource: String,
    pub field_error: FieldError,
}

impl fmt::Display for ForbiddenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} \"{}\" is forbidden: {}",
            self.resource, self.name, self.field_error
        )
    }
}

/// FieldError represents a field-level error.
#[derive(Debug)]
pub struct FieldError {
    pub field: String,
    pub error_type: FieldErrorType,
    pub value: String,
    pub supported_values: Vec<String>,
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error_type {
            FieldErrorType::NotSupported => {
                write!(
                    f,
                    "{}: Unsupported value: \"{}\": supported values: {}",
                    self.field,
                    self.value,
                    self.supported_values
                        .iter()
                        .map(|s| format!("\"{}\"", s))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            FieldErrorType::Required => {
                write!(f, "{}: Required value", self.field)
            }
            FieldErrorType::Invalid => {
                write!(f, "{}: Invalid value: \"{}\"", self.field, self.value)
            }
        }
    }
}

/// FieldErrorType represents the type of field error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldErrorType {
    /// NotSupported indicates the value is not in the list of supported values.
    NotSupported,
    /// Required indicates a required field is missing.
    Required,
    /// Invalid indicates an invalid value.
    Invalid,
}

/// AggregateError represents multiple errors.
#[derive(Debug)]
pub struct AggregateError {
    pub errors: Vec<AdmissionError>,
}

impl fmt::Display for AggregateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_strings: Vec<String> = self.errors.iter().map(|e| e.to_string()).collect();
        write!(f, "[{}]", error_strings.join(", "))
    }
}

/// Helper function to create a "not supported" field error.
pub fn field_not_supported(field: &str, value: &str, supported: Vec<&str>) -> FieldError {
    FieldError {
        field: field.to_string(),
        error_type: FieldErrorType::NotSupported,
        value: value.to_string(),
        supported_values: supported.into_iter().map(String::from).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forbidden_error_display() {
        let err = AdmissionError::forbidden(
            "test-pod",
            "default",
            "pods",
            field_not_supported(
                "spec.containers[0].imagePullPolicy",
                "Never",
                vec!["Always"],
            ),
        );
        let msg = err.to_string();
        assert!(msg.contains("pods \"test-pod\" is forbidden"));
        assert!(msg.contains("imagePullPolicy"));
        assert!(msg.contains("Unsupported value: \"Never\""));
        assert!(msg.contains("\"Always\""));
    }

    #[test]
    fn test_aggregate_error_display() {
        let errors = vec![
            AdmissionError::bad_request("error 1"),
            AdmissionError::bad_request("error 2"),
        ];
        let err = AdmissionError::aggregate(errors);
        let msg = err.to_string();
        assert!(msg.starts_with('['));
        assert!(msg.ends_with(']'));
        assert!(msg.contains("error 1"));
        assert!(msg.contains("error 2"));
    }
}
