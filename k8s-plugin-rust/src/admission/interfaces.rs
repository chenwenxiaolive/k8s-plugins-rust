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

//! Core admission controller interfaces.

use super::attributes::Attributes;
use super::errors::AdmissionResult;
use std::fmt;

/// Operation is the type of resource operation being checked for admission control.
/// This corresponds to k8s.io/apiserver/pkg/admission.Operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Create indicates a resource creation operation.
    Create,
    /// Update indicates a resource update operation.
    Update,
    /// Delete indicates a resource deletion operation.
    Delete,
    /// Connect indicates a resource connect operation (e.g., pod exec).
    Connect,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Create => write!(f, "CREATE"),
            Operation::Update => write!(f, "UPDATE"),
            Operation::Delete => write!(f, "DELETE"),
            Operation::Connect => write!(f, "CONNECT"),
        }
    }
}

impl Operation {
    /// Parse an operation from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "CREATE" => Some(Operation::Create),
            "UPDATE" => Some(Operation::Update),
            "DELETE" => Some(Operation::Delete),
            "CONNECT" => Some(Operation::Connect),
            _ => None,
        }
    }
}

/// Interface is an abstract, pluggable interface for Admission Control decisions.
/// This corresponds to k8s.io/apiserver/pkg/admission.Interface
pub trait Interface: Send + Sync {
    /// Returns true if this admission controller can handle the given operation.
    fn handles(&self, operation: Operation) -> bool;
}

/// MutationInterface is an interface for admission plugins that can modify objects.
/// This corresponds to k8s.io/apiserver/pkg/admission.MutationInterface
pub trait MutationInterface: Interface {
    /// Admit makes an admission decision based on the request attributes.
    /// It may modify the object in the attributes.
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()>;
}

/// ValidationInterface is an interface for admission plugins that validate objects.
/// This corresponds to k8s.io/apiserver/pkg/admission.ValidationInterface
pub trait ValidationInterface: Interface {
    /// Validate makes an admission decision based on the request attributes.
    /// It is NOT allowed to modify the object.
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_display() {
        assert_eq!(format!("{}", Operation::Create), "CREATE");
        assert_eq!(format!("{}", Operation::Update), "UPDATE");
        assert_eq!(format!("{}", Operation::Delete), "DELETE");
        assert_eq!(format!("{}", Operation::Connect), "CONNECT");
    }

    #[test]
    fn test_operation_from_str() {
        assert_eq!(Operation::from_str("CREATE"), Some(Operation::Create));
        assert_eq!(Operation::from_str("create"), Some(Operation::Create));
        assert_eq!(Operation::from_str("UPDATE"), Some(Operation::Update));
        assert_eq!(Operation::from_str("DELETE"), Some(Operation::Delete));
        assert_eq!(Operation::from_str("CONNECT"), Some(Operation::Connect));
        assert_eq!(Operation::from_str("UNKNOWN"), None);
    }
}
