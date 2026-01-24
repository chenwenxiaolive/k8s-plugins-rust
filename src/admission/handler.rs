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

//! Base admission handler implementation.

use super::interfaces::{Interface, Operation};
use std::collections::HashSet;

/// Handler is a base struct for admission plugins.
/// It provides default implementation of the Handles method.
#[derive(Debug, Clone)]
pub struct Handler {
    operations: HashSet<Operation>,
}

impl Handler {
    /// Create a new Handler that handles the given operations.
    pub fn new(operations: &[Operation]) -> Self {
        Self {
            operations: operations.iter().cloned().collect(),
        }
    }

    /// Create a new Handler that handles Create and Update operations.
    /// This is the most common configuration for admission plugins.
    pub fn new_create_update() -> Self {
        Self::new(&[Operation::Create, Operation::Update])
    }

    /// Create a new Handler that handles all operations.
    pub fn new_all() -> Self {
        Self::new(&[
            Operation::Create,
            Operation::Update,
            Operation::Delete,
            Operation::Connect,
        ])
    }
}

impl Interface for Handler {
    fn handles(&self, operation: Operation) -> bool {
        self.operations.contains(&operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_new() {
        let handler = Handler::new(&[Operation::Create, Operation::Update]);
        assert!(handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(!handler.handles(Operation::Delete));
        assert!(!handler.handles(Operation::Connect));
    }

    #[test]
    fn test_handler_new_create_update() {
        let handler = Handler::new_create_update();
        assert!(handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(!handler.handles(Operation::Delete));
        assert!(!handler.handles(Operation::Connect));
    }

    #[test]
    fn test_handler_new_all() {
        let handler = Handler::new_all();
        assert!(handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(handler.handles(Operation::Delete));
        assert!(handler.handles(Operation::Connect));
    }
}
