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

//! AlwaysDeny admission controller.
//!
//! DEPRECATED: This admission controller always denies all requests.
//! It has no real use and should be removed from configuration.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Interface, MutationInterface, Operation, Plugins,
    ValidationInterface,
};
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the AlwaysDeny admission controller.
pub const PLUGIN_NAME: &str = "AlwaysDeny";

/// Register the AlwaysDeny plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(AlwaysDeny::new()) as Arc<dyn Interface>)
    });
}

/// AlwaysDeny is an implementation of admission.Interface which always says no to an admit request.
/// DEPRECATED: This plugin is deprecated and should not be used.
pub struct AlwaysDeny;

impl AlwaysDeny {
    /// Create a new AlwaysDeny admission controller.
    /// Note: This plugin is deprecated.
    pub fn new() -> Self {
        // DEPRECATED: AlwaysDeny denies all admission requests, it is no use.
        eprintln!(
            "WARNING: {} admission controller is deprecated. \
            Please remove this controller from your configuration files and scripts.",
            PLUGIN_NAME
        );
        Self
    }

    /// Create a forbidden error for denying all modifications.
    fn deny_error(&self, attributes: &dyn Attributes) -> AdmissionError {
        AdmissionError::forbidden(
            attributes.get_name(),
            attributes.get_namespace(),
            "all",
            crate::admission::errors::FieldError {
                field: String::new(),
                error_type: crate::admission::errors::FieldErrorType::Invalid,
                value: String::new(),
                supported_values: vec![],
            },
        )
    }
}

impl Default for AlwaysDeny {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for AlwaysDeny {
    /// AlwaysDeny handles all operations.
    fn handles(&self, _operation: Operation) -> bool {
        true
    }
}

impl MutationInterface for AlwaysDeny {
    /// Admit always returns an error - it denies everything.
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        Err(self.deny_error(attributes))
    }
}

impl ValidationInterface for AlwaysDeny {
    /// Validate always returns an error - it denies everything.
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        Err(self.deny_error(attributes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    /// TestAdmission verifies that AlwaysDeny returns an error
    #[test]
    fn test_admission() {
        let handler = AlwaysDeny::new();
        let mut attrs = AttributesRecord::new(
            "name",
            "namespace",
            GroupVersionResource::new("", "version", "resource"),
            "subresource",
            Operation::Create,
            None,
            None,
            GroupVersionKind::new("", "version", "kind"),
            false,
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_err(), "Expected error returned from admission handler");
    }

    /// TestHandles verifies that AlwaysDeny handles all operations
    #[test]
    fn test_handles() {
        let handler = AlwaysDeny::new();
        let operations = [
            Operation::Create,
            Operation::Connect,
            Operation::Update,
            Operation::Delete,
        ];

        for op in operations {
            assert!(
                handler.handles(op),
                "Expected handling all operations, including: {:?}",
                op
            );
        }
    }

    #[test]
    fn test_validate_denies() {
        let handler = AlwaysDeny::new();
        let attrs = AttributesRecord::new(
            "name",
            "namespace",
            GroupVersionResource::new("", "version", "resource"),
            "",
            Operation::Create,
            None,
            None,
            GroupVersionKind::new("", "version", "kind"),
            false,
        );

        let result = handler.validate(&attrs);
        assert!(result.is_err(), "Expected error returned from validation");
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));

        let plugin = plugins.new_from_plugins(PLUGIN_NAME, None).unwrap();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(plugin.handles(Operation::Delete));
        assert!(plugin.handles(Operation::Connect));
    }
}
