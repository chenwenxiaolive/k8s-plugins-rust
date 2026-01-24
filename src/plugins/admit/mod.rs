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

//! AlwaysAdmit admission controller.
//!
//! DEPRECATED: This admission controller always admits all requests.
//! It has no real use and should be removed from configuration.

use crate::admission::{
    AdmissionResult, Attributes, Interface, MutationInterface, Operation, Plugins,
    ValidationInterface,
};
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the AlwaysAdmit admission controller.
pub const PLUGIN_NAME: &str = "AlwaysAdmit";

/// Register the AlwaysAdmit plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(AlwaysAdmit::new()) as Arc<dyn Interface>)
    });
}

/// AlwaysAdmit is an implementation of admission.Interface which always says yes to an admit request.
/// DEPRECATED: This plugin is deprecated and should not be used.
pub struct AlwaysAdmit;

impl AlwaysAdmit {
    /// Create a new AlwaysAdmit admission controller.
    /// Note: This plugin is deprecated.
    pub fn new() -> Self {
        // DEPRECATED: AlwaysAdmit admits all admission requests, it is no use.
        eprintln!(
            "WARNING: {} admission controller is deprecated. \
            Please remove this controller from your configuration files and scripts.",
            PLUGIN_NAME
        );
        Self
    }
}

impl Default for AlwaysAdmit {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for AlwaysAdmit {
    /// AlwaysAdmit handles all operations.
    fn handles(&self, _operation: Operation) -> bool {
        true
    }
}

impl MutationInterface for AlwaysAdmit {
    /// Admit always returns Ok - it admits everything.
    fn admit(&self, _attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        Ok(())
    }
}

impl ValidationInterface for AlwaysAdmit {
    /// Validate always returns Ok - it validates everything.
    fn validate(&self, _attributes: &dyn Attributes) -> AdmissionResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    /// TestAdmissionNonNilAttribute verifies that admit works with valid attributes
    #[test]
    fn test_admission_non_nil_attribute() {
        let handler = AlwaysAdmit::new();
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
        assert!(result.is_ok(), "Unexpected error returned from admission handler");
    }

    /// TestHandles verifies that AlwaysAdmit handles all operations
    #[test]
    fn test_handles() {
        let handler = AlwaysAdmit::new();
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
    fn test_validate() {
        let handler = AlwaysAdmit::new();
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
        assert!(result.is_ok(), "Unexpected error returned from validation");
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
