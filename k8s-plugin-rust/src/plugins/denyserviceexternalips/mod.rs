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

//! DenyServiceExternalIPs admission controller.
//!
//! This admission controller denies any new use of external IPs on Services.
//! Existing external IPs can be kept or removed, but new ones cannot be added.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use crate::api::core::Service;
use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the DenyServiceExternalIPs admission controller.
pub const PLUGIN_NAME: &str = "DenyServiceExternalIPs";

/// Register the DenyServiceExternalIPs plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Plugin denies new external IPs on Services.
pub struct Plugin {
    handler: Handler,
}

impl Plugin {
    /// Create a new DenyServiceExternalIPs admission controller.
    pub fn new() -> Self {
        Self {
            handler: Handler::new_create_update(),
        }
    }
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for Plugin {
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl ValidationInterface for Plugin {
    /// Validate denies new external IPs on Services.
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // Only process services
        let resource = attributes.get_resource();
        if resource.group != "" || resource.resource != "services" {
            return Ok(());
        }

        // Ignore subresources
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        // Get the new service object
        let obj = attributes.get_object();
        let new_svc = match obj {
            Some(o) => match o.as_any().downcast_ref::<Service>() {
                Some(s) => s,
                None => {
                    return Err(AdmissionError::internal_error(
                        "Expected Service resource, got different type",
                    ));
                }
            },
            None => return Ok(()),
        };

        // Get the old service object (if update)
        let old_svc = attributes.get_old_object().and_then(|o| {
            o.as_any().downcast_ref::<Service>()
        });

        // Check if new external IPs are a subset of old ones
        if is_subset(new_svc, old_svc) {
            return Ok(());
        }

        Err(AdmissionError::forbidden(
            &new_svc.name,
            &new_svc.namespace,
            "services",
            crate::admission::errors::FieldError {
                field: "spec.externalIPs".to_string(),
                error_type: crate::admission::errors::FieldErrorType::Invalid,
                value: "Use of external IPs is denied by admission control".to_string(),
                supported_values: vec![],
            },
        ))
    }
}

/// Check if new service's external IPs are a subset of old service's external IPs.
fn is_subset(new_svc: &Service, old_svc: Option<&Service>) -> bool {
    // If new has none, it's a subset
    if new_svc.spec.external_ips.is_empty() {
        return true;
    }

    // If we have some but it's not an update, it's not a subset
    let old_svc = match old_svc {
        Some(s) => s,
        None => return false,
    };

    // Build a set of old IPs
    let old_ips: HashSet<&str> = old_svc.spec.external_ips.iter().map(|s| s.as_str()).collect();

    // Every IP in new must be in old
    for ip in &new_svc.spec.external_ips {
        if !old_ips.contains(ip.as_str()) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    fn make_svc(external_ips: Vec<&str>) -> Service {
        Service::with_external_ips(
            "test-svc",
            "test-ns",
            external_ips.into_iter().map(String::from).collect(),
        )
    }

    #[test]
    fn test_create_without_external_ips() {
        let plugin = Plugin::new();
        let svc = make_svc(vec![]);

        let attrs = AttributesRecord::new(
            "test-svc",
            "test-ns",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Create,
            Some(Box::new(svc)),
            None,
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow create without external IPs");
    }

    #[test]
    fn test_create_with_external_ips() {
        let plugin = Plugin::new();
        let svc = make_svc(vec!["1.1.1.1"]);

        let attrs = AttributesRecord::new(
            "test-svc",
            "test-ns",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Create,
            Some(Box::new(svc)),
            None,
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Should deny create with external IPs");
    }

    #[test]
    fn test_update_same_external_ips() {
        let plugin = Plugin::new();
        let old_svc = make_svc(vec!["1.1.1.1", "2.2.2.2"]);
        let new_svc = make_svc(vec!["1.1.1.1", "2.2.2.2"]);

        let attrs = AttributesRecord::new(
            "test-svc",
            "test-ns",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Update,
            Some(Box::new(new_svc)),
            Some(Box::new(old_svc)),
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow update with same external IPs");
    }

    #[test]
    fn test_update_reorder_external_ips() {
        let plugin = Plugin::new();
        let old_svc = make_svc(vec!["2.2.2.2", "1.1.1.1"]);
        let new_svc = make_svc(vec!["1.1.1.1", "2.2.2.2"]);

        let attrs = AttributesRecord::new(
            "test-svc",
            "test-ns",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Update,
            Some(Box::new(new_svc)),
            Some(Box::new(old_svc)),
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow reordering external IPs");
    }

    #[test]
    fn test_update_add_external_ips() {
        let plugin = Plugin::new();
        let old_svc = make_svc(vec!["1.1.1.1"]);
        let new_svc = make_svc(vec!["1.1.1.1", "2.2.2.2"]);

        let attrs = AttributesRecord::new(
            "test-svc",
            "test-ns",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Update,
            Some(Box::new(new_svc)),
            Some(Box::new(old_svc)),
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Should deny adding external IPs");
    }

    #[test]
    fn test_update_remove_external_ips() {
        let plugin = Plugin::new();
        let old_svc = make_svc(vec!["1.1.1.1", "2.2.2.2"]);
        let new_svc = make_svc(vec!["1.1.1.1"]);

        let attrs = AttributesRecord::new(
            "test-svc",
            "test-ns",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Update,
            Some(Box::new(new_svc)),
            Some(Box::new(old_svc)),
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow removing external IPs");
    }

    #[test]
    fn test_update_erase_all_external_ips() {
        let plugin = Plugin::new();
        let old_svc = make_svc(vec!["1.1.1.1", "2.2.2.2"]);
        let new_svc = make_svc(vec![]);

        let attrs = AttributesRecord::new(
            "test-svc",
            "test-ns",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Update,
            Some(Box::new(new_svc)),
            Some(Box::new(old_svc)),
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow erasing all external IPs");
    }

    #[test]
    fn test_handles() {
        let handler = Plugin::new();

        assert!(handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(!handler.handles(Operation::Delete));
        assert!(!handler.handles(Operation::Connect));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));
    }
}
