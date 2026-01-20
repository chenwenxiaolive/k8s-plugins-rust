// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! ImagePolicyWebhook admission controller.

use crate::admission::{
    AdmissionResult, Attributes, Handler, Interface, Operation, Plugins, ValidationInterface,
};
use std::io::Read;
use std::sync::Arc;

pub const PLUGIN_NAME: &str = "ImagePolicyWebhook";

pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

pub struct Plugin {
    handler: Handler,
}

impl Plugin {
    pub fn new() -> Self {
        Self { handler: Handler::new(&[Operation::Create, Operation::Update]) }
    }
}

impl Default for Plugin {
    fn default() -> Self { Self::new() }
}

impl Interface for Plugin {
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl ValidationInterface for Plugin {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        let resource = attributes.get_resource();
        if resource.resource != "pods" {
            return Ok(());
        }
        // Image policy webhook logic would go here
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_ignores_non_pod_resources() {
        let plugin = Plugin::new();
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Create,
            None,
            None,
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validates_pod_resources() {
        let plugin = Plugin::new();
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            None,
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handles_update_operation() {
        let plugin = Plugin::new();
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Update,
            None,
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ignores_configmaps() {
        let plugin = Plugin::new();
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "configmaps"),
            "",
            Operation::Create,
            None,
            None,
            GroupVersionKind::new("", "v1", "ConfigMap"),
            false,
        );
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ignores_secrets() {
        let plugin = Plugin::new();
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "secrets"),
            "",
            Operation::Create,
            None,
            None,
            GroupVersionKind::new("", "v1", "Secret"),
            false,
        );
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_trait() {
        let plugin = Plugin::default();
        assert!(plugin.handles(Operation::Create));
    }
}
