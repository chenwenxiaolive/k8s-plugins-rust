// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! ValidatingAdmissionPolicy admission controller.

use crate::admission::{
    AdmissionResult, Attributes, Handler, Interface, Operation, Plugins, ValidationInterface,
};
use std::io::Read;
use std::sync::Arc;

pub const PLUGIN_NAME: &str = "ValidatingAdmissionPolicy";

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
        Self { handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]) }
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
    fn validate(&self, _attributes: &dyn Attributes) -> AdmissionResult<()> {
        // CEL-based validation policy logic would go here
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handles() {
        let handler = Plugin::new();
        assert!(handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(handler.handles(Operation::Delete));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }
}
