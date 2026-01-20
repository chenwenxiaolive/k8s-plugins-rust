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

//! Plugin registry for admission controllers.

use super::errors::AdmissionResult;
use super::interfaces::Interface;
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

/// Factory is a function that creates an admission plugin instance.
pub type Factory = fn(config: Option<&mut dyn Read>) -> AdmissionResult<Arc<dyn Interface>>;

/// PluginInitializer is used to initialize plugins after they are created.
pub trait PluginInitializer: Send + Sync {
    /// Initialize is called to initialize the plugin.
    fn initialize(&self, plugin: &dyn Interface);
}

/// Plugins is a registry of admission plugins.
#[derive(Default)]
pub struct Plugins {
    registry: RwLock<HashMap<String, Factory>>,
}

impl Plugins {
    /// Create a new empty plugin registry.
    pub fn new() -> Self {
        Self {
            registry: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new admission plugin with the given name and factory.
    pub fn register(&self, name: &str, factory: Factory) {
        let mut registry = self.registry.write().unwrap();
        registry.insert(name.to_string(), factory);
    }

    /// Get a factory for the given plugin name.
    pub fn get_factory(&self, name: &str) -> Option<Factory> {
        let registry = self.registry.read().unwrap();
        registry.get(name).copied()
    }

    /// Get all registered plugin names.
    pub fn registered_names(&self) -> Vec<String> {
        let registry = self.registry.read().unwrap();
        registry.keys().cloned().collect()
    }

    /// Check if a plugin is registered.
    pub fn is_registered(&self, name: &str) -> bool {
        let registry = self.registry.read().unwrap();
        registry.contains_key(name)
    }

    /// Create a new instance of the named plugin.
    pub fn new_from_plugins(
        &self,
        name: &str,
        config: Option<&mut dyn Read>,
    ) -> AdmissionResult<Arc<dyn Interface>> {
        let factory = self
            .get_factory(name)
            .ok_or_else(|| super::errors::AdmissionError::Internal(format!("unknown admission plugin: {}", name)))?;
        factory(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{Handler, Operation};

    struct TestPlugin {
        handler: Handler,
    }

    impl Interface for TestPlugin {
        fn handles(&self, operation: Operation) -> bool {
            self.handler.handles(operation)
        }
    }

    fn test_factory(_config: Option<&mut dyn Read>) -> AdmissionResult<Arc<dyn Interface>> {
        Ok(Arc::new(TestPlugin {
            handler: Handler::new_create_update(),
        }))
    }

    #[test]
    fn test_plugins_register() {
        let plugins = Plugins::new();
        plugins.register("TestPlugin", test_factory);

        assert!(plugins.is_registered("TestPlugin"));
        assert!(!plugins.is_registered("Unknown"));

        let names = plugins.registered_names();
        assert!(names.contains(&"TestPlugin".to_string()));
    }

    #[test]
    fn test_plugins_new_from_plugins() {
        let plugins = Plugins::new();
        plugins.register("TestPlugin", test_factory);

        let plugin = plugins.new_from_plugins("TestPlugin", None).unwrap();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
    }

    #[test]
    fn test_plugins_unknown_plugin() {
        let plugins = Plugins::new();
        let result = plugins.new_from_plugins("Unknown", None);
        assert!(result.is_err());
    }
}
