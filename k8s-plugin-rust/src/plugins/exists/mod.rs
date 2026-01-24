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

//! NamespaceExists admission controller.
//!
//! This admission controller rejects all incoming requests in a namespace context
//! if the namespace does not exist. It is useful in deployments that want to
//! enforce pre-declaration of a Namespace resource.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use std::collections::HashSet;
use std::io::Read;
use std::sync::{Arc, RwLock};

/// Plugin name for the NamespaceExists admission controller.
pub const PLUGIN_NAME: &str = "NamespaceExists";

/// Register the NamespaceExists plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Exists::new()) as Arc<dyn Interface>)
    });
}

/// NamespaceLister trait for checking if a namespace exists.
pub trait NamespaceLister: Send + Sync {
    /// Check if a namespace exists.
    fn exists(&self, name: &str) -> bool;

    /// Get a namespace by name. Returns Ok(()) if exists, Err if not found.
    fn get(&self, name: &str) -> Result<(), AdmissionError>;
}

/// In-memory namespace lister for testing purposes.
#[derive(Debug, Default)]
pub struct InMemoryNamespaceLister {
    namespaces: RwLock<HashSet<String>>,
}

impl InMemoryNamespaceLister {
    /// Create a new in-memory namespace lister.
    pub fn new() -> Self {
        Self {
            namespaces: RwLock::new(HashSet::new()),
        }
    }

    /// Create a new in-memory namespace lister with the given namespaces.
    pub fn with_namespaces(namespaces: Vec<&str>) -> Self {
        let lister = Self::new();
        for ns in namespaces {
            lister.add(ns);
        }
        lister
    }

    /// Add a namespace.
    pub fn add(&self, name: &str) {
        self.namespaces
            .write()
            .expect("namespace store lock poisoned")
            .insert(name.to_string());
    }

    /// Remove a namespace.
    pub fn remove(&self, name: &str) {
        self.namespaces
            .write()
            .expect("namespace store lock poisoned")
            .remove(name);
    }
}

impl NamespaceLister for InMemoryNamespaceLister {
    fn exists(&self, name: &str) -> bool {
        self.namespaces
            .read()
            .expect("namespace store lock poisoned")
            .contains(name)
    }

    fn get(&self, name: &str) -> Result<(), AdmissionError> {
        if self.exists(name) {
            Ok(())
        } else {
            Err(AdmissionError::not_found("Namespace", name))
        }
    }
}

/// Exists is an implementation of admission.Interface.
/// It rejects all incoming requests in a namespace context if the namespace does not exist.
/// It is useful in deployments that want to enforce pre-declaration of a Namespace resource.
pub struct Exists {
    handler: Handler,
    namespace_lister: Option<Arc<dyn NamespaceLister>>,
    ready: RwLock<bool>,
}

impl Exists {
    /// Create a new NamespaceExists admission control handler.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]),
            namespace_lister: None,
            ready: RwLock::new(false),
        }
    }

    /// Create a new NamespaceExists admission control handler with a namespace lister.
    pub fn with_lister(lister: Arc<dyn NamespaceLister>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]),
            namespace_lister: Some(lister),
            ready: RwLock::new(true),
        }
    }

    /// Set the namespace lister.
    pub fn set_namespace_lister(&mut self, lister: Arc<dyn NamespaceLister>) {
        self.namespace_lister = Some(lister);
        *self.ready.write().expect("ready state lock poisoned") = true;
    }

    /// Check if the handler is ready.
    pub fn is_ready(&self) -> bool {
        *self.ready.read().expect("ready state lock poisoned")
    }

    /// Set the ready state.
    pub fn set_ready(&self, ready: bool) {
        *self.ready.write().expect("ready state lock poisoned") = ready;
    }
}

impl Default for Exists {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for Exists {
    /// Handles returns true for Create, Update, and Delete operations.
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl ValidationInterface for Exists {
    /// Validate makes an admission decision based on the request attributes.
    /// It rejects requests if the namespace does not exist.
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // if we're here, then we've already passed authentication, so we're allowed to do what we're trying to do
        // if we're here, then the API server has found a route, which means that if we have a non-empty namespace
        // its a namespaced resource.
        let namespace = attributes.get_namespace();
        if namespace.is_empty() {
            return Ok(());
        }

        // Skip validation for Namespace objects themselves
        let kind = attributes.get_kind();
        if kind.group.is_empty() && kind.kind == "Namespace" {
            return Ok(());
        }

        // We need to wait for our caches to warm
        if !self.is_ready() {
            return Err(AdmissionError::forbidden(
                attributes.get_name(),
                &*namespace,
                &attributes.get_resource().resource,
                crate::admission::errors::FieldError {
                    field: String::new(),
                    error_type: crate::admission::errors::FieldErrorType::Invalid,
                    value: "not yet ready to handle request".to_string(),
                    supported_values: vec![],
                },
            ));
        }

        // Check if namespace exists
        let lister = match &self.namespace_lister {
            Some(l) => l,
            None => {
                return Err(AdmissionError::internal_error(
                    "namespace lister not configured",
                ));
            }
        };

        match lister.get(&namespace) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::Pod;

    /// Helper to create a new pod for the specified namespace.
    fn new_pod(namespace: &str) -> Pod {
        let mut pod = Pod::new("123", namespace);
        pod.spec.containers.push(crate::api::core::Container::new("ctr", "image"));
        pod.spec.volumes.push(crate::api::core::Volume::new("vol"));
        pod
    }

    /// TestAdmissionNamespaceExists verifies pod is admitted only if namespace exists.
    #[test]
    fn test_admission_namespace_exists() {
        let namespace = "test";
        let lister = Arc::new(InMemoryNamespaceLister::with_namespaces(vec![namespace]));
        let handler = Exists::with_lister(lister);

        let pod = new_pod(namespace);
        let pod_name = pod.name.clone();
        let attrs = AttributesRecord::new(
            &pod_name,
            namespace,
            GroupVersionResource::new("", "version", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "version", "Pod"),
            false,
        );

        let result = handler.validate(&attrs);
        assert!(
            result.is_ok(),
            "unexpected error returned from admission handler: {:?}",
            result.err()
        );
    }

    /// TestAdmissionNamespaceDoesNotExist verifies pod is not admitted if namespace does not exist.
    #[test]
    fn test_admission_namespace_does_not_exist() {
        let namespace = "test";
        // Create lister with no namespaces
        let lister = Arc::new(InMemoryNamespaceLister::new());
        let handler = Exists::with_lister(lister);

        let pod = new_pod(namespace);
        let pod_name = pod.name.clone();
        let attrs = AttributesRecord::new(
            &pod_name,
            namespace,
            GroupVersionResource::new("", "version", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "version", "Pod"),
            false,
        );

        let result = handler.validate(&attrs);
        assert!(
            result.is_err(),
            "expected error returned from admission handler"
        );
    }

    /// Test that namespace objects themselves are not checked.
    #[test]
    fn test_namespace_objects_allowed() {
        // Create lister with no namespaces
        let lister = Arc::new(InMemoryNamespaceLister::new());
        let handler = Exists::with_lister(lister);

        let ns = crate::api::core::Namespace::new("new-namespace");
        let attrs = AttributesRecord::new(
            "new-namespace",
            "new-namespace",
            GroupVersionResource::new("", "v1", "namespaces"),
            "",
            Operation::Create,
            Some(Box::new(ns)),
            None,
            GroupVersionKind::new("", "v1", "Namespace"),
            false,
        );

        let result = handler.validate(&attrs);
        assert!(
            result.is_ok(),
            "namespace objects should be allowed even if namespace doesn't exist: {:?}",
            result.err()
        );
    }

    /// Test that cluster-scoped resources (empty namespace) are allowed.
    #[test]
    fn test_cluster_scoped_resources_allowed() {
        // Create lister with no namespaces
        let lister = Arc::new(InMemoryNamespaceLister::new());
        let handler = Exists::with_lister(lister);

        let node = crate::api::core::Node::new("my-node");
        let attrs = AttributesRecord::new(
            "my-node",
            "", // empty namespace = cluster-scoped
            GroupVersionResource::new("", "v1", "nodes"),
            "",
            Operation::Create,
            Some(Box::new(node)),
            None,
            GroupVersionKind::new("", "v1", "Node"),
            false,
        );

        let result = handler.validate(&attrs);
        assert!(
            result.is_ok(),
            "cluster-scoped resources should be allowed: {:?}",
            result.err()
        );
    }

    /// Test that handler is not ready by default.
    #[test]
    fn test_not_ready_error() {
        let handler = Exists::new();
        // Handler is not ready because no lister is set

        let pod = new_pod("test");
        let pod_name = pod.name.clone();
        let attrs = AttributesRecord::new(
            &pod_name,
            "test",
            GroupVersionResource::new("", "version", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "version", "Pod"),
            false,
        );

        let result = handler.validate(&attrs);
        assert!(
            result.is_err(),
            "expected error when handler is not ready"
        );
    }

    /// Test which operations are handled.
    #[test]
    fn test_handles() {
        let handler = Exists::new();

        let tests = [
            (Operation::Create, true),
            (Operation::Update, true),
            (Operation::Delete, true),
            (Operation::Connect, false),
        ];

        for (op, expected) in tests {
            let result = handler.handles(op);
            assert_eq!(
                result, expected,
                "Unexpected result for operation {:?}: {}",
                op, result
            );
        }
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
        assert!(!plugin.handles(Operation::Connect));
    }
}
