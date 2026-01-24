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

//! NamespaceLifecycle admission controller.
//!
//! This admission controller enforces life-cycle constraints around a Namespace
//! depending on its Phase. It prevents deletion of immortal namespaces and
//! prevents creation of resources in terminating namespaces.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins,
};
use std::collections::HashSet;
use std::io::Read;
use std::sync::{Arc, RwLock};

/// Plugin name for the NamespaceLifecycle admission controller.
pub const PLUGIN_NAME: &str = "NamespaceLifecycle";

/// Default namespace name.
pub const NAMESPACE_DEFAULT: &str = "default";
/// System namespace name.
pub const NAMESPACE_SYSTEM: &str = "kube-system";
/// Public namespace name.
pub const NAMESPACE_PUBLIC: &str = "kube-public";

/// Register the NamespaceLifecycle plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        let immortal = vec![NAMESPACE_DEFAULT, NAMESPACE_SYSTEM, NAMESPACE_PUBLIC];
        Ok(Arc::new(Lifecycle::new(immortal)) as Arc<dyn Interface>)
    });
}

/// NamespacePhase represents the phase of a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespacePhase {
    Active,
    Terminating,
}

/// NamespaceLister trait for checking namespace state.
pub trait NamespaceLister: Send + Sync {
    /// Get a namespace's phase. Returns None if not found.
    fn get_phase(&self, name: &str) -> Option<NamespacePhase>;
}

/// In-memory namespace store for testing.
#[derive(Debug, Default)]
pub struct InMemoryNamespaceStore {
    namespaces: RwLock<std::collections::HashMap<String, NamespacePhase>>,
}

impl InMemoryNamespaceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, name: &str, phase: NamespacePhase) {
        self.namespaces
            .write()
            .expect("namespace store lock poisoned")
            .insert(name.to_string(), phase);
    }

    pub fn set_terminating(&self, name: &str) {
        if let Some(phase) = self
            .namespaces
            .write()
            .expect("namespace store lock poisoned")
            .get_mut(name)
        {
            *phase = NamespacePhase::Terminating;
        }
    }
}

impl NamespaceLister for InMemoryNamespaceStore {
    fn get_phase(&self, name: &str) -> Option<NamespacePhase> {
        self.namespaces
            .read()
            .expect("namespace store lock poisoned")
            .get(name)
            .copied()
    }
}

/// Lifecycle admission controller enforces namespace lifecycle constraints.
pub struct Lifecycle {
    handler: Handler,
    immortal_namespaces: HashSet<String>,
    namespace_lister: Option<Arc<dyn NamespaceLister>>,
    ready: RwLock<bool>,
}

impl Lifecycle {
    /// Create a new NamespaceLifecycle admission controller.
    pub fn new(immortal_namespaces: Vec<&str>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]),
            immortal_namespaces: immortal_namespaces.into_iter().map(String::from).collect(),
            namespace_lister: None,
            ready: RwLock::new(false),
        }
    }

    /// Create with a namespace lister.
    pub fn with_lister(immortal_namespaces: Vec<&str>, lister: Arc<dyn NamespaceLister>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]),
            immortal_namespaces: immortal_namespaces.into_iter().map(String::from).collect(),
            namespace_lister: Some(lister),
            ready: RwLock::new(true),
        }
    }

    pub fn is_ready(&self) -> bool {
        *self.ready.read().expect("ready state lock poisoned")
    }

    /// Check if a resource is an access review (always allowed).
    fn is_access_review(&self, attributes: &dyn Attributes) -> bool {
        let resource = attributes.get_resource();
        resource.group == "authorization.k8s.io" && resource.resource == "localsubjectaccessreviews"
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new(vec![NAMESPACE_DEFAULT, NAMESPACE_SYSTEM, NAMESPACE_PUBLIC])
    }
}

impl Interface for Lifecycle {
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl MutationInterface for Lifecycle {
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        let operation = attributes.get_operation();
        let kind = attributes.get_kind();
        let namespace = attributes.get_namespace();
        let name = attributes.get_name();

        // Prevent deletion of immortal namespaces
        if operation == Operation::Delete
            && kind.group.is_empty()
            && kind.kind == "Namespace"
            && self.immortal_namespaces.contains(name)
        {
            return Err(AdmissionError::forbidden(
                name,
                "",
                "namespaces",
                crate::admission::errors::FieldError {
                    field: String::new(),
                    error_type: crate::admission::errors::FieldErrorType::Invalid,
                    value: "this namespace may not be deleted".to_string(),
                    supported_values: vec![],
                },
            ));
        }

        // Always allow non-namespaced resources (except Namespace itself)
        if namespace.is_empty() && !(kind.group.is_empty() && kind.kind == "Namespace") {
            return Ok(());
        }

        // Allow all operations on Namespace objects
        if kind.group.is_empty() && kind.kind == "Namespace" {
            return Ok(());
        }

        // Always allow deletion of other resources
        if operation == Operation::Delete {
            return Ok(());
        }

        // Always allow access review checks
        if self.is_access_review(attributes) {
            return Ok(());
        }

        // Check if ready
        if !self.is_ready() {
            return Err(AdmissionError::forbidden(
                name,
                namespace,
                &attributes.get_resource().resource,
                crate::admission::errors::FieldError {
                    field: String::new(),
                    error_type: crate::admission::errors::FieldErrorType::Invalid,
                    value: "not yet ready to handle request".to_string(),
                    supported_values: vec![],
                },
            ));
        }

        // Check namespace state
        let lister = match &self.namespace_lister {
            Some(l) => l,
            None => return Err(AdmissionError::internal_error("namespace lister not configured")),
        };

        let phase = lister.get_phase(namespace);

        // Refuse to operate on non-existent namespaces
        let phase = match phase {
            Some(p) => p,
            None => {
                return Err(AdmissionError::not_found("Namespace", namespace));
            }
        };

        // Prevent creation in terminating namespaces
        if operation == Operation::Create && phase == NamespacePhase::Terminating {
            return Err(AdmissionError::forbidden(
                name,
                namespace,
                &attributes.get_resource().resource,
                crate::admission::errors::FieldError {
                    field: "metadata.namespace".to_string(),
                    error_type: crate::admission::errors::FieldErrorType::Invalid,
                    value: format!(
                        "unable to create new content in namespace {} because it is being terminated",
                        namespace
                    ),
                    supported_values: vec![],
                },
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::Pod;

    fn new_store_with_namespace(name: &str, phase: NamespacePhase) -> Arc<InMemoryNamespaceStore> {
        let store = Arc::new(InMemoryNamespaceStore::new());
        store.add(name, phase);
        store
    }

    #[test]
    fn test_prevent_delete_immortal_namespace() {
        let handler = Lifecycle::default();
        *handler.ready.write().unwrap() = true;

        let ns = crate::api::core::Namespace::new(NAMESPACE_DEFAULT);
        let mut attrs = AttributesRecord::new(
            NAMESPACE_DEFAULT,
            "",
            GroupVersionResource::new("", "v1", "namespaces"),
            "",
            Operation::Delete,
            Some(Box::new(ns)),
            None,
            GroupVersionKind::new("", "v1", "Namespace"),
            false,
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_err(), "Should prevent deletion of default namespace");
    }

    #[test]
    fn test_allow_delete_regular_namespace() {
        let store = new_store_with_namespace("test-ns", NamespacePhase::Active);
        let handler = Lifecycle::with_lister(
            vec![NAMESPACE_DEFAULT, NAMESPACE_SYSTEM, NAMESPACE_PUBLIC],
            store,
        );

        let ns = crate::api::core::Namespace::new("test-ns");
        let mut attrs = AttributesRecord::new(
            "test-ns",
            "",
            GroupVersionResource::new("", "v1", "namespaces"),
            "",
            Operation::Delete,
            Some(Box::new(ns)),
            None,
            GroupVersionKind::new("", "v1", "Namespace"),
            false,
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_ok(), "Should allow deletion of regular namespace");
    }

    #[test]
    fn test_allow_create_in_active_namespace() {
        let store = new_store_with_namespace("test-ns", NamespacePhase::Active);
        let handler = Lifecycle::with_lister(
            vec![NAMESPACE_DEFAULT, NAMESPACE_SYSTEM, NAMESPACE_PUBLIC],
            store,
        );

        let pod = Pod::new("test-pod", "test-ns");
        let mut attrs = AttributesRecord::new(
            "test-pod",
            "test-ns",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_ok(), "Should allow create in active namespace");
    }

    #[test]
    fn test_deny_create_in_terminating_namespace() {
        let store = new_store_with_namespace("test-ns", NamespacePhase::Terminating);
        let handler = Lifecycle::with_lister(
            vec![NAMESPACE_DEFAULT, NAMESPACE_SYSTEM, NAMESPACE_PUBLIC],
            store,
        );

        let pod = Pod::new("test-pod", "test-ns");
        let mut attrs = AttributesRecord::new(
            "test-pod",
            "test-ns",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_err(), "Should deny create in terminating namespace");
    }

    #[test]
    fn test_deny_create_in_nonexistent_namespace() {
        let store = Arc::new(InMemoryNamespaceStore::new());
        let handler = Lifecycle::with_lister(
            vec![NAMESPACE_DEFAULT, NAMESPACE_SYSTEM, NAMESPACE_PUBLIC],
            store,
        );

        let pod = Pod::new("test-pod", "nonexistent");
        let mut attrs = AttributesRecord::new(
            "test-pod",
            "nonexistent",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_err(), "Should deny create in nonexistent namespace");
    }

    #[test]
    fn test_allow_delete_in_terminating_namespace() {
        let store = new_store_with_namespace("test-ns", NamespacePhase::Terminating);
        let handler = Lifecycle::with_lister(
            vec![NAMESPACE_DEFAULT, NAMESPACE_SYSTEM, NAMESPACE_PUBLIC],
            store,
        );

        let pod = Pod::new("test-pod", "test-ns");
        let mut attrs = AttributesRecord::new(
            "test-pod",
            "test-ns",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Delete,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_ok(), "Should allow delete in terminating namespace");
    }

    #[test]
    fn test_handles() {
        let handler = Lifecycle::default();

        assert!(handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(handler.handles(Operation::Delete));
        assert!(!handler.handles(Operation::Connect));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));
    }
}
