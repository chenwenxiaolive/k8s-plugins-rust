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

//! NamespaceAutoProvision admission controller.
//!
//! This admission controller looks at all incoming requests in a namespace context,
//! and if the namespace does not exist, it creates one. It is useful in deployments
//! that do not want to restrict creation of a namespace prior to its usage.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins,
};
use std::collections::HashSet;
use std::io::Read;
use std::sync::{Arc, RwLock};

/// Plugin name for the NamespaceAutoProvision admission controller.
pub const PLUGIN_NAME: &str = "NamespaceAutoProvision";

/// Register the NamespaceAutoProvision plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Provision::new()) as Arc<dyn Interface>)
    });
}

/// NamespaceClient trait for creating namespaces.
pub trait NamespaceClient: Send + Sync {
    /// Create a namespace. Returns Ok(()) if created or already exists.
    fn create_namespace(&self, name: &str) -> Result<(), AdmissionError>;
}

/// NamespaceLister trait for checking if a namespace exists.
pub trait NamespaceLister: Send + Sync {
    /// Get a namespace by name. Returns Ok(()) if exists, Err if not found.
    fn get(&self, name: &str) -> Result<(), AdmissionError>;
}

/// In-memory namespace store for testing purposes.
#[derive(Debug, Default)]
pub struct InMemoryNamespaceStore {
    namespaces: RwLock<HashSet<String>>,
}

impl InMemoryNamespaceStore {
    /// Create a new in-memory namespace store.
    pub fn new() -> Self {
        Self {
            namespaces: RwLock::new(HashSet::new()),
        }
    }

    /// Create a new in-memory namespace store with the given namespaces.
    pub fn with_namespaces(namespaces: Vec<&str>) -> Self {
        let store = Self::new();
        for ns in namespaces {
            store.add(ns);
        }
        store
    }

    /// Add a namespace.
    pub fn add(&self, name: &str) {
        self.namespaces
            .write()
            .expect("namespace store lock poisoned")
            .insert(name.to_string());
    }

    /// Check if namespace exists.
    pub fn exists(&self, name: &str) -> bool {
        self.namespaces
            .read()
            .expect("namespace store lock poisoned")
            .contains(name)
    }

    /// Get the list of created namespaces (for testing).
    pub fn get_namespaces(&self) -> Vec<String> {
        self.namespaces
            .read()
            .expect("namespace store lock poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

impl NamespaceLister for InMemoryNamespaceStore {
    fn get(&self, name: &str) -> Result<(), AdmissionError> {
        if self.exists(name) {
            Ok(())
        } else {
            Err(AdmissionError::not_found("Namespace", name))
        }
    }
}

impl NamespaceClient for InMemoryNamespaceStore {
    fn create_namespace(&self, name: &str) -> Result<(), AdmissionError> {
        self.add(name);
        Ok(())
    }
}

/// Provision is an implementation of admission.Interface.
/// It looks at all incoming requests in a namespace context, and if the namespace
/// does not exist, it creates one.
pub struct Provision {
    handler: Handler,
    client: Option<Arc<dyn NamespaceClient>>,
    namespace_lister: Option<Arc<dyn NamespaceLister>>,
    ready: RwLock<bool>,
}

impl Provision {
    /// Create a new NamespaceAutoProvision admission control handler.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            client: None,
            namespace_lister: None,
            ready: RwLock::new(false),
        }
    }

    /// Create a new Provision with client and lister.
    pub fn with_client_and_lister(
        client: Arc<dyn NamespaceClient>,
        lister: Arc<dyn NamespaceLister>,
    ) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            client: Some(client),
            namespace_lister: Some(lister),
            ready: RwLock::new(true),
        }
    }

    /// Create a new Provision with a store that acts as both client and lister.
    pub fn with_store(store: Arc<InMemoryNamespaceStore>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            client: Some(store.clone()),
            namespace_lister: Some(store),
            ready: RwLock::new(true),
        }
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

impl Default for Provision {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for Provision {
    /// Handles returns true for Create operations only.
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl MutationInterface for Provision {
    /// Admit makes an admission decision based on the request attributes.
    /// If the namespace doesn't exist, it creates one.
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Don't create a namespace if the request is for a dry-run.
        if attributes.is_dry_run() {
            return Ok(());
        }

        // if we're here, then we've already passed authentication
        // if we have a non-empty namespace, it's a namespaced resource.
        let namespace = attributes.get_namespace();
        if namespace.is_empty() {
            return Ok(());
        }

        // Skip Namespace objects themselves
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
                return Err(AdmissionError::internal_error("namespace lister not configured"));
            }
        };

        // If namespace exists, we're done
        if lister.get(&namespace).is_ok() {
            return Ok(());
        }

        // Namespace doesn't exist, create it
        let client = match &self.client {
            Some(c) => c,
            None => {
                return Err(AdmissionError::internal_error("client not configured"));
            }
        };

        // Create the namespace (handles AlreadyExists gracefully)
        match client.create_namespace(&namespace) {
            Ok(()) => Ok(()),
            Err(AdmissionError::NotFound { .. }) => Ok(()), // Already exists is OK
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

    /// TestAdmission verifies a namespace is created on create requests for namespace managed resources
    #[test]
    fn test_admission() {
        let namespace = "test";
        let store = Arc::new(InMemoryNamespaceStore::new());
        let handler = Provision::with_store(store.clone());

        let pod = new_pod(namespace);
        let pod_name = pod.name.clone();
        let mut attrs = AttributesRecord::new(
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

        let result = handler.admit(&mut attrs);
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());

        // Verify namespace was created
        assert!(
            store.exists(namespace),
            "expected namespace to be created"
        );
    }

    /// TestAdmissionNamespaceExists verifies that no client call is made when a namespace already exists
    #[test]
    fn test_admission_namespace_exists() {
        let namespace = "test";
        let store = Arc::new(InMemoryNamespaceStore::with_namespaces(vec![namespace]));
        let initial_count = store.get_namespaces().len();
        let handler = Provision::with_store(store.clone());

        let pod = new_pod(namespace);
        let pod_name = pod.name.clone();
        let mut attrs = AttributesRecord::new(
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

        let result = handler.admit(&mut attrs);
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());

        // Verify no new namespace was created
        assert_eq!(
            store.get_namespaces().len(),
            initial_count,
            "no new namespace should be created"
        );
    }

    /// TestAdmissionDryRun verifies that no client call is made on a dry run request
    #[test]
    fn test_admission_dry_run() {
        let namespace = "test";
        let store = Arc::new(InMemoryNamespaceStore::new());
        let handler = Provision::with_store(store.clone());

        let pod = new_pod(namespace);
        let pod_name = pod.name.clone();
        let mut attrs = AttributesRecord::new(
            &pod_name,
            namespace,
            GroupVersionResource::new("", "version", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "version", "Pod"),
            true, // dry run
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());

        // Verify namespace was NOT created (dry run)
        assert!(
            !store.exists(namespace),
            "namespace should not be created on dry run"
        );
    }

    /// TestIgnoreAdmission validates that a request is ignored if its not a create
    #[test]
    fn test_ignore_admission() {
        let _namespace = "test";
        let store = Arc::new(InMemoryNamespaceStore::new());
        let handler = Provision::with_store(store.clone());

        // Update operation should be ignored (handler only handles Create)
        assert!(
            !handler.handles(Operation::Update),
            "handler should not handle Update"
        );
        assert!(
            handler.handles(Operation::Create),
            "handler should handle Create"
        );
    }

    /// Test that namespace objects themselves are ignored
    #[test]
    fn test_namespace_objects_ignored() {
        let store = Arc::new(InMemoryNamespaceStore::new());
        let handler = Provision::with_store(store.clone());

        let ns = crate::api::core::Namespace::new("new-namespace");
        let mut attrs = AttributesRecord::new(
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

        let result = handler.admit(&mut attrs);
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());

        // Verify namespace was NOT auto-created (Namespace objects are skipped)
        assert!(
            !store.exists("new-namespace"),
            "namespace should not be auto-created for Namespace objects"
        );
    }

    /// Test which operations are handled
    #[test]
    fn test_handles() {
        let handler = Provision::new();

        let tests = [
            (Operation::Create, true),
            (Operation::Update, false),
            (Operation::Delete, false),
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
        assert!(!plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }
}
