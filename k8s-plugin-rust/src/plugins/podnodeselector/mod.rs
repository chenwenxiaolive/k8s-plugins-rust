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

//! PodNodeSelector admission controller.
//!
//! This admission controller enforces that pods use node selectors that match
//! the namespace's allowed node selectors.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface,
    Operation, Plugins, ValidationInterface,
};
use crate::api::core::Pod;
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the PodNodeSelector admission controller.
pub const PLUGIN_NAME: &str = "PodNodeSelector";

/// Namespace annotation key for node selector.
pub const NAMESPACE_NODE_SELECTOR_ANNOTATION: &str = "scheduler.alpha.kubernetes.io/node-selector";

/// Register the PodNodeSelector plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new(HashMap::new())) as Arc<dyn Interface>)
    });
}

/// LabelSet is a set of labels.
pub type LabelSet = HashMap<String, String>;

/// Namespace information for node selector lookup.
#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    pub name: String,
    pub annotations: HashMap<String, String>,
}

/// Trait for namespace lister.
pub trait NamespaceLister: Send + Sync {
    fn get(&self, name: &str) -> Option<NamespaceInfo>;
}

/// In-memory namespace store for testing.
#[derive(Debug, Default)]
pub struct InMemoryNamespaceStore {
    namespaces: std::sync::RwLock<HashMap<String, NamespaceInfo>>,
}

impl InMemoryNamespaceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, info: NamespaceInfo) {
        self.namespaces
            .write()
            .expect("namespace store lock poisoned")
            .insert(info.name.clone(), info);
    }
}

impl NamespaceLister for InMemoryNamespaceStore {
    fn get(&self, name: &str) -> Option<NamespaceInfo> {
        self.namespaces
            .read()
            .expect("namespace store lock poisoned")
            .get(name)
            .cloned()
    }
}

/// Plugin is an implementation of the PodNodeSelector admission controller.
pub struct Plugin {
    handler: Handler,
    cluster_node_selectors: HashMap<String, String>,
    namespace_lister: Option<Arc<dyn NamespaceLister>>,
}

impl Plugin {
    /// Create a new PodNodeSelector admission controller.
    pub fn new(cluster_node_selectors: HashMap<String, String>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            cluster_node_selectors,
            namespace_lister: None,
        }
    }

    /// Create with a namespace lister.
    pub fn with_lister(
        cluster_node_selectors: HashMap<String, String>,
        lister: Arc<dyn NamespaceLister>,
    ) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            cluster_node_selectors,
            namespace_lister: Some(lister),
        }
    }

    /// Get namespace node selector map.
    fn get_namespace_node_selector_map(&self, namespace_name: &str) -> AdmissionResult<LabelSet> {
        let lister = match &self.namespace_lister {
            Some(l) => l,
            None => return Ok(LabelSet::new()),
        };

        let namespace = match lister.get(namespace_name) {
            Some(ns) => ns,
            None => {
                return Err(AdmissionError::not_found("Namespace", namespace_name));
            }
        };

        self.get_node_selector_map(&namespace)
    }

    /// Get node selector map from namespace.
    fn get_node_selector_map(&self, namespace: &NamespaceInfo) -> AdmissionResult<LabelSet> {
        let mut selector = LabelSet::new();
        let mut found = false;

        // Check namespace annotation
        if let Some(ns) = namespace.annotations.get(NAMESPACE_NODE_SELECTOR_ANNOTATION) {
            let labels_map = parse_selector_to_labels_map(ns)?;
            if labels_conflict(&selector, &labels_map) {
                return Err(AdmissionError::bad_request(&format!(
                    "{} annotations' node label selectors conflict",
                    namespace.name
                )));
            }
            selector = merge_labels(selector, labels_map);
            found = true;
        }

        if !found {
            // Use cluster default
            if let Some(default_selector) = self.cluster_node_selectors.get("clusterDefaultNodeSelector") {
                selector = parse_selector_to_labels_map(default_selector)?;
            }
        }

        Ok(selector)
    }

    /// Check if this admission controller should ignore the request.
    fn should_ignore(&self, attributes: &dyn Attributes) -> bool {
        let resource = attributes.get_resource();
        if resource.resource != "pods" {
            return true;
        }
        if !attributes.get_subresource().is_empty() {
            return true;
        }
        false
    }
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new(HashMap::new())
    }
}

impl Interface for Plugin {
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl MutationInterface for Plugin {
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        if self.should_ignore(attributes) {
            return Ok(());
        }

        let namespace = attributes.get_namespace().to_string();
        let namespace_node_selector = self.get_namespace_node_selector_map(&namespace)?;

        // Get pod
        let obj = match attributes.get_object_mut() {
            Some(o) => o,
            None => return Ok(()),
        };

        let pod = match obj.as_any_mut().downcast_mut::<Pod>() {
            Some(p) => p,
            None => {
                return Err(AdmissionError::bad_request("expected Pod but got different type"));
            }
        };

        // Check for conflicts
        if labels_conflict(&namespace_node_selector, &pod.spec.node_selector) {
            let pod_name = pod.name.clone();
            return Err(AdmissionError::forbidden(
                pod_name,
                namespace,
                "pods",
                crate::admission::errors::FieldError {
                    field: "spec.nodeSelector".to_string(),
                    error_type: crate::admission::errors::FieldErrorType::Invalid,
                    value: "pod node label selector conflicts with its namespace node label selector".to_string(),
                    supported_values: vec![],
                },
            ));
        }

        // Merge: namespace node selector + pod node selector (pod wins)
        let merged = merge_labels(namespace_node_selector, pod.spec.node_selector.clone());
        pod.spec.node_selector = merged;

        Ok(())
    }
}

impl ValidationInterface for Plugin {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        if self.should_ignore(attributes) {
            return Ok(());
        }

        let namespace = attributes.get_namespace();
        let namespace_node_selector = self.get_namespace_node_selector_map(&namespace)?;

        // Get pod
        let obj = match attributes.get_object() {
            Some(o) => o,
            None => return Ok(()),
        };

        let pod = match obj.as_any().downcast_ref::<Pod>() {
            Some(p) => p,
            None => {
                return Err(AdmissionError::bad_request("expected Pod but got different type"));
            }
        };

        // Check for conflicts
        if labels_conflict(&namespace_node_selector, &pod.spec.node_selector) {
            return Err(AdmissionError::forbidden(
                &pod.name,
                &*namespace,
                "pods",
                crate::admission::errors::FieldError {
                    field: "spec.nodeSelector".to_string(),
                    error_type: crate::admission::errors::FieldErrorType::Invalid,
                    value: "pod node label selector conflicts with its namespace node label selector".to_string(),
                    supported_values: vec![],
                },
            ));
        }

        // Whitelist verification
        let whitelist = if let Some(wl) = self.cluster_node_selectors.get(&*namespace) {
            parse_selector_to_labels_map(wl)?
        } else {
            LabelSet::new()
        };

        if !is_subset(&pod.spec.node_selector, &whitelist) {
            return Err(AdmissionError::forbidden(
                &pod.name,
                &*namespace,
                "pods",
                crate::admission::errors::FieldError {
                    field: "spec.nodeSelector".to_string(),
                    error_type: crate::admission::errors::FieldErrorType::Invalid,
                    value: "pod node label selector labels conflict with its namespace whitelist".to_string(),
                    supported_values: vec![],
                },
            ));
        }

        Ok(())
    }
}

/// Parse a selector string to a labels map.
/// Format: "key1=value1,key2=value2"
fn parse_selector_to_labels_map(selector: &str) -> AdmissionResult<LabelSet> {
    let mut result = LabelSet::new();
    if selector.is_empty() {
        return Ok(result);
    }

    for part in selector.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let kv: Vec<&str> = part.splitn(2, '=').collect();
        if kv.len() != 2 {
            return Err(AdmissionError::bad_request(&format!(
                "invalid selector format: {}",
                part
            )));
        }
        result.insert(kv[0].trim().to_string(), kv[1].trim().to_string());
    }
    Ok(result)
}

/// Check if two label sets conflict.
fn labels_conflict(a: &LabelSet, b: &LabelSet) -> bool {
    for (k, v) in a {
        if let Some(bv) = b.get(k) {
            if v != bv {
                return true;
            }
        }
    }
    false
}

/// Merge two label sets. Second set wins on conflicts.
fn merge_labels(mut base: LabelSet, overlay: LabelSet) -> LabelSet {
    for (k, v) in overlay {
        base.insert(k, v);
    }
    base
}

/// Check if subset is a subset of superset.
fn is_subset(subset: &LabelSet, superset: &LabelSet) -> bool {
    if superset.is_empty() {
        return true;
    }
    for (k, v) in subset {
        match superset.get(k) {
            Some(sv) if sv == v => continue,
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    #[allow(dead_code)]
    fn create_namespace_store() -> Arc<InMemoryNamespaceStore> {
        let store = Arc::new(InMemoryNamespaceStore::new());
        store.add(NamespaceInfo {
            name: "default".to_string(),
            annotations: HashMap::new(),
        });
        store
    }

    #[test]
    fn test_parse_selector_to_labels_map() {
        let result = parse_selector_to_labels_map("env=prod,tier=frontend").unwrap();
        assert_eq!(result.get("env"), Some(&"prod".to_string()));
        assert_eq!(result.get("tier"), Some(&"frontend".to_string()));
    }

    #[test]
    fn test_parse_selector_empty() {
        let result = parse_selector_to_labels_map("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_labels_conflict() {
        let mut a = LabelSet::new();
        a.insert("env".to_string(), "prod".to_string());

        let mut b = LabelSet::new();
        b.insert("env".to_string(), "dev".to_string());

        assert!(labels_conflict(&a, &b));
    }

    #[test]
    fn test_labels_no_conflict() {
        let mut a = LabelSet::new();
        a.insert("env".to_string(), "prod".to_string());

        let mut b = LabelSet::new();
        b.insert("tier".to_string(), "frontend".to_string());

        assert!(!labels_conflict(&a, &b));
    }

    #[test]
    fn test_merge_labels() {
        let mut base = LabelSet::new();
        base.insert("env".to_string(), "prod".to_string());

        let mut overlay = LabelSet::new();
        overlay.insert("tier".to_string(), "frontend".to_string());
        overlay.insert("env".to_string(), "dev".to_string());

        let merged = merge_labels(base, overlay);
        assert_eq!(merged.get("env"), Some(&"dev".to_string()));
        assert_eq!(merged.get("tier"), Some(&"frontend".to_string()));
    }

    #[test]
    fn test_is_subset() {
        let mut subset = LabelSet::new();
        subset.insert("env".to_string(), "prod".to_string());

        let mut superset = LabelSet::new();
        superset.insert("env".to_string(), "prod".to_string());
        superset.insert("tier".to_string(), "frontend".to_string());

        assert!(is_subset(&subset, &superset));
    }

    #[test]
    fn test_is_subset_empty_superset() {
        let mut subset = LabelSet::new();
        subset.insert("env".to_string(), "prod".to_string());

        let superset = LabelSet::new();

        assert!(is_subset(&subset, &superset));
    }

    #[test]
    fn test_handles() {
        let handler = Plugin::new(HashMap::new());

        assert!(handler.handles(Operation::Create));
        assert!(!handler.handles(Operation::Update));
        assert!(!handler.handles(Operation::Delete));
        assert!(!handler.handles(Operation::Connect));
    }

    #[test]
    fn test_should_ignore_non_pod() {
        let handler = Plugin::new(HashMap::new());

        let pod = Pod::new("test", "default");
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );

        assert!(handler.should_ignore(&attrs));
    }

    #[test]
    fn test_should_ignore_subresource() {
        let handler = Plugin::new(HashMap::new());

        let pod = Pod::new("test", "default");
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "status",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        assert!(handler.should_ignore(&attrs));
    }

    #[test]
    fn test_admit_merge_namespace_selector() {
        let store = Arc::new(InMemoryNamespaceStore::new());
        let mut annotations = HashMap::new();
        annotations.insert(
            NAMESPACE_NODE_SELECTOR_ANNOTATION.to_string(),
            "env=prod".to_string(),
        );
        store.add(NamespaceInfo {
            name: "test".to_string(),
            annotations,
        });

        let handler = Plugin::with_lister(HashMap::new(), store);

        let mut pod = Pod::new("test-pod", "test");
        pod.spec.node_selector.insert("tier".to_string(), "frontend".to_string());

        let mut attrs = AttributesRecord::new(
            "test-pod",
            "test",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_ok());

        // Verify the pod's node selector was merged
        let obj = attrs.get_object().unwrap();
        let pod = obj.as_any().downcast_ref::<Pod>().unwrap();
        assert_eq!(pod.spec.node_selector.get("env"), Some(&"prod".to_string()));
        assert_eq!(pod.spec.node_selector.get("tier"), Some(&"frontend".to_string()));
    }

    #[test]
    fn test_admit_conflict() {
        let store = Arc::new(InMemoryNamespaceStore::new());
        let mut annotations = HashMap::new();
        annotations.insert(
            NAMESPACE_NODE_SELECTOR_ANNOTATION.to_string(),
            "env=prod".to_string(),
        );
        store.add(NamespaceInfo {
            name: "test".to_string(),
            annotations,
        });

        let handler = Plugin::with_lister(HashMap::new(), store);

        let mut pod = Pod::new("test-pod", "test");
        pod.spec.node_selector.insert("env".to_string(), "dev".to_string());

        let mut attrs = AttributesRecord::new(
            "test-pod",
            "test",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = handler.admit(&mut attrs);
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));
    }
}
