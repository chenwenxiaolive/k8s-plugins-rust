// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! PodTopologyLabels admission controller.
//!
//! This admission controller copies topology labels from Node objects onto Pod objects
//! when they are scheduled. It supports both direct Pod updates and Binding subresource
//! operations. By default, it copies "topology.kubernetes.io/zone" and
//! "topology.kubernetes.io/region" labels.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins,
};
use crate::api::core::{Binding, Node, Pod};
use std::collections::HashSet;
use std::io::Read;
use std::sync::{Arc, RwLock};

pub const PLUGIN_NAME: &str = "PodTopologyLabels";

/// Default topology labels to copy from Node to Pod.
const DEFAULT_TOPOLOGY_LABELS: &[&str] = &[
    "topology.kubernetes.io/zone",
    "topology.kubernetes.io/region",
];

pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new(Config::default())) as Arc<dyn Interface>)
    });
}

/// Configuration for the PodTopologyLabels admission plugin.
#[derive(Debug, Clone)]
pub struct Config {
    /// Labels is the set of explicit label keys to be copied from the Node object
    /// onto Pod/Binding objects during admission.
    pub labels: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            labels: DEFAULT_TOPOLOGY_LABELS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// Trait for looking up Node objects.
pub trait NodeLister: Send + Sync {
    /// Get a Node by name.
    fn get(&self, name: &str) -> Option<Node>;
}

/// In-memory implementation of NodeLister for testing.
pub struct InMemoryNodeLister {
    nodes: RwLock<std::collections::HashMap<String, Node>>,
}

impl InMemoryNodeLister {
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub fn add_node(&self, node: Node) {
        let mut nodes = self.nodes.write().unwrap();
        nodes.insert(node.name.clone(), node);
    }
}

impl Default for InMemoryNodeLister {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeLister for InMemoryNodeLister {
    fn get(&self, name: &str) -> Option<Node> {
        let nodes = self.nodes.read().unwrap();
        nodes.get(name).cloned()
    }
}

pub struct Plugin {
    handler: Handler,
    /// Set of label keys to copy from Node to Pod.
    labels: HashSet<String>,
    /// Node lister for looking up node labels.
    node_lister: Option<Arc<dyn NodeLister>>,
    /// Whether the feature is enabled.
    enabled: bool,
    /// Whether the plugin is ready.
    ready: bool,
}

impl Plugin {
    pub fn new(config: Config) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            labels: config.labels.into_iter().collect(),
            node_lister: None,
            enabled: true, // Enabled by default in Rust implementation
            ready: false,
        }
    }

    /// Set the node lister and mark the plugin as ready.
    pub fn set_node_lister(&mut self, lister: Arc<dyn NodeLister>) {
        self.node_lister = Some(lister);
        self.ready = true;
    }

    /// Create a plugin with a node lister already set.
    pub fn with_node_lister(config: Config, lister: Arc<dyn NodeLister>) -> Self {
        let mut plugin = Self::new(config);
        plugin.set_node_lister(lister);
        plugin
    }

    /// Set whether the feature is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if a label key is a topology label that should be copied.
    fn is_topology_label(&self, key: &str) -> bool {
        self.labels.contains(key)
    }

    /// Get topology labels from a node by name.
    fn topology_labels_for_node_name(
        &self,
        node_name: &str,
    ) -> AdmissionResult<std::collections::HashMap<String, String>> {
        let mut labels = std::collections::HashMap::new();

        let node_lister = match &self.node_lister {
            Some(lister) => lister,
            None => return Ok(labels), // Return empty if no lister configured
        };

        // Try to get the node, but ignore not found errors
        let node = match node_lister.get(node_name) {
            Some(n) => n,
            None => return Ok(labels), // Node not found, return empty labels
        };

        // Copy matching topology labels
        for (k, v) in &node.labels {
            if self.is_topology_label(k) {
                labels.insert(k.clone(), v.clone());
            }
        }

        Ok(labels)
    }

    /// Admit a Pod object (direct create/update).
    #[allow(dead_code)]
    fn admit_pod(&self, pod: &mut Pod) -> AdmissionResult<()> {
        // If pod has no node name, it hasn't been scheduled yet
        if pod.node_name.is_none() || pod.node_name.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            return Ok(());
        }

        let node_name = pod.node_name.as_ref().unwrap();

        // Get topology labels from the node
        let labels_to_copy = self.topology_labels_for_node_name(node_name)?;
        if labels_to_copy.is_empty() {
            return Ok(());
        }

        // Copy the topology labels into the Pod's labels
        merge_labels(&mut pod.labels, &labels_to_copy);

        Ok(())
    }

    /// Admit a Binding object.
    #[allow(dead_code)]
    fn admit_binding(&self, binding: &mut Binding) -> AdmissionResult<()> {
        // Only process bindings to Nodes
        if binding.target.kind.as_deref() != Some("Node") {
            return Ok(());
        }

        let node_name = match &binding.target.name {
            Some(name) if !name.is_empty() => name.clone(),
            _ => return Ok(()),
        };

        // Get topology labels from the node
        let labels_to_copy = self.topology_labels_for_node_name(&node_name)?;
        if labels_to_copy.is_empty() {
            return Ok(());
        }

        // Copy the topology labels into the Binding's labels
        merge_labels(&mut binding.labels, &labels_to_copy);

        Ok(())
    }
}

/// Merge new labels into existing labels, overwriting existing keys.
fn merge_labels(
    existing: &mut std::collections::HashMap<String, String>,
    new: &std::collections::HashMap<String, String>,
) {
    for (k, v) in new {
        existing.insert(k.clone(), v.clone());
    }
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Interface for Plugin {
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl MutationInterface for Plugin {
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // If feature is disabled, skip
        if !self.enabled {
            return Ok(());
        }

        let resource = attributes.get_resource();
        if resource.resource != "pods" {
            return Ok(());
        }

        let subresource = attributes.get_subresource();

        // Check if we're ready
        if !self.ready {
            return Err(AdmissionError::not_ready(PLUGIN_NAME));
        }

        match subresource.as_ref() {
            "" => {
                // Regular Pod endpoint
                let pod = match attributes
                    .get_object_mut()
                    .and_then(|obj| obj.as_any_mut().downcast_mut::<Pod>())
                {
                    Some(p) => p,
                    None => return Ok(()),
                };

                // Create a mutable copy to work with
                let node_name = pod.node_name.clone();
                if node_name.is_none()
                    || node_name.as_ref().map(|s| s.is_empty()).unwrap_or(true)
                {
                    return Ok(());
                }

                let labels_to_copy =
                    self.topology_labels_for_node_name(node_name.as_ref().unwrap())?;
                if !labels_to_copy.is_empty() {
                    merge_labels(&mut pod.labels, &labels_to_copy);
                }
                Ok(())
            }
            "binding" => {
                // Binding subresource
                let binding = match attributes
                    .get_object_mut()
                    .and_then(|obj| obj.as_any_mut().downcast_mut::<Binding>())
                {
                    Some(b) => b,
                    None => return Ok(()),
                };

                // Only process bindings to Nodes
                if binding.target.kind.as_deref() != Some("Node") {
                    return Ok(());
                }

                let node_name = match &binding.target.name {
                    Some(name) if !name.is_empty() => name.clone(),
                    _ => return Ok(()),
                };

                let labels_to_copy = self.topology_labels_for_node_name(&node_name)?;
                if !labels_to_copy.is_empty() {
                    merge_labels(&mut binding.labels, &labels_to_copy);
                }
                Ok(())
            }
            _ => {
                // Ignore all other sub-resources
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::ObjectReference;
    use std::collections::HashMap;

    fn create_node_with_labels(name: &str, labels: HashMap<String, String>) -> Node {
        Node {
            name: name.to_string(),
            labels,
            taints: vec![],
            spec: Default::default(),
            status: Default::default(),
        }
    }

    fn create_pod(name: &str, node_name: Option<&str>) -> Pod {
        let mut pod = Pod::new(name, "test-ns");
        pod.node_name = node_name.map(|s| s.to_string());
        pod
    }

    fn create_binding(name: &str, target_kind: &str, target_name: &str) -> Binding {
        Binding {
            name: name.to_string(),
            namespace: "test-ns".to_string(),
            labels: HashMap::new(),
            target: ObjectReference {
                kind: Some(target_kind.to_string()),
                name: Some(target_name.to_string()),
                namespace: None,
                uid: None,
                api_version: None,
                resource_version: None,
                field_path: None,
            },
        }
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new(Config::default());
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.labels.len(), 2);
        assert!(config.labels.contains(&"topology.kubernetes.io/zone".to_string()));
        assert!(config.labels.contains(&"topology.kubernetes.io/region".to_string()));
    }

    #[test]
    fn test_is_topology_label() {
        let plugin = Plugin::new(Config::default());
        assert!(plugin.is_topology_label("topology.kubernetes.io/zone"));
        assert!(plugin.is_topology_label("topology.kubernetes.io/region"));
        assert!(!plugin.is_topology_label("topology.kubernetes.io/arbitrary"));
        assert!(!plugin.is_topology_label("non-topology.kubernetes.io/label"));
    }

    #[test]
    fn test_copies_topology_labels_to_pod() {
        let node_lister = Arc::new(InMemoryNodeLister::new());
        let mut node_labels = HashMap::new();
        node_labels.insert("topology.kubernetes.io/zone".to_string(), "zone1".to_string());
        node_labels.insert("topology.kubernetes.io/region".to_string(), "region1".to_string());
        node_labels.insert("topology.kubernetes.io/arbitrary".to_string(), "something".to_string());
        node_labels.insert("non-topology.kubernetes.io/label".to_string(), "something".to_string());
        node_lister.add_node(create_node_with_labels("test-node", node_labels));

        let plugin = Plugin::with_node_lister(Config::default(), node_lister);

        let mut pod = create_pod("test-pod", Some("test-node"));
        plugin.admit_pod(&mut pod).unwrap();

        assert_eq!(pod.labels.get("topology.kubernetes.io/zone"), Some(&"zone1".to_string()));
        assert_eq!(pod.labels.get("topology.kubernetes.io/region"), Some(&"region1".to_string()));
        // Should NOT copy arbitrary topology labels
        assert!(!pod.labels.contains_key("topology.kubernetes.io/arbitrary"));
        assert!(!pod.labels.contains_key("non-topology.kubernetes.io/label"));
    }

    #[test]
    fn test_does_not_copy_arbitrary_topology_labels() {
        let node_lister = Arc::new(InMemoryNodeLister::new());
        let mut node_labels = HashMap::new();
        node_labels.insert("topology.kubernetes.io/zone".to_string(), "zone1".to_string());
        node_labels.insert("topology.kubernetes.io/arbitrary".to_string(), "something".to_string());
        node_lister.add_node(create_node_with_labels("test-node", node_labels));

        let plugin = Plugin::with_node_lister(Config::default(), node_lister);

        let mut pod = create_pod("test-pod", Some("test-node"));
        plugin.admit_pod(&mut pod).unwrap();

        assert_eq!(pod.labels.get("topology.kubernetes.io/zone"), Some(&"zone1".to_string()));
        assert!(!pod.labels.contains_key("topology.kubernetes.io/arbitrary"));
    }

    #[test]
    fn test_overwrites_existing_topology_labels() {
        let node_lister = Arc::new(InMemoryNodeLister::new());
        let mut node_labels = HashMap::new();
        node_labels.insert("topology.kubernetes.io/zone".to_string(), "newValue".to_string());
        node_lister.add_node(create_node_with_labels("test-node", node_labels));

        let plugin = Plugin::with_node_lister(Config::default(), node_lister);

        let mut pod = create_pod("test-pod", Some("test-node"));
        pod.labels.insert("topology.kubernetes.io/zone".to_string(), "oldValue".to_string());
        plugin.admit_pod(&mut pod).unwrap();

        assert_eq!(pod.labels.get("topology.kubernetes.io/zone"), Some(&"newValue".to_string()));
    }

    #[test]
    fn test_skips_pod_without_node_name() {
        let node_lister = Arc::new(InMemoryNodeLister::new());
        let plugin = Plugin::with_node_lister(Config::default(), node_lister);

        let mut pod = create_pod("test-pod", None);
        plugin.admit_pod(&mut pod).unwrap();

        assert!(pod.labels.is_empty());
    }

    #[test]
    fn test_copies_topology_labels_to_binding() {
        let node_lister = Arc::new(InMemoryNodeLister::new());
        let mut node_labels = HashMap::new();
        node_labels.insert("topology.kubernetes.io/zone".to_string(), "zone1".to_string());
        node_labels.insert("topology.kubernetes.io/region".to_string(), "region1".to_string());
        node_lister.add_node(create_node_with_labels("test-node", node_labels));

        let plugin = Plugin::with_node_lister(Config::default(), node_lister);

        let mut binding = create_binding("test-pod", "Node", "test-node");
        plugin.admit_binding(&mut binding).unwrap();

        assert_eq!(binding.labels.get("topology.kubernetes.io/zone"), Some(&"zone1".to_string()));
        assert_eq!(binding.labels.get("topology.kubernetes.io/region"), Some(&"region1".to_string()));
    }

    #[test]
    fn test_skips_binding_to_non_node() {
        let node_lister = Arc::new(InMemoryNodeLister::new());
        let plugin = Plugin::with_node_lister(Config::default(), node_lister);

        let mut binding = create_binding("test-pod", "PersistentVolume", "some-pv");
        plugin.admit_binding(&mut binding).unwrap();

        assert!(binding.labels.is_empty());
    }

    #[test]
    fn test_feature_disabled() {
        let node_lister = Arc::new(InMemoryNodeLister::new());
        let mut node_labels = HashMap::new();
        node_labels.insert("topology.kubernetes.io/zone".to_string(), "zone1".to_string());
        node_lister.add_node(create_node_with_labels("test-node", node_labels));

        let mut plugin = Plugin::with_node_lister(Config::default(), node_lister);
        plugin.set_enabled(false);

        // When disabled, admit() should return Ok immediately without modifications
        let pod = create_pod("test-pod", Some("test-node"));
        let mut attrs = AttributesRecord::new(
            "test-pod",
            "test-ns",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod.clone())),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();
        // Should not have modified anything because feature is disabled
    }

    #[test]
    fn test_node_not_found_returns_empty_labels() {
        let node_lister = Arc::new(InMemoryNodeLister::new());
        // Don't add any nodes
        let plugin = Plugin::with_node_lister(Config::default(), node_lister);

        let mut pod = create_pod("test-pod", Some("nonexistent-node"));
        plugin.admit_pod(&mut pod).unwrap();

        // Should succeed but not add any labels
        assert!(pod.labels.is_empty());
    }

    #[test]
    fn test_custom_config_labels() {
        let node_lister = Arc::new(InMemoryNodeLister::new());
        let mut node_labels = HashMap::new();
        node_labels.insert("custom.label/key".to_string(), "value1".to_string());
        node_labels.insert("topology.kubernetes.io/zone".to_string(), "zone1".to_string());
        node_lister.add_node(create_node_with_labels("test-node", node_labels));

        let config = Config {
            labels: vec!["custom.label/key".to_string()],
        };
        let plugin = Plugin::with_node_lister(config, node_lister);

        let mut pod = create_pod("test-pod", Some("test-node"));
        plugin.admit_pod(&mut pod).unwrap();

        // Should only copy the custom label, not the default topology labels
        assert_eq!(pod.labels.get("custom.label/key"), Some(&"value1".to_string()));
        assert!(!pod.labels.contains_key("topology.kubernetes.io/zone"));
    }
}
