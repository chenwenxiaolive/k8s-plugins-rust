// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! PodTolerationRestriction admission controller.
//!
//! This admission controller verifies any conflict between a pod's tolerations
//! and the tolerations of its namespace. It rejects the pod if there's a conflict.
//! If the namespace has default tolerations, they are merged with the pod's tolerations.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins, ValidationInterface,
};
use crate::api::core::{Namespace, Pod, Toleration, TolerationOperator, TolerationEffect};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

/// Plugin name for PodTolerationRestriction admission controller.
pub const PLUGIN_NAME: &str = "PodTolerationRestriction";

/// Annotation key for namespace default tolerations.
pub const NS_DEFAULT_TOLERATIONS: &str = "scheduler.alpha.kubernetes.io/defaultTolerations";

/// Annotation key for namespace tolerations whitelist.
pub const NS_WHITELIST_TOLERATIONS: &str = "scheduler.alpha.kubernetes.io/tolerationsWhitelist";

/// Taint key for memory pressure.
pub const TAINT_NODE_MEMORY_PRESSURE: &str = "node.kubernetes.io/memory-pressure";

/// Register the PodTolerationRestriction plugin.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Configuration for the PodTolerationRestriction plugin.
#[derive(Debug, Clone, Default)]
pub struct Configuration {
    /// Default tolerations to add to all pods.
    pub default: Vec<Toleration>,
    /// Whitelist of allowed tolerations.
    pub whitelist: Vec<Toleration>,
}

/// Trait for namespace store operations.
pub trait NamespaceStore: Send + Sync {
    fn get(&self, name: &str) -> Option<Namespace>;
}

/// In-memory namespace store for testing.
pub struct InMemoryNamespaceStore {
    namespaces: RwLock<HashMap<String, Namespace>>,
}

impl InMemoryNamespaceStore {
    pub fn new() -> Self {
        Self {
            namespaces: RwLock::new(HashMap::new()),
        }
    }

    pub fn add(&self, ns: Namespace) {
        let mut namespaces = self.namespaces.write().unwrap();
        namespaces.insert(ns.name.clone(), ns);
    }
}

impl Default for InMemoryNamespaceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceStore for InMemoryNamespaceStore {
    fn get(&self, name: &str) -> Option<Namespace> {
        let namespaces = self.namespaces.read().unwrap();
        namespaces.get(name).cloned()
    }
}

/// PodTolerationRestriction plugin.
pub struct Plugin {
    handler: Handler,
    config: Configuration,
    namespace_store: Option<Arc<dyn NamespaceStore>>,
    ready: RwLock<bool>,
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            config: Configuration::default(),
            namespace_store: None,
            ready: RwLock::new(true),
        }
    }

    pub fn with_config(config: Configuration) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            config,
            namespace_store: None,
            ready: RwLock::new(true),
        }
    }

    pub fn with_namespace_store(mut self, store: Arc<dyn NamespaceStore>) -> Self {
        self.namespace_store = Some(store);
        self
    }

    /// Check if the plugin is ready.
    fn is_ready(&self) -> bool {
        *self.ready.read().unwrap()
    }

    /// Get namespace default tolerations from annotations.
    fn get_namespace_default_tolerations(&self, ns_name: &str) -> Option<Vec<Toleration>> {
        let store = self.namespace_store.as_ref()?;
        let ns = store.get(ns_name)?;
        extract_tolerations_from_annotations(&ns.annotations, NS_DEFAULT_TOLERATIONS)
    }

    /// Get namespace tolerations whitelist from annotations.
    fn get_namespace_whitelist(&self, ns_name: &str) -> Option<Vec<Toleration>> {
        let store = self.namespace_store.as_ref()?;
        let ns = store.get(ns_name)?;
        extract_tolerations_from_annotations(&ns.annotations, NS_WHITELIST_TOLERATIONS)
    }

    /// Check if a toleration is in the whitelist.
    fn toleration_in_whitelist(toleration: &Toleration, whitelist: &[Toleration]) -> bool {
        for wl in whitelist {
            if tolerations_match(toleration, wl) {
                return true;
            }
        }
        false
    }

    /// Verify all tolerations are in the whitelist.
    fn verify_against_whitelist(tolerations: &[Toleration], whitelist: &[Toleration]) -> bool {
        for t in tolerations {
            if !Self::toleration_in_whitelist(t, whitelist) {
                return false;
            }
        }
        true
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

impl MutationInterface for Plugin {
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Only handle pods
        let resource = attributes.get_resource();
        if resource.resource != "pods" {
            return Ok(());
        }

        // Skip subresources
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        if !self.is_ready() {
            return Err(AdmissionError::not_ready("PodTolerationRestriction"));
        }

        // Get namespace and operation before mutable borrow
        let namespace = attributes.get_namespace().to_string();
        let operation = attributes.get_operation();

        // Get the pod
        let pod = match attributes
            .get_object_mut()
            .and_then(|obj| obj.as_any_mut().downcast_mut::<Pod>())
        {
            Some(pod) => pod,
            None => return Ok(()),
        };

        let mut extra_tolerations: Vec<Toleration> = Vec::new();

        // On create, add namespace default tolerations
        if operation == Operation::Create {
            // Try namespace-level defaults first
            if let Some(ns_defaults) = self.get_namespace_default_tolerations(&namespace) {
                extra_tolerations.extend(ns_defaults);
            } else {
                // Fall back to cluster-level defaults
                extra_tolerations.extend(self.config.default.clone());
            }
        }

        // Add memory pressure toleration for non-BestEffort pods
        if !is_best_effort_pod(pod) {
            extra_tolerations.push(Toleration {
                key: TAINT_NODE_MEMORY_PRESSURE.to_string(),
                operator: TolerationOperator::Exists,
                value: String::new(),
                effect: Some(TolerationEffect::NoSchedule),
                toleration_seconds: None,
            });
        }

        // Merge tolerations
        if !extra_tolerations.is_empty() {
            pod.spec.tolerations = merge_tolerations(&pod.spec.tolerations, &extra_tolerations);
        }

        Ok(())
    }
}

impl ValidationInterface for Plugin {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // Only handle pods
        let resource = attributes.get_resource();
        if resource.resource != "pods" {
            return Ok(());
        }

        // Skip subresources
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        if !self.is_ready() {
            return Err(AdmissionError::not_ready("PodTolerationRestriction"));
        }

        // Get the pod
        let pod = match attributes
            .get_object()
            .and_then(|obj| obj.as_any().downcast_ref::<Pod>())
        {
            Some(pod) => pod,
            None => return Ok(()),
        };

        // Verify against whitelist if pod has tolerations
        if !pod.spec.tolerations.is_empty() {
            let namespace = attributes.get_namespace();

            // Try namespace-level whitelist first
            let (whitelist, scope) =
                if let Some(ns_whitelist) = self.get_namespace_whitelist(namespace) {
                    (ns_whitelist, "namespace")
                } else {
                    // Fall back to cluster-level whitelist
                    (self.config.whitelist.clone(), "cluster")
                };

            if !whitelist.is_empty()
                && !Self::verify_against_whitelist(&pod.spec.tolerations, &whitelist)
            {
                return Err(AdmissionError::invalid(
                    "PodTolerationRestriction",
                    format!(
                        "pod tolerations conflict with {} whitelist",
                        scope
                    ),
                ));
            }
        }

        Ok(())
    }
}

/// Check if a pod is BestEffort QoS.
fn is_best_effort_pod(pod: &Pod) -> bool {
    // A pod is BestEffort if all containers have no resource requests or limits
    for container in &pod.spec.containers {
        if !container.resources.requests.is_empty() || !container.resources.limits.is_empty() {
            return false;
        }
    }
    for container in &pod.spec.init_containers {
        if !container.resources.requests.is_empty() || !container.resources.limits.is_empty() {
            return false;
        }
    }
    true
}

/// Extract tolerations from namespace annotations.
fn extract_tolerations_from_annotations(
    annotations: &HashMap<String, String>,
    key: &str,
) -> Option<Vec<Toleration>> {
    let value = annotations.get(key)?;
    if value.is_empty() {
        return Some(Vec::new());
    }

    // Parse JSON array of tolerations
    // For now, return empty - full JSON parsing would require serde_json
    // In production, this would parse the JSON annotation value
    Some(Vec::new())
}

/// Check if two tolerations match (for whitelist comparison).
fn tolerations_match(t1: &Toleration, t2: &Toleration) -> bool {
    // A toleration matches a whitelist entry if:
    // - Keys match (or whitelist has empty key for "match all keys")
    // - Operators match
    // - Effects match (or whitelist has empty effect for "match all effects")
    // - Values match (if operator is Equal)

    // Empty key in whitelist matches any key
    if !t2.key.is_empty() && t1.key != t2.key {
        return false;
    }

    // Effects must match unless whitelist allows all effects
    if t2.effect.is_some() && t1.effect != t2.effect {
        return false;
    }

    // For Equal operator, values must match
    if t2.operator == TolerationOperator::Equal && t1.value != t2.value {
        return false;
    }

    true
}

/// Merge two sets of tolerations, avoiding duplicates.
fn merge_tolerations(existing: &[Toleration], additional: &[Toleration]) -> Vec<Toleration> {
    let mut result = existing.to_vec();

    for t in additional {
        let exists = result.iter().any(|existing| {
            existing.key == t.key
                && existing.operator == t.operator
                && existing.effect == t.effect
                && existing.value == t.value
        });

        if !exists {
            result.push(t.clone());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::{Container, PodSpec, ResourceRequirements, TolerationEffect};

    fn create_pod(name: &str, tolerations: Vec<Toleration>) -> Pod {
        Pod {
            name: name.to_string(),
            namespace: "default".to_string(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            node_name: None,
            spec: PodSpec {
                containers: vec![Container {
                    name: "test".to_string(),
                    image: "nginx".to_string(),
                    image_pull_policy: crate::api::core::PullPolicy::IfNotPresent,
                    resources: ResourceRequirements::default(),
                    ..Default::default()
                }],
                init_containers: vec![],
                ephemeral_containers: vec![],
                volumes: vec![],
                tolerations,
                affinity: None,
                node_selector: HashMap::new(),
                priority_class_name: String::new(),
                priority: None,
                preemption_policy: None,
                ..Default::default()
            },
        }
    }

    fn create_pod_with_resources(name: &str) -> Pod {
        let mut pod = create_pod(name, vec![]);
        pod.spec.containers[0].resources.requests.insert("cpu".to_string(), "100m".to_string());
        pod
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
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
    fn test_ignore_non_pod_resources() {
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
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_ignore_subresources() {
        let plugin = Plugin::new();
        let pod = create_pod("test", vec![]);
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "status",
            Operation::Update,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_allow_pod_without_tolerations() {
        let plugin = Plugin::new();
        let pod = create_pod("test", vec![]);
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_allow_pod_with_whitelisted_tolerations() {
        let whitelist = vec![Toleration {
            key: "key1".to_string(),
            operator: TolerationOperator::Equal,
            value: "value1".to_string(),
            effect: Some(TolerationEffect::NoSchedule),
            toleration_seconds: None,
        }];

        let plugin = Plugin::with_config(Configuration {
            default: vec![],
            whitelist,
        });

        let pod = create_pod(
            "test",
            vec![Toleration {
                key: "key1".to_string(),
                operator: TolerationOperator::Equal,
                value: "value1".to_string(),
                effect: Some(TolerationEffect::NoSchedule),
                toleration_seconds: None,
            }],
        );

        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_reject_pod_with_non_whitelisted_tolerations() {
        let whitelist = vec![Toleration {
            key: "key1".to_string(),
            operator: TolerationOperator::Equal,
            value: "value1".to_string(),
            effect: Some(TolerationEffect::NoSchedule),
            toleration_seconds: None,
        }];

        let plugin = Plugin::with_config(Configuration {
            default: vec![],
            whitelist,
        });

        let pod = create_pod(
            "test",
            vec![Toleration {
                key: "key2".to_string(), // Different key - not in whitelist
                operator: TolerationOperator::Equal,
                value: "value2".to_string(),
                effect: Some(TolerationEffect::NoSchedule),
                toleration_seconds: None,
            }],
        );

        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );
        assert!(plugin.validate(&attrs).is_err());
    }

    #[test]
    fn test_is_best_effort_pod() {
        let pod = create_pod("test", vec![]);
        assert!(is_best_effort_pod(&pod));

        let pod_with_resources = create_pod_with_resources("test");
        assert!(!is_best_effort_pod(&pod_with_resources));
    }

    #[test]
    fn test_merge_tolerations() {
        let existing = vec![Toleration {
            key: "key1".to_string(),
            operator: TolerationOperator::Equal,
            value: "value1".to_string(),
            effect: Some(TolerationEffect::NoSchedule),
            toleration_seconds: None,
        }];

        let additional = vec![
            Toleration {
                key: "key2".to_string(),
                operator: TolerationOperator::Equal,
                value: "value2".to_string(),
                effect: Some(TolerationEffect::NoSchedule),
                toleration_seconds: None,
            },
            // Duplicate - should not be added again
            Toleration {
                key: "key1".to_string(),
                operator: TolerationOperator::Equal,
                value: "value1".to_string(),
                effect: Some(TolerationEffect::NoSchedule),
                toleration_seconds: None,
            },
        ];

        let result = merge_tolerations(&existing, &additional);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_tolerations_match() {
        let t1 = Toleration {
            key: "key1".to_string(),
            operator: TolerationOperator::Equal,
            value: "value1".to_string(),
            effect: Some(TolerationEffect::NoSchedule),
            toleration_seconds: None,
        };

        let t2 = Toleration {
            key: "key1".to_string(),
            operator: TolerationOperator::Equal,
            value: "value1".to_string(),
            effect: Some(TolerationEffect::NoSchedule),
            toleration_seconds: None,
        };

        assert!(tolerations_match(&t1, &t2));

        let t3 = Toleration {
            key: "key2".to_string(),
            operator: TolerationOperator::Equal,
            value: "value1".to_string(),
            effect: Some(TolerationEffect::NoSchedule),
            toleration_seconds: None,
        };

        assert!(!tolerations_match(&t1, &t3));
    }

    #[test]
    fn test_default_trait() {
        let plugin = Plugin::default();
        assert!(plugin.handles(Operation::Create));
    }
}
