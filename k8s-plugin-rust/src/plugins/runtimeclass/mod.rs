// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! RuntimeClass admission controller.
//!
//! This admission controller modifies and validates new Pods to take RuntimeClass into account.
//! For RuntimeClass definitions which describe an overhead associated with running a pod,
//! this admission controller will set the pod.Spec.Overhead field accordingly.
//!
//! This field should only be set through this controller, so validation will be carried out
//! to ensure the pod's value matches what is defined in the corresponding RuntimeClass.
//!
//! The controller also handles scheduling constraints (nodeSelector and tolerations) defined
//! in the RuntimeClass.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins, ValidationInterface,
};
use crate::api::core::{ApiObject, Pod, ResourceList, Toleration};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

/// Plugin name for RuntimeClass admission controller.
pub const PLUGIN_NAME: &str = "RuntimeClass";

/// Register the RuntimeClass plugin.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

// ============================================================================
// RuntimeClass Types
// ============================================================================

/// Overhead structure associated with running a pod.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Overhead {
    /// PodFixed represents the fixed resource overhead associated with running a pod.
    pub pod_fixed: ResourceList,
}

impl Overhead {
    /// Create a new Overhead with the given pod fixed resources.
    pub fn new(pod_fixed: ResourceList) -> Self {
        Self { pod_fixed }
    }
}

/// Scheduling holds the scheduling constraints to ensure pods running with this
/// RuntimeClass are scheduled to nodes that support it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Scheduling {
    /// NodeSelector lists labels that must be present on nodes that support this
    /// RuntimeClass. Pods using this RuntimeClass can only be scheduled to a
    /// node matched by this selector.
    pub node_selector: HashMap<String, String>,
    /// Tolerations are appended (excluding duplicates) to pods running with this
    /// RuntimeClass during admission, effectively unioning the set of nodes
    /// tolerated by the pod and the RuntimeClass.
    pub tolerations: Vec<Toleration>,
}

impl Scheduling {
    /// Create a new Scheduling with node selector.
    pub fn with_node_selector(node_selector: HashMap<String, String>) -> Self {
        Self {
            node_selector,
            tolerations: Vec::new(),
        }
    }

    /// Create a new Scheduling with tolerations.
    pub fn with_tolerations(tolerations: Vec<Toleration>) -> Self {
        Self {
            node_selector: HashMap::new(),
            tolerations,
        }
    }
}

/// RuntimeClass defines a class of container runtime supported in the cluster.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeClass {
    /// Name is the metadata name of this RuntimeClass.
    pub name: String,
    /// Handler specifies the underlying runtime and configuration that the CRI
    /// implementation will use to handle pods of this class.
    pub handler: String,
    /// Overhead represents the resource overhead associated with running a pod
    /// for the given RuntimeClass.
    pub overhead: Option<Overhead>,
    /// Scheduling holds the scheduling constraints to ensure pods running with
    /// this RuntimeClass are scheduled to nodes that support it.
    pub scheduling: Option<Scheduling>,
}

impl RuntimeClass {
    /// Create a new RuntimeClass with just a name and handler.
    pub fn new(name: &str, handler: &str) -> Self {
        Self {
            name: name.to_string(),
            handler: handler.to_string(),
            overhead: None,
            scheduling: None,
        }
    }

    /// Create a new RuntimeClass with overhead.
    pub fn with_overhead(name: &str, handler: &str, overhead: Overhead) -> Self {
        Self {
            name: name.to_string(),
            handler: handler.to_string(),
            overhead: Some(overhead),
            scheduling: None,
        }
    }

    /// Create a new RuntimeClass with scheduling.
    pub fn with_scheduling(name: &str, handler: &str, scheduling: Scheduling) -> Self {
        Self {
            name: name.to_string(),
            handler: handler.to_string(),
            overhead: None,
            scheduling: Some(scheduling),
        }
    }

    /// Add scheduling constraints to this RuntimeClass.
    pub fn set_scheduling(mut self, scheduling: Scheduling) -> Self {
        self.scheduling = Some(scheduling);
        self
    }

    /// Add overhead to this RuntimeClass.
    pub fn set_overhead(mut self, overhead: Overhead) -> Self {
        self.overhead = Some(overhead);
        self
    }
}

impl ApiObject for RuntimeClass {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "RuntimeClass"
    }
}

// ============================================================================
// RuntimeClass Lister
// ============================================================================

/// Trait for RuntimeClass lister operations.
pub trait RuntimeClassLister: Send + Sync {
    /// Get a RuntimeClass by name from the cache/lister.
    fn get(&self, name: &str) -> Option<RuntimeClass>;
}

/// Trait for RuntimeClass client operations (live lookups).
pub trait RuntimeClassClient: Send + Sync {
    /// Get a RuntimeClass by name from the API server.
    fn get(&self, name: &str) -> Result<Option<RuntimeClass>, String>;
}

/// In-memory RuntimeClass store for testing.
#[derive(Debug, Default)]
pub struct InMemoryRuntimeClassStore {
    classes: RwLock<HashMap<String, RuntimeClass>>,
}

impl InMemoryRuntimeClassStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, rc: RuntimeClass) {
        self.classes.write().expect("runtime class store lock poisoned").insert(rc.name.clone(), rc);
    }
}

impl RuntimeClassLister for InMemoryRuntimeClassStore {
    fn get(&self, name: &str) -> Option<RuntimeClass> {
        self.classes.read().expect("runtime class store lock poisoned").get(name).cloned()
    }
}

impl RuntimeClassClient for InMemoryRuntimeClassStore {
    fn get(&self, name: &str) -> Result<Option<RuntimeClass>, String> {
        Ok(self.classes.read().expect("runtime class store lock poisoned").get(name).cloned())
    }
}

// ============================================================================
// Pod Extension for RuntimeClass
// ============================================================================

/// PodRuntimeClassInfo holds RuntimeClass-related pod information.
/// In a real implementation, these would be part of the Pod struct.
/// For this implementation, we use a separate storage mechanism.
#[derive(Debug, Clone, Default)]
pub struct PodRuntimeClassInfo {
    /// The name of the RuntimeClass for this pod.
    pub runtime_class_name: Option<String>,
    /// Resource overhead associated with running the pod.
    pub overhead: Option<ResourceList>,
}

// ============================================================================
// Plugin Implementation
// ============================================================================

/// RuntimeClass admission controller plugin.
pub struct Plugin {
    handler: Handler,
    lister: Option<Arc<dyn RuntimeClassLister>>,
    client: Option<Arc<dyn RuntimeClassClient>>,
    #[allow(dead_code)]
    ready: RwLock<bool>,
}

impl Plugin {
    /// Create a new RuntimeClass admission controller.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            lister: None,
            client: None,
            ready: RwLock::new(true),
        }
    }

    /// Create a new RuntimeClass admission controller with a lister.
    pub fn with_lister(lister: Arc<dyn RuntimeClassLister>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            lister: Some(lister),
            client: None,
            ready: RwLock::new(true),
        }
    }

    /// Create a new RuntimeClass admission controller with both lister and client.
    pub fn with_lister_and_client(
        lister: Arc<dyn RuntimeClassLister>,
        client: Arc<dyn RuntimeClassClient>,
    ) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            lister: Some(lister),
            client: Some(client),
            ready: RwLock::new(true),
        }
    }

    /// Validate that the plugin is properly initialized.
    pub fn validate_initialization(&self) -> Result<(), String> {
        if self.lister.is_none() {
            return Err("missing RuntimeClass lister".to_string());
        }
        if self.client.is_none() {
            return Err("missing RuntimeClass client".to_string());
        }
        Ok(())
    }

    /// Check if this request should be ignored.
    fn should_ignore(&self, attributes: &dyn Attributes) -> bool {
        // Ignore all calls to subresources or resources other than pods
        if !attributes.get_subresource().is_empty() {
            return true;
        }
        let resource = attributes.get_resource();
        resource.resource != "pods"
    }

    /// Get RuntimeClass by name, trying lister first, then client.
    fn get_runtime_class(&self, name: &str) -> Result<Option<RuntimeClass>, AdmissionError> {
        // Try lister first
        if let Some(lister) = &self.lister {
            if let Some(rc) = lister.get(name) {
                return Ok(Some(rc));
            }
        }

        // If not found in lister, try client (informer cache might be lagging)
        if let Some(client) = &self.client {
            match client.get(name) {
                Ok(rc) => return Ok(rc),
                Err(e) => return Err(AdmissionError::internal_error(e)),
            }
        }

        // If we have a lister but no client, and lister didn't find it
        if self.lister.is_some() {
            return Ok(None);
        }

        // No lister or client configured
        Ok(None)
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
        if self.should_ignore(attributes) {
            return Ok(());
        }

        // Get the runtime class name from the pod before mutable borrow
        let runtime_class_name = {
            let obj = match attributes.get_object() {
                Some(o) => o,
                None => return Err(AdmissionError::bad_request(
                    "Resource was marked with kind Pod but was unable to be converted",
                )),
            };

            let pod = match obj.as_any().downcast_ref::<Pod>() {
                Some(p) => p,
                None => return Err(AdmissionError::bad_request(
                    "Resource was marked with kind Pod but was unable to be converted",
                )),
            };

            // Check if pod has a RuntimeClassName annotation (simulating spec.runtimeClassName)
            pod.annotations.get("spec.runtimeClassName").cloned()
        };

        // If no RuntimeClassName, nothing to do
        let rc_name = match runtime_class_name {
            Some(name) if !name.is_empty() => name,
            _ => return Ok(()),
        };

        // Get the RuntimeClass
        let runtime_class = match self.get_runtime_class(&rc_name)? {
            Some(rc) => rc,
            None => {
                return Err(AdmissionError::bad_request(format!(
                    "pod rejected: RuntimeClass \"{}\" not found",
                    rc_name
                )));
            }
        };

        // Now get mutable access to set overhead and scheduling
        let obj = match attributes.get_object_mut() {
            Some(o) => o,
            None => return Err(AdmissionError::bad_request(
                "Resource was marked with kind Pod but was unable to be converted",
            )),
        };

        let pod = match obj.as_any_mut().downcast_mut::<Pod>() {
            Some(p) => p,
            None => return Err(AdmissionError::bad_request(
                "Resource was marked with kind Pod but was unable to be converted",
            )),
        };

        // Set overhead
        set_overhead(pod, &runtime_class)?;

        // Set scheduling
        set_scheduling(pod, &runtime_class)?;

        Ok(())
    }
}

impl ValidationInterface for Plugin {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        if self.should_ignore(attributes) {
            return Ok(());
        }

        let obj = match attributes.get_object() {
            Some(o) => o,
            None => return Err(AdmissionError::bad_request(
                "Resource was marked with kind Pod but was unable to be converted",
            )),
        };

        let pod = match obj.as_any().downcast_ref::<Pod>() {
            Some(p) => p,
            None => return Err(AdmissionError::bad_request(
                "Resource was marked with kind Pod but was unable to be converted",
            )),
        };

        // Get RuntimeClassName from annotations
        let runtime_class_name = pod.annotations.get("spec.runtimeClassName").cloned();

        // Get RuntimeClass if specified
        let runtime_class = match &runtime_class_name {
            Some(name) if !name.is_empty() => {
                match self.get_runtime_class(name)? {
                    Some(rc) => Some(rc),
                    None => {
                        return Err(AdmissionError::bad_request(format!(
                            "pod rejected: RuntimeClass \"{}\" not found",
                            name
                        )));
                    }
                }
            }
            _ => None,
        };

        // Validate overhead
        validate_overhead(pod, runtime_class.as_ref())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Set overhead on the pod from the RuntimeClass.
fn set_overhead(pod: &mut Pod, runtime_class: &RuntimeClass) -> AdmissionResult<()> {
    let overhead = match &runtime_class.overhead {
        Some(o) => o,
        None => return Ok(()),
    };

    // Get current pod overhead from annotations (simulating spec.overhead)
    let pod_overhead = get_pod_overhead(pod);

    // If pod already has overhead set, check if it matches
    if !pod_overhead.is_empty()
        && !resource_lists_equal(&pod_overhead, &overhead.pod_fixed) {
            return Err(AdmissionError::bad_request(
                "pod rejected: Pod's Overhead doesn't match RuntimeClass's defined Overhead",
            ));
        }

    // Set the overhead on the pod
    set_pod_overhead(pod, &overhead.pod_fixed);

    Ok(())
}

/// Set scheduling constraints on the pod from the RuntimeClass.
fn set_scheduling(pod: &mut Pod, runtime_class: &RuntimeClass) -> AdmissionResult<()> {
    let scheduling = match &runtime_class.scheduling {
        Some(s) => s,
        None => return Ok(()),
    };

    // Handle node selector
    let runtime_node_selector = &scheduling.node_selector;

    if pod.spec.node_selector.is_empty() {
        // Pod has no node selector, use RuntimeClass's
        pod.spec.node_selector = runtime_node_selector.clone();
    } else {
        // Merge node selectors, checking for conflicts
        for (key, runtime_value) in runtime_node_selector {
            if let Some(pod_value) = pod.spec.node_selector.get(key) {
                if pod_value != runtime_value {
                    return Err(AdmissionError::bad_request(format!(
                        "conflict: runtimeClass.scheduling.nodeSelector[{}] = {}; pod.spec.nodeSelector[{}] = {}",
                        key, runtime_value, key, pod_value
                    )));
                }
            }
            pod.spec.node_selector.insert(key.clone(), runtime_value.clone());
        }
    }

    // Merge tolerations
    pod.spec.tolerations = merge_tolerations(&pod.spec.tolerations, &scheduling.tolerations);

    Ok(())
}

/// Validate that the pod's overhead matches the RuntimeClass's overhead.
fn validate_overhead(pod: &Pod, runtime_class: Option<&RuntimeClass>) -> AdmissionResult<()> {
    let pod_overhead = get_pod_overhead(pod);

    match runtime_class {
        Some(rc) if rc.overhead.is_some() => {
            let rc_overhead = rc.overhead.as_ref().unwrap();
            // If the overhead set doesn't match what is provided in RuntimeClass, reject
            if !resource_lists_equal(&pod_overhead, &rc_overhead.pod_fixed) {
                return Err(AdmissionError::bad_request(
                    "pod rejected: Pod's Overhead doesn't match RuntimeClass's defined Overhead",
                ));
            }
        }
        _ => {
            // If RuntimeClass with Overhead is not defined but an Overhead is set for pod, reject
            if !pod_overhead.is_empty() {
                return Err(AdmissionError::bad_request(
                    "pod rejected: Pod Overhead set without corresponding RuntimeClass defined Overhead",
                ));
            }
        }
    }

    Ok(())
}

/// Get pod overhead from annotations (simulating spec.overhead).
fn get_pod_overhead(pod: &Pod) -> ResourceList {
    let mut overhead = ResourceList::new();

    // Check for overhead annotations
    if let Some(cpu) = pod.annotations.get("spec.overhead.cpu") {
        overhead.insert("cpu".to_string(), cpu.clone());
    }
    if let Some(memory) = pod.annotations.get("spec.overhead.memory") {
        overhead.insert("memory".to_string(), memory.clone());
    }

    overhead
}

/// Set pod overhead using annotations (simulating spec.overhead).
fn set_pod_overhead(pod: &mut Pod, overhead: &ResourceList) {
    for (key, value) in overhead {
        pod.annotations.insert(format!("spec.overhead.{}", key), value.clone());
    }
}

/// Check if two resource lists are equal.
fn resource_lists_equal(a: &ResourceList, b: &ResourceList) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (key, value) in a {
        match b.get(key) {
            Some(v) if v == value => continue,
            _ => return false,
        }
    }
    true
}

/// Merge two sets of tolerations, avoiding duplicates.
fn merge_tolerations(existing: &[Toleration], additional: &[Toleration]) -> Vec<Toleration> {
    let mut result = existing.to_vec();

    for t in additional {
        let exists = result.iter().any(|existing| tolerations_equal(existing, t));
        if !exists {
            result.push(t.clone());
        }
    }

    result
}

/// Check if two tolerations are equal.
fn tolerations_equal(a: &Toleration, b: &Toleration) -> bool {
    a.key == b.key
        && a.operator == b.operator
        && a.value == b.value
        && a.effect == b.effect
        && a.toleration_seconds == b.toleration_seconds
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::{Container, ResourceRequirements, TolerationEffect, TolerationOperator};

    /// Create a pod with optional overhead set.
    fn new_overhead_valid_pod(name: &str, num_containers: usize, resources: ResourceRequirements, set_overhead: bool) -> Pod {
        let mut pod = Pod::new(name, "test");
        pod.spec.containers = (0..num_containers)
            .map(|i| Container {
                name: format!("foo-{}", i),
                image: format!("foo:V{}", i),
                image_pull_policy: crate::api::core::PullPolicy::IfNotPresent,
                resources: resources.clone(),
                security_context: None,
            })
            .collect();

        if set_overhead {
            pod.annotations.insert("spec.overhead.cpu".to_string(), "100m".to_string());
            pod.annotations.insert("spec.overhead.memory".to_string(), "1".to_string());
        }

        pod
    }

    /// Create a pod with node selector and tolerations.
    fn new_scheduling_valid_pod(
        name: &str,
        node_selector: HashMap<String, String>,
        tolerations: Vec<Toleration>,
    ) -> Pod {
        let mut pod = Pod::new(name, "test");
        pod.spec.node_selector = node_selector;
        pod.spec.tolerations = tolerations;
        pod
    }

    /// Get guaranteed resource requirements.
    fn get_guaranteed_requirements() -> ResourceRequirements {
        let mut resources = HashMap::new();
        resources.insert("cpu".to_string(), "1".to_string());
        resources.insert("memory".to_string(), "10".to_string());

        ResourceRequirements {
            limits: resources.clone(),
            requests: resources,
        }
    }

    /// Create a RuntimeClass with overhead.
    fn create_runtime_class_with_overhead(name: &str, cpu: &str, memory: &str) -> RuntimeClass {
        let mut pod_fixed = ResourceList::new();
        pod_fixed.insert("cpu".to_string(), cpu.to_string());
        pod_fixed.insert("memory".to_string(), memory.to_string());

        RuntimeClass::with_overhead(name, "bar", Overhead::new(pod_fixed))
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Create));
        assert!(!plugin.handles(Operation::Update));
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
        let mut attrs = AttributesRecord::new(
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
        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ignores_subresources() {
        let plugin = Plugin::new();
        let pod = Pod::new("test", "default");
        let mut attrs = AttributesRecord::new(
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
        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_set_overhead_no_container_requirements() {
        let rc = create_runtime_class_with_overhead("foo", "100m", "1");
        let mut pod = new_overhead_valid_pod("no-resource-req-no-overhead", 1, ResourceRequirements::default(), false);

        let result = set_overhead(&mut pod, &rc);
        assert!(result.is_ok());

        // Verify overhead was set
        assert_eq!(pod.annotations.get("spec.overhead.cpu"), Some(&"100m".to_string()));
        assert_eq!(pod.annotations.get("spec.overhead.memory"), Some(&"1".to_string()));
    }

    #[test]
    fn test_set_overhead_guaranteed_pod() {
        let rc = create_runtime_class_with_overhead("foo", "100m", "1");
        let mut pod = new_overhead_valid_pod("guaranteed", 1, get_guaranteed_requirements(), false);

        let result = set_overhead(&mut pod, &rc);
        assert!(result.is_ok());

        // Verify overhead was set
        assert_eq!(pod.annotations.get("spec.overhead.cpu"), Some(&"100m".to_string()));
        assert_eq!(pod.annotations.get("spec.overhead.memory"), Some(&"1".to_string()));
    }

    #[test]
    fn test_set_overhead_differing_overhead_already_set() {
        // RuntimeClass has different overhead than pod
        let rc = create_runtime_class_with_overhead("foo", "10", "10G");
        let mut pod = new_overhead_valid_pod("empty-requirements-overhead", 1, ResourceRequirements::default(), true);

        let result = set_overhead(&mut pod, &rc);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Pod's Overhead doesn't match"));
    }

    #[test]
    fn test_set_overhead_same_overhead_already_set() {
        // RuntimeClass has same overhead as pod
        let rc = create_runtime_class_with_overhead("foo", "100m", "1");
        let mut pod = new_overhead_valid_pod("empty-requirements-overhead", 1, ResourceRequirements::default(), true);

        let result = set_overhead(&mut pod, &rc);
        assert!(result.is_ok());
    }

    #[test]
    fn test_set_scheduling_nil_scheduling() {
        let rc = RuntimeClass::new("foo", "bar");
        let mut pod = new_scheduling_valid_pod(
            "pod-with-node-selector",
            [("foo".to_string(), "bar".to_string())].into_iter().collect(),
            vec![],
        );

        let result = set_scheduling(&mut pod, &rc);
        assert!(result.is_ok());

        // Pod should retain its original node selector
        assert_eq!(pod.spec.node_selector.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_set_scheduling_conflict_node_selector() {
        let mut rc = RuntimeClass::new("foo", "bar");
        rc.scheduling = Some(Scheduling::with_node_selector(
            [("foo".to_string(), "conflict".to_string())].into_iter().collect(),
        ));

        let mut pod = new_scheduling_valid_pod(
            "pod-with-conflict-node-selector",
            [("foo".to_string(), "bar".to_string())].into_iter().collect(),
            vec![],
        );

        let result = set_scheduling(&mut pod, &rc);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("conflict"));
    }

    #[test]
    fn test_set_scheduling_nil_node_selector() {
        let mut rc = RuntimeClass::new("foo", "bar");
        rc.scheduling = Some(Scheduling::with_node_selector(
            [("foo".to_string(), "bar".to_string())].into_iter().collect(),
        ));

        let mut pod = new_scheduling_valid_pod("pod-with-nil-node-selector", HashMap::new(), vec![]);

        let result = set_scheduling(&mut pod, &rc);
        assert!(result.is_ok());

        // Pod should have RuntimeClass's node selector
        assert_eq!(pod.spec.node_selector.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_set_scheduling_same_key_value_node_selector() {
        let mut rc = RuntimeClass::new("foo", "bar");
        rc.scheduling = Some(Scheduling::with_node_selector(
            [("foo".to_string(), "bar".to_string())].into_iter().collect(),
        ));

        let mut pod = new_scheduling_valid_pod(
            "pod-with-same-key-value",
            [("foo".to_string(), "bar".to_string())].into_iter().collect(),
            vec![],
        );

        let result = set_scheduling(&mut pod, &rc);
        assert!(result.is_ok());

        // Pod should retain its node selector (same as RC)
        assert_eq!(pod.spec.node_selector.get("foo"), Some(&"bar".to_string()));
        assert_eq!(pod.spec.node_selector.len(), 1);
    }

    #[test]
    fn test_set_scheduling_different_key_value_node_selector() {
        let mut node_selector = HashMap::new();
        node_selector.insert("foo".to_string(), "bar".to_string());
        node_selector.insert("fizz".to_string(), "buzz".to_string());

        let mut rc = RuntimeClass::new("foo", "bar");
        rc.scheduling = Some(Scheduling::with_node_selector(node_selector));

        let mut pod = new_scheduling_valid_pod(
            "pod-with-different-key-value",
            [("foo".to_string(), "bar".to_string())].into_iter().collect(),
            vec![],
        );

        let result = set_scheduling(&mut pod, &rc);
        assert!(result.is_ok());

        // Pod should have merged node selector
        assert_eq!(pod.spec.node_selector.get("foo"), Some(&"bar".to_string()));
        assert_eq!(pod.spec.node_selector.get("fizz"), Some(&"buzz".to_string()));
        assert_eq!(pod.spec.node_selector.len(), 2);
    }

    #[test]
    fn test_set_scheduling_multiple_tolerations() {
        let rc_tolerations = vec![
            Toleration {
                key: "foo".to_string(),
                operator: TolerationOperator::Equal,
                value: "bar".to_string(),
                effect: Some(TolerationEffect::NoSchedule),
                toleration_seconds: None,
            },
            Toleration {
                key: "fizz".to_string(),
                operator: TolerationOperator::Equal,
                value: "buzz".to_string(),
                effect: Some(TolerationEffect::NoSchedule),
                toleration_seconds: None,
            },
        ];

        let mut rc = RuntimeClass::new("foo", "bar");
        rc.scheduling = Some(Scheduling::with_tolerations(rc_tolerations));

        let pod_tolerations = vec![Toleration {
            key: "foo".to_string(),
            operator: TolerationOperator::Equal,
            value: "bar".to_string(),
            effect: Some(TolerationEffect::NoSchedule),
            toleration_seconds: None,
        }];

        let mut pod = new_scheduling_valid_pod(
            "pod-with-tolerations",
            [("foo".to_string(), "bar".to_string())].into_iter().collect(),
            pod_tolerations,
        );

        let result = set_scheduling(&mut pod, &rc);
        assert!(result.is_ok());

        // Pod should have 2 tolerations (merged, no duplicates)
        assert_eq!(pod.spec.tolerations.len(), 2);
        assert!(pod.spec.tolerations.iter().any(|t| t.key == "foo"));
        assert!(pod.spec.tolerations.iter().any(|t| t.key == "fizz"));
    }

    #[test]
    fn test_validate_initialization_missing_lister() {
        let plugin = Plugin::new();
        let result = plugin.validate_initialization();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("lister"));
    }

    #[test]
    fn test_validate_initialization_missing_client() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let plugin = Plugin::with_lister(store);
        let result = plugin.validate_initialization();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("client"));
    }

    #[test]
    fn test_validate_initialization_success() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let plugin = Plugin::with_lister_and_client(store.clone(), store);
        let result = plugin.validate_initialization();
        assert!(result.is_ok());
    }

    #[test]
    fn test_admit_runtime_class_found_by_lister() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let rc = RuntimeClass::new("runtimeClassName", "handler");
        store.add(rc);

        let plugin = Plugin::with_lister_and_client(store.clone(), store);

        let mut pod = Pod::new("podname", "default");
        pod.annotations.insert("spec.runtimeClassName".to_string(), "runtimeClassName".to_string());

        let mut attrs = AttributesRecord::new(
            "podname",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_admit_runtime_class_not_found() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let plugin = Plugin::with_lister_and_client(store.clone(), store);

        let mut pod = Pod::new("podname", "default");
        pod.annotations.insert("spec.runtimeClassName".to_string(), "nonexistent".to_string());

        let mut attrs = AttributesRecord::new(
            "podname",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_validate_no_overhead_in_rc_overhead_set_in_pod() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let rc = RuntimeClass::new("foo", "bar"); // No overhead
        store.add(rc);

        let plugin = Plugin::with_lister_and_client(store.clone(), store);

        let mut pod = new_overhead_valid_pod("test", 1, get_guaranteed_requirements(), true);
        pod.annotations.insert("spec.runtimeClassName".to_string(), "foo".to_string());

        let attrs = AttributesRecord::new(
            "test",
            "test",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("without corresponding RuntimeClass"));
    }

    #[test]
    fn test_validate_non_matching_overheads() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let rc = create_runtime_class_with_overhead("foo", "10", "10G");
        store.add(rc);

        let plugin = Plugin::with_lister_and_client(store.clone(), store);

        let mut pod = new_overhead_valid_pod("test", 1, ResourceRequirements::default(), true);
        pod.annotations.insert("spec.runtimeClassName".to_string(), "foo".to_string());

        let attrs = AttributesRecord::new(
            "test",
            "test",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("doesn't match"));
    }

    #[test]
    fn test_validate_matching_overheads() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let rc = create_runtime_class_with_overhead("foo", "100m", "1");
        store.add(rc);

        let plugin = Plugin::with_lister_and_client(store.clone(), store);

        let mut pod = new_overhead_valid_pod("test", 1, ResourceRequirements::default(), true);
        pod.annotations.insert("spec.runtimeClassName".to_string(), "foo".to_string());

        let attrs = AttributesRecord::new(
            "test",
            "test",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_overhead_rc_has_overhead_pod_does_not() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let rc = create_runtime_class_with_overhead("foo", "100m", "1");
        store.add(rc);

        let plugin = Plugin::with_lister_and_client(store.clone(), store);

        let mut pod = new_overhead_valid_pod("test", 1, ResourceRequirements::default(), false);
        pod.annotations.insert("spec.runtimeClassName".to_string(), "foo".to_string());

        let attrs = AttributesRecord::new(
            "test",
            "test",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("doesn't match"));
    }

    #[test]
    fn test_validate_no_runtime_class_overhead_set_in_pod() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let plugin = Plugin::with_lister_and_client(store.clone(), store);

        // Pod with overhead but no RuntimeClass specified
        let pod = new_overhead_valid_pod("test", 1, get_guaranteed_requirements(), true);

        let attrs = AttributesRecord::new(
            "test",
            "test",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("without corresponding RuntimeClass"));
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
    fn test_resource_lists_equal() {
        let mut a = ResourceList::new();
        a.insert("cpu".to_string(), "100m".to_string());
        a.insert("memory".to_string(), "1Gi".to_string());

        let mut b = ResourceList::new();
        b.insert("cpu".to_string(), "100m".to_string());
        b.insert("memory".to_string(), "1Gi".to_string());

        assert!(resource_lists_equal(&a, &b));

        let mut c = ResourceList::new();
        c.insert("cpu".to_string(), "200m".to_string());
        c.insert("memory".to_string(), "1Gi".to_string());

        assert!(!resource_lists_equal(&a, &c));

        let mut d = ResourceList::new();
        d.insert("cpu".to_string(), "100m".to_string());

        assert!(!resource_lists_equal(&a, &d));
    }

    #[test]
    fn test_default_trait() {
        let plugin = Plugin::default();
        assert!(plugin.handles(Operation::Create));
    }

    #[test]
    fn test_runtime_class_builders() {
        let rc = RuntimeClass::new("test", "handler")
            .set_overhead(Overhead::new([("cpu".to_string(), "100m".to_string())].into_iter().collect()))
            .set_scheduling(Scheduling::with_node_selector([("zone".to_string(), "us-east".to_string())].into_iter().collect()));

        assert_eq!(rc.name, "test");
        assert_eq!(rc.handler, "handler");
        assert!(rc.overhead.is_some());
        assert!(rc.scheduling.is_some());
        assert_eq!(rc.overhead.unwrap().pod_fixed.get("cpu"), Some(&"100m".to_string()));
        assert_eq!(rc.scheduling.unwrap().node_selector.get("zone"), Some(&"us-east".to_string()));
    }

    #[test]
    fn test_admits_pod_without_runtime_class() {
        let store = Arc::new(InMemoryRuntimeClassStore::new());
        let plugin = Plugin::with_lister_and_client(store.clone(), store);

        // Pod without RuntimeClassName
        let pod = Pod::new("test", "default");

        let mut attrs = AttributesRecord::new(
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

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());
    }
}
