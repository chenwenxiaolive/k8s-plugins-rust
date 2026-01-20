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

//! Core Kubernetes API types (Pod, Container, Volume, Node, etc.)

use std::any::Any;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;

/// ResourceList is a map of resource names to quantity strings.
pub type ResourceList = HashMap<String, String>;

/// ApiObject is a trait for Kubernetes API objects that can be used in admission.
pub trait ApiObject: Send + Sync {
    /// Returns the object as Any for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Returns the object as mutable Any for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Returns the kind of this object.
    fn kind(&self) -> &str;
}

// ============================================================================
// Constants
// ============================================================================

/// Label key for hostname topology.
pub const LABEL_HOSTNAME: &str = "kubernetes.io/hostname";

/// Taint key for node not ready.
pub const TAINT_NODE_NOT_READY: &str = "node.kubernetes.io/not-ready";

/// Taint key for node unreachable.
pub const TAINT_NODE_UNREACHABLE: &str = "node.kubernetes.io/unreachable";

// ============================================================================
// Toleration Types
// ============================================================================

/// TolerationOperator represents an operator for toleration matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TolerationOperator {
    /// Exists means the key exists, regardless of value.
    #[default]
    Exists,
    /// Equal means the key/value must match exactly.
    Equal,
}

impl TolerationOperator {
    pub fn as_str(&self) -> &'static str {
        match self {
            TolerationOperator::Exists => "Exists",
            TolerationOperator::Equal => "Equal",
        }
    }
}

/// Toleration represents a toleration that a pod can have.
#[derive(Debug, Clone, PartialEq)]
pub struct Toleration {
    /// Key is the taint key that the toleration applies to.
    pub key: String,
    /// Operator represents a key's relationship to the value.
    pub operator: TolerationOperator,
    /// Value is the taint value the toleration matches to.
    pub value: String,
    /// Effect indicates the taint effect to match.
    pub effect: Option<TolerationEffect>,
    /// TolerationSeconds represents the period of time the toleration tolerates the taint.
    pub toleration_seconds: Option<i64>,
}

impl Toleration {
    /// Create a new toleration.
    pub fn new(key: &str, operator: TolerationOperator, effect: Option<TolerationEffect>) -> Self {
        Self {
            key: key.to_string(),
            operator,
            value: String::new(),
            effect,
            toleration_seconds: None,
        }
    }

    /// Create a new toleration with toleration seconds.
    pub fn with_seconds(
        key: &str,
        operator: TolerationOperator,
        effect: Option<TolerationEffect>,
        seconds: i64,
    ) -> Self {
        Self {
            key: key.to_string(),
            operator,
            value: String::new(),
            effect,
            toleration_seconds: Some(seconds),
        }
    }

    /// Check if this toleration matches a taint key and effect.
    pub fn matches_taint(&self, key: &str, effect: TolerationEffect) -> bool {
        // Empty key with Exists operator matches all taints
        if self.key.is_empty() && self.operator == TolerationOperator::Exists {
            // Empty effect matches all effects, or specific effect must match
            return self.effect.is_none() || self.effect == Some(effect);
        }

        // Key must match
        if self.key != key {
            return false;
        }

        // Effect must match (empty effect matches all)
        if let Some(ref toleration_effect) = self.effect {
            if *toleration_effect != effect {
                return false;
            }
        }

        true
    }
}

impl Default for Toleration {
    fn default() -> Self {
        Self {
            key: String::new(),
            operator: TolerationOperator::Exists,
            value: String::new(),
            effect: None,
            toleration_seconds: None,
        }
    }
}

/// TolerationEffect describes the effect of a toleration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TolerationEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}

impl TolerationEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            TolerationEffect::NoSchedule => "NoSchedule",
            TolerationEffect::PreferNoSchedule => "PreferNoSchedule",
            TolerationEffect::NoExecute => "NoExecute",
        }
    }
}

// ============================================================================
// PullPolicy
// ============================================================================

/// PullPolicy describes a policy for if/when to pull a container image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PullPolicy {
    /// Always means that kubelet always attempts to pull the latest image.
    Always,
    /// Never means that kubelet never pulls an image, but only uses a local image.
    Never,
    /// IfNotPresent means that kubelet pulls if the image isn't present on disk.
    #[default]
    IfNotPresent,
    /// Empty represents an unset pull policy (defaults to IfNotPresent in practice).
    Empty,
}

impl PullPolicy {
    /// Returns the string representation of the pull policy.
    pub fn as_str(&self) -> &'static str {
        match self {
            PullPolicy::Always => "Always",
            PullPolicy::Never => "Never",
            PullPolicy::IfNotPresent => "IfNotPresent",
            PullPolicy::Empty => "",
        }
    }

    /// Parse a pull policy from a string.
    pub fn from_str(s: &str) -> Self {
        match s {
            "Always" => PullPolicy::Always,
            "Never" => PullPolicy::Never,
            "IfNotPresent" => PullPolicy::IfNotPresent,
            "" => PullPolicy::Empty,
            _ => PullPolicy::Empty,
        }
    }
}

impl fmt::Display for PullPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Resource Types
// ============================================================================

/// ResourceRequirements describes the compute resource requirements.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResourceRequirements {
    /// Requests describes the minimum amount of compute resources required.
    pub requests: std::collections::HashMap<String, String>,
    /// Limits describes the maximum amount of compute resources allowed.
    pub limits: std::collections::HashMap<String, String>,
}

/// Check if a resource name is an extended resource name.
/// Extended resources are resources that are not built-in (cpu, memory, etc.)
pub fn is_extended_resource_name(name: &str) -> bool {
    // Extended resources must contain a '/' and not be in the kubernetes.io namespace
    if !name.contains('/') {
        return false;
    }
    // Standard resources prefixes that are not extended resources
    let standard_prefixes = [
        "kubernetes.io/",
        "requests.cpu",
        "requests.memory",
        "limits.cpu",
        "limits.memory",
        "hugepages-",
        "attachable-volumes-",
    ];
    for prefix in &standard_prefixes {
        if name.starts_with(prefix) {
            return false;
        }
    }
    true
}

// ============================================================================
// Container
// ============================================================================

/// Container represents a single container in a pod.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Container {
    /// Name of the container.
    pub name: String,
    /// Container image name.
    pub image: String,
    /// Image pull policy.
    pub image_pull_policy: PullPolicy,
    /// Compute Resources required by this container.
    pub resources: ResourceRequirements,
}

impl Container {
    /// Create a new container with the given name and image.
    pub fn new(name: &str, image: &str) -> Self {
        Self {
            name: name.to_string(),
            image: image.to_string(),
            image_pull_policy: PullPolicy::Empty,
            resources: ResourceRequirements::default(),
        }
    }

    /// Create a new container with a specific pull policy.
    pub fn with_pull_policy(name: &str, image: &str, policy: PullPolicy) -> Self {
        Self {
            name: name.to_string(),
            image: image.to_string(),
            image_pull_policy: policy,
            resources: ResourceRequirements::default(),
        }
    }
}

// ============================================================================
// Volume Types
// ============================================================================

/// ImageVolumeSource represents a volume that is backed by an image.
/// KEP-4639: https://kep.k8s.io/4639
#[derive(Debug, Clone, PartialEq)]
pub struct ImageVolumeSource {
    /// The image reference.
    pub reference: String,
    /// Image pull policy.
    pub pull_policy: PullPolicy,
}

impl ImageVolumeSource {
    /// Create a new image volume source.
    pub fn new(reference: &str, pull_policy: PullPolicy) -> Self {
        Self {
            reference: reference.to_string(),
            pull_policy,
        }
    }
}

/// VolumeSource represents the source of a volume.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VolumeSource {
    /// Image volume source (KEP-4639).
    pub image: Option<ImageVolumeSource>,
}

/// Volume represents a volume in a pod.
#[derive(Debug, Clone, PartialEq)]
pub struct Volume {
    /// Name of the volume.
    pub name: String,
    /// Volume source.
    pub volume_source: VolumeSource,
}

impl Volume {
    /// Create a new volume with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            volume_source: VolumeSource::default(),
        }
    }

    /// Create a new image volume.
    pub fn new_image(name: &str, image_source: ImageVolumeSource) -> Self {
        Self {
            name: name.to_string(),
            volume_source: VolumeSource {
                image: Some(image_source),
            },
        }
    }
}

// ============================================================================
// Affinity Types
// ============================================================================

/// LabelSelectorOperator represents an operator for label selector requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelSelectorOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

/// LabelSelectorRequirement is a selector that contains values, a key, and an operator.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: LabelSelectorOperator,
    pub values: Vec<String>,
}

/// LabelSelector is a label query over a set of resources.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LabelSelector {
    pub match_labels: std::collections::HashMap<String, String>,
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

/// PodAffinityTerm defines a set of pods for affinity/anti-affinity.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PodAffinityTerm {
    pub label_selector: Option<LabelSelector>,
    pub topology_key: String,
    pub namespaces: Vec<String>,
}

/// WeightedPodAffinityTerm is a weighted pod affinity term.
#[derive(Debug, Clone, PartialEq)]
pub struct WeightedPodAffinityTerm {
    pub weight: i32,
    pub pod_affinity_term: PodAffinityTerm,
}

/// PodAntiAffinity describes pod anti-affinity scheduling rules.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PodAntiAffinity {
    pub required_during_scheduling_ignored_during_execution: Vec<PodAffinityTerm>,
    pub preferred_during_scheduling_ignored_during_execution: Vec<WeightedPodAffinityTerm>,
}

/// PodAffinity describes pod affinity scheduling rules.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PodAffinity {
    pub required_during_scheduling_ignored_during_execution: Vec<PodAffinityTerm>,
    pub preferred_during_scheduling_ignored_during_execution: Vec<WeightedPodAffinityTerm>,
}

/// Affinity groups all affinity scheduling rules.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Affinity {
    pub pod_affinity: Option<PodAffinity>,
    pub pod_anti_affinity: Option<PodAntiAffinity>,
}

// ============================================================================
// PodSpec
// ============================================================================

/// PodSpec describes the specification of a pod.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PodSpec {
    /// List of initialization containers.
    pub init_containers: Vec<Container>,
    /// List of containers.
    pub containers: Vec<Container>,
    /// List of ephemeral containers.
    pub ephemeral_containers: Vec<Container>,
    /// List of volumes.
    pub volumes: Vec<Volume>,
    /// Affinity scheduling rules.
    pub affinity: Option<Affinity>,
    /// List of tolerations.
    pub tolerations: Vec<Toleration>,
    /// NodeSelector is a selector which must be true for the pod to fit on a node.
    pub node_selector: HashMap<String, String>,
}

impl PodSpec {
    /// Create a new empty PodSpec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Visit all containers with their field paths.
    pub fn visit_containers_with_path<F>(&self, base_path: &str, mut visitor: F) -> bool
    where
        F: FnMut(&Container, String) -> bool,
    {
        for (i, c) in self.init_containers.iter().enumerate() {
            let path = format!("{}.initContainers[{}]", base_path, i);
            if !visitor(c, path) {
                return false;
            }
        }
        for (i, c) in self.containers.iter().enumerate() {
            let path = format!("{}.containers[{}]", base_path, i);
            if !visitor(c, path) {
                return false;
            }
        }
        for (i, c) in self.ephemeral_containers.iter().enumerate() {
            let path = format!("{}.ephemeralContainers[{}]", base_path, i);
            if !visitor(c, path) {
                return false;
            }
        }
        true
    }

    /// Visit all containers mutably with their field paths.
    pub fn visit_containers_with_path_mut<F>(&mut self, base_path: &str, mut visitor: F) -> bool
    where
        F: FnMut(&mut Container, String) -> bool,
    {
        for (i, c) in self.init_containers.iter_mut().enumerate() {
            let path = format!("{}.initContainers[{}]", base_path, i);
            if !visitor(c, path) {
                return false;
            }
        }
        for (i, c) in self.containers.iter_mut().enumerate() {
            let path = format!("{}.containers[{}]", base_path, i);
            if !visitor(c, path) {
                return false;
            }
        }
        for (i, c) in self.ephemeral_containers.iter_mut().enumerate() {
            let path = format!("{}.ephemeralContainers[{}]", base_path, i);
            if !visitor(c, path) {
                return false;
            }
        }
        true
    }

    /// Get all container images as a set.
    pub fn get_all_images(&self) -> HashSet<String> {
        let mut images = HashSet::new();
        for c in &self.init_containers {
            images.insert(c.image.clone());
        }
        for c in &self.containers {
            images.insert(c.image.clone());
        }
        for c in &self.ephemeral_containers {
            images.insert(c.image.clone());
        }
        images
    }
}

// ============================================================================
// Pod
// ============================================================================

/// Pod represents a Kubernetes Pod.
#[derive(Debug, Clone, PartialEq)]
pub struct Pod {
    /// Name of the pod.
    pub name: String,
    /// Namespace of the pod.
    pub namespace: String,
    /// Pod specification.
    pub spec: PodSpec,
    /// Annotations is an unstructured key value map.
    pub annotations: std::collections::HashMap<String, String>,
}

impl Pod {
    /// Create a new pod with the given name and namespace.
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            spec: PodSpec::default(),
            annotations: std::collections::HashMap::new(),
        }
    }
}

impl ApiObject for Pod {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "Pod"
    }
}

// ============================================================================
// Node Types
// ============================================================================

/// TaintEffect describes the effect of a taint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}

impl TaintEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaintEffect::NoSchedule => "NoSchedule",
            TaintEffect::PreferNoSchedule => "PreferNoSchedule",
            TaintEffect::NoExecute => "NoExecute",
        }
    }
}

/// Taint represents a taint on a node.
#[derive(Debug, Clone, PartialEq)]
pub struct Taint {
    pub key: String,
    pub value: String,
    pub effect: TaintEffect,
}

impl Taint {
    /// Create a new taint.
    pub fn new(key: &str, effect: TaintEffect) -> Self {
        Self {
            key: key.to_string(),
            value: String::new(),
            effect,
        }
    }

    /// Check if this taint matches another taint (by key and effect).
    pub fn matches(&self, other: &Taint) -> bool {
        self.key == other.key && self.effect == other.effect
    }
}

/// NodeSpec describes the specification of a node.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NodeSpec {
    pub taints: Vec<Taint>,
}

/// ConditionStatus represents the status of a condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

/// NodeConditionType represents the type of a node condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeConditionType {
    Ready,
    MemoryPressure,
    DiskPressure,
    PIDPressure,
    NetworkUnavailable,
}

/// NodeCondition represents a condition of a node.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeCondition {
    pub condition_type: NodeConditionType,
    pub status: ConditionStatus,
}

/// NodeStatus represents the status of a node.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NodeStatus {
    pub conditions: Vec<NodeCondition>,
}

/// Node represents a Kubernetes Node.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub name: String,
    pub spec: NodeSpec,
    pub status: NodeStatus,
}

impl Node {
    /// Create a new node with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            spec: NodeSpec::default(),
            status: NodeStatus::default(),
        }
    }

    /// Check if node has the given taint.
    pub fn has_taint(&self, taint: &Taint) -> bool {
        self.spec.taints.iter().any(|t| t.matches(taint))
    }

    /// Add a taint to the node if it doesn't already exist.
    pub fn add_taint(&mut self, taint: Taint) {
        if !self.has_taint(&taint) {
            self.spec.taints.push(taint);
        }
    }
}

impl ApiObject for Node {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "Node"
    }
}

// ============================================================================
// Namespace
// ============================================================================

/// Namespace represents a Kubernetes Namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct Namespace {
    pub name: String,
}

impl Namespace {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl ApiObject for Namespace {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "Namespace"
    }
}

// ============================================================================
// Service
// ============================================================================

/// Service represents a Kubernetes Service (for testing non-pod resources).
#[derive(Debug, Clone, PartialEq)]
pub struct Service {
    pub name: String,
    pub namespace: String,
    pub spec: ServiceSpec,
}

impl Service {
    /// Create a new service with the given name and namespace.
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            spec: ServiceSpec::default(),
        }
    }

    /// Create a new service with external IPs.
    pub fn with_external_ips(name: &str, namespace: &str, external_ips: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            spec: ServiceSpec { external_ips },
        }
    }
}

/// ServiceSpec represents the specification of a service.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceSpec {
    /// List of external IPs.
    pub external_ips: Vec<String>,
}

impl ApiObject for Service {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "Service"
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper to create a core API resource GroupResource.
pub fn resource(name: &str) -> crate::admission::attributes::GroupResource {
    crate::admission::attributes::GroupResource::new("", name)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pull_policy() {
        assert_eq!(PullPolicy::Always.as_str(), "Always");
        assert_eq!(PullPolicy::Never.as_str(), "Never");
        assert_eq!(PullPolicy::IfNotPresent.as_str(), "IfNotPresent");
        assert_eq!(PullPolicy::Empty.as_str(), "");

        assert_eq!(PullPolicy::from_str("Always"), PullPolicy::Always);
        assert_eq!(PullPolicy::from_str("Never"), PullPolicy::Never);
        assert_eq!(PullPolicy::from_str("IfNotPresent"), PullPolicy::IfNotPresent);
        assert_eq!(PullPolicy::from_str(""), PullPolicy::Empty);
    }

    #[test]
    fn test_container() {
        let container = Container::new("test", "nginx:latest");
        assert_eq!(container.name, "test");
        assert_eq!(container.image, "nginx:latest");
        assert_eq!(container.image_pull_policy, PullPolicy::Empty);

        let container = Container::with_pull_policy("test", "nginx:latest", PullPolicy::Always);
        assert_eq!(container.image_pull_policy, PullPolicy::Always);
    }

    #[test]
    fn test_pod_spec_visit_containers() {
        let spec = PodSpec {
            node_selector: std::collections::HashMap::new(),
            init_containers: vec![Container::new("init1", "busybox")],
            containers: vec![
                Container::new("main1", "nginx"),
                Container::new("main2", "redis"),
            ],
            ephemeral_containers: vec![],
            volumes: vec![],
            affinity: None,
            tolerations: vec![],
        };

        let mut visited = vec![];
        spec.visit_containers_with_path("spec", |c, path| {
            visited.push((c.name.clone(), path));
            true
        });

        assert_eq!(visited.len(), 3);
        assert_eq!(visited[0], ("init1".to_string(), "spec.initContainers[0]".to_string()));
        assert_eq!(visited[1], ("main1".to_string(), "spec.containers[0]".to_string()));
        assert_eq!(visited[2], ("main2".to_string(), "spec.containers[1]".to_string()));
    }

    #[test]
    fn test_pod_spec_visit_containers_short_circuit() {
        let spec = PodSpec {
            node_selector: std::collections::HashMap::new(),
            init_containers: vec![],
            containers: vec![
                Container::new("main1", "nginx"),
                Container::new("main2", "redis"),
            ],
            ephemeral_containers: vec![],
            volumes: vec![],
            affinity: None,
            tolerations: vec![],
        };

        let mut count = 0;
        let result = spec.visit_containers_with_path("spec", |_, _| {
            count += 1;
            false // Stop after first
        });

        assert!(!result);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_pod_as_api_object() {
        let pod = Pod::new("test", "default");
        let obj: &dyn ApiObject = &pod;
        assert_eq!(obj.kind(), "Pod");

        let downcast = obj.as_any().downcast_ref::<Pod>();
        assert!(downcast.is_some());
        assert_eq!(downcast.unwrap().name, "test");
    }

    #[test]
    fn test_image_volume() {
        let vol = Volume::new_image(
            "my-image-vol",
            ImageVolumeSource::new("nginx:latest", PullPolicy::Never),
        );
        assert_eq!(vol.name, "my-image-vol");
        assert!(vol.volume_source.image.is_some());
        assert_eq!(vol.volume_source.image.unwrap().pull_policy, PullPolicy::Never);
    }

    #[test]
    fn test_node_taints() {
        let mut node = Node::new("test-node");
        let taint = Taint::new(TAINT_NODE_NOT_READY, TaintEffect::NoSchedule);

        assert!(!node.has_taint(&taint));

        node.add_taint(taint.clone());
        assert!(node.has_taint(&taint));
        assert_eq!(node.spec.taints.len(), 1);

        // Adding same taint again shouldn't duplicate
        node.add_taint(taint.clone());
        assert_eq!(node.spec.taints.len(), 1);
    }

    #[test]
    fn test_affinity() {
        let affinity = Affinity {
            pod_anti_affinity: Some(PodAntiAffinity {
                required_during_scheduling_ignored_during_execution: vec![
                    PodAffinityTerm {
                        topology_key: LABEL_HOSTNAME.to_string(),
                        ..Default::default()
                    }
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        let anti_affinity = affinity.pod_anti_affinity.as_ref().unwrap();
        assert_eq!(anti_affinity.required_during_scheduling_ignored_during_execution.len(), 1);
        assert_eq!(
            anti_affinity.required_during_scheduling_ignored_during_execution[0].topology_key,
            LABEL_HOSTNAME
        );
    }
}
