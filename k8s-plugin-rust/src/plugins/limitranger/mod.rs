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

//! LimitRanger admission controller.
//!
//! This admission controller enforces usage limits on a per resource basis in the namespace.
//! It can set default resource requests/limits and validate that resource usage stays within
//! defined LimitRange constraints.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface,
    Operation, Plugins, ValidationInterface,
};
use crate::api::core::{ApiObject, Container, Pod, ResourceList, ResourceRequirements};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the LimitRanger admission controller.
pub const PLUGIN_NAME: &str = "LimitRanger";

/// Annotation key for limit ranger.
pub const LIMIT_RANGER_ANNOTATION: &str = "kubernetes.io/limit-ranger";

/// Register the LimitRanger plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(LimitRanger::new()) as Arc<dyn Interface>)
    });
}

/// LimitType represents the type of limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitType {
    Pod,
    Container,
    PersistentVolumeClaim,
}

/// LimitRangeItem defines a min/max usage limit for any resource.
#[derive(Debug, Clone, Default)]
pub struct LimitRangeItem {
    pub limit_type: Option<LimitType>,
    pub min: ResourceList,
    pub max: ResourceList,
    pub default: ResourceList,
    pub default_request: ResourceList,
    pub max_limit_request_ratio: ResourceList,
}

/// LimitRangeSpec defines a min/max usage limit for resources.
#[derive(Debug, Clone, Default)]
pub struct LimitRangeSpec {
    pub limits: Vec<LimitRangeItem>,
}

/// LimitRange represents a LimitRange resource.
#[derive(Debug, Clone)]
pub struct LimitRange {
    pub name: String,
    pub namespace: String,
    pub spec: LimitRangeSpec,
}

impl LimitRange {
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            spec: LimitRangeSpec::default(),
        }
    }
}

impl ApiObject for LimitRange {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "LimitRange"
    }
}

/// Trait for limit range lister.
pub trait LimitRangeLister: Send + Sync {
    fn list(&self, namespace: &str) -> Vec<LimitRange>;
}

/// In-memory limit range store for testing.
#[derive(Debug, Default)]
pub struct InMemoryLimitRangeStore {
    ranges: std::sync::RwLock<HashMap<String, Vec<LimitRange>>>,
}

impl InMemoryLimitRangeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, range: LimitRange) {
        let mut ranges = self.ranges.write().expect("limit range store lock poisoned");
        ranges
            .entry(range.namespace.clone())
            .or_default()
            .push(range);
    }
}

impl LimitRangeLister for InMemoryLimitRangeStore {
    fn list(&self, namespace: &str) -> Vec<LimitRange> {
        self.ranges
            .read()
            .expect("limit range store lock poisoned")
            .get(namespace)
            .cloned()
            .unwrap_or_default()
    }
}

/// LimitRanger enforces usage limits on a per resource basis in the namespace.
pub struct LimitRanger {
    handler: Handler,
    lister: Option<Arc<dyn LimitRangeLister>>,
}

impl LimitRanger {
    /// Create a new LimitRanger admission controller.
    pub fn new() -> Self {
        Self {
            handler: Handler::new_create_update(),
            lister: None,
        }
    }

    /// Create with a limit range lister.
    pub fn with_lister(lister: Arc<dyn LimitRangeLister>) -> Self {
        Self {
            handler: Handler::new_create_update(),
            lister: Some(lister),
        }
    }

    /// Get limit ranges for a namespace.
    pub fn get_limit_ranges(&self, namespace: &str) -> Vec<LimitRange> {
        match &self.lister {
            Some(lister) => lister.list(namespace),
            None => vec![],
        }
    }

    /// Check if this admission controller supports the given attributes.
    fn supports_attributes(&self, attributes: &dyn Attributes) -> bool {
        let subresource = attributes.get_subresource();
        let kind = attributes.get_kind();
        let operation = attributes.get_operation();

        // Handle in-place vertical scaling of pods
        if subresource == "resize" && kind.kind == "Pod" && operation == Operation::Update {
            return true;
        }

        // No other subresources are supported
        if !subresource.is_empty() {
            return false;
        }

        // Pod updates are not supported (containers are immutable)
        if kind.kind == "Pod" && operation == Operation::Update {
            return false;
        }

        kind.kind == "Pod" || kind.kind == "PersistentVolumeClaim"
    }
}

impl Default for LimitRanger {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for LimitRanger {
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl MutationInterface for LimitRanger {
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        if !self.supports_attributes(attributes) {
            return Ok(());
        }

        let namespace = attributes.get_namespace();
        let limit_ranges = self.get_limit_ranges(&namespace);

        for limit_range in &limit_ranges {
            pod_mutate_limit_func(limit_range, attributes)?;
        }

        Ok(())
    }
}

impl ValidationInterface for LimitRanger {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        if !self.supports_attributes(attributes) {
            return Ok(());
        }

        let namespace = attributes.get_namespace();
        let limit_ranges = self.get_limit_ranges(&namespace);

        for limit_range in &limit_ranges {
            pod_validate_limit_func(limit_range, attributes)?;
        }

        Ok(())
    }
}

/// Get default container resource requirements from limit range.
pub fn default_container_resource_requirements(limit_range: &LimitRange) -> ResourceRequirements {
    let mut requirements = ResourceRequirements::default();

    for limit in &limit_range.spec.limits {
        if limit.limit_type == Some(LimitType::Container) {
            // Copy default requests
            for (k, v) in &limit.default_request {
                requirements.requests.insert(k.clone(), v.clone());
            }
            // Copy default limits
            for (k, v) in &limit.default {
                requirements.limits.insert(k.clone(), v.clone());
            }
        }
    }

    requirements
}

/// Merge container resources with defaults.
fn merge_container_resources(
    container: &mut Container,
    defaults: &ResourceRequirements,
    annotation_prefix: &str,
    annotations: &mut Vec<String>,
) {
    let mut set_requests = Vec::new();
    let mut set_limits = Vec::new();

    // Set default limits
    for (k, v) in &defaults.limits {
        if !container.resources.limits.contains_key(k) {
            container.resources.limits.insert(k.clone(), v.clone());
            set_limits.push(k.clone());
        }
    }

    // Set default requests
    for (k, v) in &defaults.requests {
        if !container.resources.requests.contains_key(k) {
            container.resources.requests.insert(k.clone(), v.clone());
            set_requests.push(k.clone());
        }
    }

    if !set_requests.is_empty() {
        set_requests.sort();
        let a = format!(
            "{} request for {} {}",
            set_requests.join(", "),
            annotation_prefix,
            container.name
        );
        annotations.push(a);
    }

    if !set_limits.is_empty() {
        set_limits.sort();
        let a = format!(
            "{} limit for {} {}",
            set_limits.join(", "),
            annotation_prefix,
            container.name
        );
        annotations.push(a);
    }
}

/// Merge pod resource requirements with defaults.
pub fn merge_pod_resource_requirements(pod: &mut Pod, defaults: &ResourceRequirements) {
    let mut annotations = Vec::new();

    for container in &mut pod.spec.containers {
        merge_container_resources(container, defaults, "container", &mut annotations);
    }

    for container in &mut pod.spec.init_containers {
        merge_container_resources(container, defaults, "init container", &mut annotations);
    }

    if !annotations.is_empty() {
        let val = format!("LimitRanger plugin set: {}", annotations.join("; "));
        pod.annotations
            .insert(LIMIT_RANGER_ANNOTATION.to_string(), val);
    }
}

/// Pod mutate limit function - applies defaults from limit range.
fn pod_mutate_limit_func(
    limit_range: &LimitRange,
    attributes: &mut dyn Attributes,
) -> AdmissionResult<()> {
    let kind = attributes.get_kind();
    if kind.kind != "Pod" {
        return Ok(());
    }

    let obj = match attributes.get_object_mut() {
        Some(o) => o,
        None => return Ok(()),
    };

    let pod = match obj.as_any_mut().downcast_mut::<Pod>() {
        Some(p) => p,
        None => return Ok(()),
    };

    let defaults = default_container_resource_requirements(limit_range);
    merge_pod_resource_requirements(pod, &defaults);

    Ok(())
}

/// Validate min constraint.
fn min_constraint(
    limit_type: &str,
    resource_name: &str,
    enforced: &str,
    request: Option<&String>,
    limit: Option<&String>,
) -> Result<(), String> {
    let enforced_val = parse_quantity(enforced);

    match request {
        None => {
            return Err(format!(
                "minimum {} usage per {} is {}. No request is specified",
                resource_name, limit_type, enforced
            ));
        }
        Some(req) => {
            let req_val = parse_quantity(req);
            if req_val < enforced_val {
                return Err(format!(
                    "minimum {} usage per {} is {}, but request is {}",
                    resource_name, limit_type, enforced, req
                ));
            }
        }
    }

    if let Some(lim) = limit {
        let lim_val = parse_quantity(lim);
        if lim_val < enforced_val {
            return Err(format!(
                "minimum {} usage per {} is {}, but limit is {}",
                resource_name, limit_type, enforced, lim
            ));
        }
    }

    Ok(())
}

/// Validate max constraint.
fn max_constraint(
    limit_type: &str,
    resource_name: &str,
    enforced: &str,
    request: Option<&String>,
    limit: Option<&String>,
) -> Result<(), String> {
    let enforced_val = parse_quantity(enforced);

    match limit {
        None => {
            return Err(format!(
                "maximum {} usage per {} is {}. No limit is specified",
                resource_name, limit_type, enforced
            ));
        }
        Some(lim) => {
            let lim_val = parse_quantity(lim);
            if lim_val > enforced_val {
                return Err(format!(
                    "maximum {} usage per {} is {}, but limit is {}",
                    resource_name, limit_type, enforced, lim
                ));
            }
        }
    }

    if let Some(req) = request {
        let req_val = parse_quantity(req);
        if req_val > enforced_val {
            return Err(format!(
                "maximum {} usage per {} is {}, but request is {}",
                resource_name, limit_type, enforced, req
            ));
        }
    }

    Ok(())
}

/// Parse a quantity string to a comparable value (simplified).
fn parse_quantity(s: &str) -> i64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }

    // Handle memory units
    if let Some(num) = s.strip_suffix("Gi") {
        return num.parse::<i64>().unwrap_or(0) * 1024 * 1024 * 1024;
    }
    if let Some(num) = s.strip_suffix("Mi") {
        return num.parse::<i64>().unwrap_or(0) * 1024 * 1024;
    }
    if let Some(num) = s.strip_suffix("Ki") {
        return num.parse::<i64>().unwrap_or(0) * 1024;
    }
    if let Some(num) = s.strip_suffix('G') {
        return num.parse::<i64>().unwrap_or(0) * 1000 * 1000 * 1000;
    }
    if let Some(num) = s.strip_suffix('M') {
        return num.parse::<i64>().unwrap_or(0) * 1000 * 1000;
    }
    if let Some(num) = s.strip_suffix('K') {
        return num.parse::<i64>().unwrap_or(0) * 1000;
    }

    // Handle CPU units (millicores)
    if let Some(num) = s.strip_suffix('m') {
        return num.parse::<i64>().unwrap_or(0);
    }

    // Plain number (for CPU, treat as cores = 1000 millicores)
    if let Ok(val) = s.parse::<i64>() {
        return val * 1000; // Assume CPU in cores
    }

    0
}

/// Pod validate limit function - validates resource limits.
fn pod_validate_limit_func(
    limit_range: &LimitRange,
    attributes: &dyn Attributes,
) -> AdmissionResult<()> {
    let kind = attributes.get_kind();
    if kind.kind != "Pod" {
        return Ok(());
    }

    let obj = match attributes.get_object() {
        Some(o) => o,
        None => return Ok(()),
    };

    let pod = match obj.as_any().downcast_ref::<Pod>() {
        Some(p) => p,
        None => return Ok(()),
    };

    let mut errors = Vec::new();

    for limit in &limit_range.spec.limits {
        let limit_type = match limit.limit_type {
            Some(lt) => lt,
            None => continue,
        };

        if limit_type == LimitType::Container {
            // Validate each container
            for container in &pod.spec.containers {
                for (k, v) in &limit.min {
                    if let Err(e) = min_constraint(
                        "Container",
                        k,
                        v,
                        container.resources.requests.get(k),
                        container.resources.limits.get(k),
                    ) {
                        errors.push(e);
                    }
                }
                for (k, v) in &limit.max {
                    if let Err(e) = max_constraint(
                        "Container",
                        k,
                        v,
                        container.resources.requests.get(k),
                        container.resources.limits.get(k),
                    ) {
                        errors.push(e);
                    }
                }
            }

            // Validate init containers
            for container in &pod.spec.init_containers {
                for (k, v) in &limit.min {
                    if let Err(e) = min_constraint(
                        "Container",
                        k,
                        v,
                        container.resources.requests.get(k),
                        container.resources.limits.get(k),
                    ) {
                        errors.push(e);
                    }
                }
                for (k, v) in &limit.max {
                    if let Err(e) = max_constraint(
                        "Container",
                        k,
                        v,
                        container.resources.requests.get(k),
                        container.resources.limits.get(k),
                    ) {
                        errors.push(e);
                    }
                }
            }
        }

        if limit_type == LimitType::Pod {
            // Calculate pod totals
            let pod_requests = calculate_pod_requests(pod);
            let pod_limits = calculate_pod_limits(pod);

            for (k, v) in &limit.min {
                if let Err(e) = min_constraint(
                    "Pod",
                    k,
                    v,
                    pod_requests.get(k),
                    pod_limits.get(k),
                ) {
                    errors.push(e);
                }
            }
            for (k, v) in &limit.max {
                if let Err(e) = max_constraint(
                    "Pod",
                    k,
                    v,
                    pod_requests.get(k),
                    pod_limits.get(k),
                ) {
                    errors.push(e);
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(AdmissionError::forbidden(
            &pod.name,
            &pod.namespace,
            "pods",
            crate::admission::errors::FieldError {
                field: "spec.containers".to_string(),
                error_type: crate::admission::errors::FieldErrorType::Invalid,
                value: errors.join("; "),
                supported_values: vec![],
            },
        ));
    }

    Ok(())
}

/// Calculate total pod requests.
fn calculate_pod_requests(pod: &Pod) -> ResourceList {
    let mut reqs = ResourceList::new();

    for container in &pod.spec.containers {
        for (k, v) in &container.resources.requests {
            let current = reqs.entry(k.clone()).or_insert_with(|| "0".to_string());
            let current_val = parse_quantity(current);
            let add_val = parse_quantity(v);
            *current = format!("{}m", current_val + add_val);
        }
    }

    // For init containers, take the max
    let mut init_reqs = ResourceList::new();
    for container in &pod.spec.init_containers {
        for (k, v) in &container.resources.requests {
            let current = init_reqs.entry(k.clone()).or_insert_with(|| "0".to_string());
            let current_val = parse_quantity(current);
            let new_val = parse_quantity(v);
            if new_val > current_val {
                *current = v.clone();
            }
        }
    }

    // Max of container sum and init container max
    for (k, v) in init_reqs.iter() {
        let current = reqs.entry(k.clone()).or_insert_with(|| "0".to_string());
        let current_val = parse_quantity(current);
        let init_val = parse_quantity(v);
        if init_val > current_val {
            *current = v.clone();
        }
    }

    reqs
}

/// Calculate total pod limits.
fn calculate_pod_limits(pod: &Pod) -> ResourceList {
    let mut limits = ResourceList::new();

    for container in &pod.spec.containers {
        for (k, v) in &container.resources.limits {
            let current = limits.entry(k.clone()).or_insert_with(|| "0".to_string());
            let current_val = parse_quantity(current);
            let add_val = parse_quantity(v);
            *current = format!("{}m", current_val + add_val);
        }
    }

    // For init containers, take the max
    let mut init_limits = ResourceList::new();
    for container in &pod.spec.init_containers {
        for (k, v) in &container.resources.limits {
            let current = init_limits.entry(k.clone()).or_insert_with(|| "0".to_string());
            let current_val = parse_quantity(current);
            let new_val = parse_quantity(v);
            if new_val > current_val {
                *current = v.clone();
            }
        }
    }

    // Max of container sum and init container max
    for (k, v) in init_limits.iter() {
        let current = limits.entry(k.clone()).or_insert_with(|| "0".to_string());
        let current_val = parse_quantity(current);
        let init_val = parse_quantity(v);
        if init_val > current_val {
            *current = v.clone();
        }
    }

    limits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    fn create_limit_range(
        limit_type: LimitType,
        min: ResourceList,
        max: ResourceList,
        default: ResourceList,
        default_request: ResourceList,
    ) -> LimitRange {
        let mut lr = LimitRange::new("test-lr", "test");
        lr.spec.limits.push(LimitRangeItem {
            limit_type: Some(limit_type),
            min,
            max,
            default,
            default_request,
            max_limit_request_ratio: ResourceList::new(),
        });
        lr
    }

    fn resource_list(cpu: &str, memory: &str) -> ResourceList {
        let mut rl = ResourceList::new();
        if !cpu.is_empty() {
            rl.insert("cpu".to_string(), cpu.to_string());
        }
        if !memory.is_empty() {
            rl.insert("memory".to_string(), memory.to_string());
        }
        rl
    }

    #[test]
    fn test_default_container_resource_requirements() {
        let lr = create_limit_range(
            LimitType::Container,
            resource_list("25m", "1Mi"),
            resource_list("100m", "2Gi"),
            resource_list("75m", "10Mi"),
            resource_list("50m", "5Mi"),
        );

        let defaults = default_container_resource_requirements(&lr);

        assert_eq!(defaults.requests.get("cpu"), Some(&"50m".to_string()));
        assert_eq!(defaults.requests.get("memory"), Some(&"5Mi".to_string()));
        assert_eq!(defaults.limits.get("cpu"), Some(&"75m".to_string()));
        assert_eq!(defaults.limits.get("memory"), Some(&"10Mi".to_string()));
    }

    #[test]
    fn test_merge_pod_resource_requirements() {
        let defaults = ResourceRequirements {
            requests: resource_list("50m", "5Mi"),
            limits: resource_list("75m", "10Mi"),
        };

        let mut pod = Pod::new("test-pod", "test");
        pod.spec.containers.push(Container {
            name: "container1".to_string(),
            image: "nginx".to_string(),
            resources: ResourceRequirements::default(),
            ..Default::default()
        });

        merge_pod_resource_requirements(&mut pod, &defaults);

        let container = &pod.spec.containers[0];
        assert_eq!(container.resources.requests.get("cpu"), Some(&"50m".to_string()));
        assert_eq!(container.resources.limits.get("cpu"), Some(&"75m".to_string()));
        assert!(pod.annotations.contains_key(LIMIT_RANGER_ANNOTATION));
    }

    #[test]
    fn test_handles() {
        let handler = LimitRanger::new();

        assert!(handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(!handler.handles(Operation::Delete));
        assert!(!handler.handles(Operation::Connect));
    }

    #[test]
    fn test_supports_attributes_pod_create() {
        let handler = LimitRanger::new();

        let pod = Pod::new("test", "default");
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

        assert!(handler.supports_attributes(&attrs));
    }

    #[test]
    fn test_supports_attributes_pod_update_ignored() {
        let handler = LimitRanger::new();

        let pod = Pod::new("test", "default");
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Update,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        // Pod updates should be ignored (containers are immutable)
        assert!(!handler.supports_attributes(&attrs));
    }

    #[test]
    fn test_supports_attributes_subresource_ignored() {
        let handler = LimitRanger::new();

        let pod = Pod::new("test", "default");
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

        assert!(!handler.supports_attributes(&attrs));
    }

    #[test]
    fn test_parse_quantity() {
        assert_eq!(parse_quantity("100m"), 100);
        assert_eq!(parse_quantity("1"), 1000);
        assert_eq!(parse_quantity("2"), 2000);
        assert_eq!(parse_quantity("1Mi"), 1024 * 1024);
        assert_eq!(parse_quantity("1Gi"), 1024 * 1024 * 1024);
    }

    #[test]
    fn test_min_constraint_pass() {
        let result = min_constraint(
            "Container",
            "cpu",
            "50m",
            Some(&"100m".to_string()),
            Some(&"200m".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_min_constraint_fail_no_request() {
        let result = min_constraint("Container", "cpu", "50m", None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No request is specified"));
    }

    #[test]
    fn test_min_constraint_fail_too_low() {
        let result = min_constraint(
            "Container",
            "cpu",
            "100m",
            Some(&"50m".to_string()),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_max_constraint_pass() {
        let result = max_constraint(
            "Container",
            "cpu",
            "200m",
            Some(&"100m".to_string()),
            Some(&"150m".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_max_constraint_fail_no_limit() {
        let result = max_constraint("Container", "cpu", "200m", Some(&"100m".to_string()), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No limit is specified"));
    }

    #[test]
    fn test_max_constraint_fail_too_high() {
        let result = max_constraint(
            "Container",
            "cpu",
            "100m",
            Some(&"50m".to_string()),
            Some(&"200m".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_validate_container_within_limits() {
        let store = Arc::new(InMemoryLimitRangeStore::new());
        store.add(create_limit_range(
            LimitType::Container,
            resource_list("25m", ""),
            resource_list("100m", ""),
            resource_list("", ""),
            resource_list("", ""),
        ));

        let handler = LimitRanger::with_lister(store);

        let mut pod = Pod::new("test-pod", "test");
        pod.spec.containers.push(Container {
            name: "c1".to_string(),
            image: "nginx".to_string(),
            resources: ResourceRequirements {
                requests: resource_list("50m", ""),
                limits: resource_list("75m", ""),
            },
            ..Default::default()
        });

        let attrs = AttributesRecord::new(
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

        let result = handler.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_container_below_min() {
        let store = Arc::new(InMemoryLimitRangeStore::new());
        store.add(create_limit_range(
            LimitType::Container,
            resource_list("100m", ""),
            resource_list("", ""),
            resource_list("", ""),
            resource_list("", ""),
        ));

        let handler = LimitRanger::with_lister(store);

        let mut pod = Pod::new("test-pod", "test");
        pod.spec.containers.push(Container {
            name: "c1".to_string(),
            image: "nginx".to_string(),
            resources: ResourceRequirements {
                requests: resource_list("50m", ""),
                limits: resource_list("75m", ""),
            },
            ..Default::default()
        });

        let attrs = AttributesRecord::new(
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

        let result = handler.validate(&attrs);
        assert!(result.is_err());
    }
}
