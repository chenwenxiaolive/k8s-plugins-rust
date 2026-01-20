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

//! ExtendedResourceToleration admission controller.
//!
//! This admission controller adds tolerations to pods based on the extended resources
//! they request. If an extended resource of name "example.com/device" is requested,
//! it adds a toleration with key "example.com/device", operator "Exists" and effect "NoSchedule".

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins,
};
use crate::api::core::{is_extended_resource_name, Pod, Toleration, TolerationEffect, TolerationOperator};
use std::collections::BTreeSet;
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the ExtendedResourceToleration admission controller.
pub const PLUGIN_NAME: &str = "ExtendedResourceToleration";

/// Register the ExtendedResourceToleration plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Plugin adds tolerations to pods based on extended resource requests.
pub struct Plugin {
    handler: Handler,
}

impl Plugin {
    /// Create a new ExtendedResourceToleration admission controller.
    pub fn new() -> Self {
        Self {
            handler: Handler::new_create_update(),
        }
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
    /// Admit updates the toleration of a pod based on the resources requested by it.
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Ignore all calls to subresources or resources other than pods.
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        let resource = attributes.get_resource();
        if resource.group != "" || resource.resource != "pods" {
            return Ok(());
        }

        // Get the pod object mutably
        let obj = attributes.get_object_mut();
        let pod = match obj {
            Some(o) => match o.as_any_mut().downcast_mut::<Pod>() {
                Some(p) => p,
                None => {
                    return Err(AdmissionError::bad_request(
                        "expected *Pod but got different type",
                    ));
                }
            },
            None => return Ok(()),
        };

        // Collect all extended resources from containers
        let mut resources = BTreeSet::new();

        for container in &pod.spec.containers {
            for resource_name in container.resources.requests.keys() {
                if is_extended_resource_name(resource_name) {
                    resources.insert(resource_name.clone());
                }
            }
        }

        for container in &pod.spec.init_containers {
            for resource_name in container.resources.requests.keys() {
                if is_extended_resource_name(resource_name) {
                    resources.insert(resource_name.clone());
                }
            }
        }

        // Add tolerations for each extended resource
        for resource in resources {
            add_or_update_toleration(
                pod,
                Toleration {
                    key: resource,
                    operator: TolerationOperator::Exists,
                    value: String::new(),
                    effect: Some(TolerationEffect::NoSchedule),
                    toleration_seconds: None,
                },
            );
        }

        Ok(())
    }
}

/// Add or update a toleration in the pod's tolerations list.
fn add_or_update_toleration(pod: &mut Pod, toleration: Toleration) {
    // Check if a matching toleration already exists
    for existing in &pod.spec.tolerations {
        if existing.key == toleration.key
            && existing.operator == toleration.operator
            && existing.effect == toleration.effect
        {
            // Already exists, don't add duplicate
            return;
        }
    }
    pod.spec.tolerations.push(toleration);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::{Container, PodSpec, ResourceRequirements};
    use std::collections::HashMap;

    fn make_pod_with_resources(container_resources: Vec<HashMap<String, String>>) -> Pod {
        let mut pod = Pod::new("test-pod", "default");
        pod.spec.containers = container_resources
            .into_iter()
            .enumerate()
            .map(|(i, requests)| {
                let mut c = Container::new(&format!("container-{}", i), "image");
                c.resources = ResourceRequirements {
                    requests,
                    limits: HashMap::new(),
                };
                c
            })
            .collect();
        pod
    }

    #[test]
    fn test_empty_pod() {
        let plugin = Plugin::new();
        let mut pod = Pod::new("test", "default");

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

        let obj = attrs.get_object().unwrap();
        let pod = obj.as_any().downcast_ref::<Pod>().unwrap();
        assert!(pod.spec.tolerations.is_empty());
    }

    #[test]
    fn test_pod_with_standard_resources() {
        let plugin = Plugin::new();
        let mut requests = HashMap::new();
        requests.insert("cpu".to_string(), "100m".to_string());
        requests.insert("memory".to_string(), "128Mi".to_string());

        let pod = make_pod_with_resources(vec![requests]);

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

        let obj = attrs.get_object().unwrap();
        let pod = obj.as_any().downcast_ref::<Pod>().unwrap();
        // Standard resources should not add tolerations
        assert!(pod.spec.tolerations.is_empty());
    }

    #[test]
    fn test_pod_with_extended_resource() {
        let plugin = Plugin::new();
        let mut requests = HashMap::new();
        requests.insert("example.com/gpu".to_string(), "1".to_string());

        let pod = make_pod_with_resources(vec![requests]);

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

        let obj = attrs.get_object().unwrap();
        let pod = obj.as_any().downcast_ref::<Pod>().unwrap();
        assert_eq!(pod.spec.tolerations.len(), 1);
        assert_eq!(pod.spec.tolerations[0].key, "example.com/gpu");
        assert_eq!(pod.spec.tolerations[0].operator, TolerationOperator::Exists);
        assert_eq!(
            pod.spec.tolerations[0].effect,
            Some(TolerationEffect::NoSchedule)
        );
    }

    #[test]
    fn test_pod_with_multiple_extended_resources() {
        let plugin = Plugin::new();
        let mut requests = HashMap::new();
        requests.insert("example.com/gpu".to_string(), "1".to_string());
        requests.insert("vendor.io/fpga".to_string(), "2".to_string());

        let pod = make_pod_with_resources(vec![requests]);

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

        let obj = attrs.get_object().unwrap();
        let pod = obj.as_any().downcast_ref::<Pod>().unwrap();
        assert_eq!(pod.spec.tolerations.len(), 2);

        let keys: Vec<&str> = pod.spec.tolerations.iter().map(|t| t.key.as_str()).collect();
        assert!(keys.contains(&"example.com/gpu"));
        assert!(keys.contains(&"vendor.io/fpga"));
    }

    #[test]
    fn test_pod_with_existing_toleration() {
        let plugin = Plugin::new();
        let mut requests = HashMap::new();
        requests.insert("example.com/gpu".to_string(), "1".to_string());

        let mut pod = make_pod_with_resources(vec![requests]);
        // Add existing toleration
        pod.spec.tolerations.push(Toleration {
            key: "example.com/gpu".to_string(),
            operator: TolerationOperator::Exists,
            value: String::new(),
            effect: Some(TolerationEffect::NoSchedule),
            toleration_seconds: None,
        });

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

        let obj = attrs.get_object().unwrap();
        let pod = obj.as_any().downcast_ref::<Pod>().unwrap();
        // Should not add duplicate
        assert_eq!(pod.spec.tolerations.len(), 1);
    }

    #[test]
    fn test_handles() {
        let handler = Plugin::new();

        assert!(handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(!handler.handles(Operation::Delete));
        assert!(!handler.handles(Operation::Connect));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));
    }
}
