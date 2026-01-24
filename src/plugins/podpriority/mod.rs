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

//! Priority admission controller.
//!
//! This admission controller resolves pod priority based on PriorityClass
//! and validates PriorityClass resources.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface,
    Operation, Plugins, ValidationInterface,
};
use crate::api::core::{ApiObject, Pod};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

/// Plugin name for the Priority admission controller.
pub const PLUGIN_NAME: &str = "Priority";

/// Default priority when no default class exists.
pub const DEFAULT_PRIORITY_WHEN_NO_DEFAULT_CLASS_EXISTS: i32 = 0;

/// PreemptionPolicy describes the preemption policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum PreemptionPolicy {
    #[default]
    PreemptLowerPriority,
    Never,
}


/// PriorityClass defines a priority class.
#[derive(Debug, Clone)]
pub struct PriorityClass {
    pub name: String,
    pub value: i32,
    pub global_default: bool,
    pub preemption_policy: Option<PreemptionPolicy>,
    pub description: String,
}

impl PriorityClass {
    pub fn new(name: &str, value: i32) -> Self {
        Self {
            name: name.to_string(),
            value,
            global_default: false,
            preemption_policy: Some(PreemptionPolicy::PreemptLowerPriority),
            description: String::new(),
        }
    }

    pub fn with_global_default(mut self, global_default: bool) -> Self {
        self.global_default = global_default;
        self
    }
}

impl ApiObject for PriorityClass {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "PriorityClass"
    }
}

/// Register the Priority plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Trait for priority class lister.
pub trait PriorityClassLister: Send + Sync {
    fn get(&self, name: &str) -> Option<PriorityClass>;
    fn list(&self) -> Vec<PriorityClass>;
}

/// In-memory priority class store for testing.
#[derive(Debug, Default)]
pub struct InMemoryPriorityClassStore {
    classes: RwLock<HashMap<String, PriorityClass>>,
}

impl InMemoryPriorityClassStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, pc: PriorityClass) {
        self.classes
            .write()
            .expect("priority class store lock poisoned")
            .insert(pc.name.clone(), pc);
    }
}

impl PriorityClassLister for InMemoryPriorityClassStore {
    fn get(&self, name: &str) -> Option<PriorityClass> {
        self.classes
            .read()
            .expect("priority class store lock poisoned")
            .get(name)
            .cloned()
    }

    fn list(&self) -> Vec<PriorityClass> {
        self.classes
            .read()
            .expect("priority class store lock poisoned")
            .values()
            .cloned()
            .collect()
    }
}

/// Plugin is an implementation of the Priority admission controller.
pub struct Plugin {
    handler: Handler,
    lister: Option<Arc<dyn PriorityClassLister>>,
}

impl Plugin {
    /// Create a new Priority admission controller.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]),
            lister: None,
        }
    }

    /// Create with a priority class lister.
    pub fn with_lister(lister: Arc<dyn PriorityClassLister>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]),
            lister: Some(lister),
        }
    }

    /// Get the default priority class.
    fn get_default_priority_class(&self) -> Option<PriorityClass> {
        let lister = self.lister.as_ref()?;
        let list = lister.list();

        let mut default_pc: Option<PriorityClass> = None;
        for pc in list {
            if pc.global_default
                && (default_pc.is_none() || default_pc.as_ref().unwrap().value > pc.value) {
                    default_pc = Some(pc);
                }
        }
        default_pc
    }

    /// Get the default priority.
    fn get_default_priority(&self) -> (String, i32, Option<PreemptionPolicy>) {
        if let Some(dpc) = self.get_default_priority_class() {
            return (dpc.name, dpc.value, dpc.preemption_policy);
        }
        (
            String::new(),
            DEFAULT_PRIORITY_WHEN_NO_DEFAULT_CLASS_EXISTS,
            Some(PreemptionPolicy::PreemptLowerPriority),
        )
    }

    /// Check if this admission controller should ignore the request.
    fn should_ignore(&self, attributes: &dyn Attributes) -> bool {
        !attributes.get_subresource().is_empty()
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

        let resource = attributes.get_resource();
        let operation = attributes.get_operation();

        // Only handle pods
        if resource.resource != "pods" {
            return Ok(());
        }

        if operation != Operation::Create && operation != Operation::Update {
            return Ok(());
        }

        // Get pod
        let obj = match attributes.get_object_mut() {
            Some(o) => o,
            None => return Ok(()),
        };

        let pod = match obj.as_any_mut().downcast_mut::<Pod>() {
            Some(p) => p,
            None => {
                return Err(AdmissionError::bad_request(
                    "resource was marked with kind Pod but was unable to be converted",
                ));
            }
        };

        if operation == Operation::Update {
            // Preserve existing priority on update
            // API validation prevents mutations to Priority and PriorityClassName
            return Ok(());
        }

        // Handle Create operation
        let lister = match &self.lister {
            Some(l) => l,
            None => {
                // No lister configured, use default priority
                let (pc_name, priority, _) = self.get_default_priority();
                if pod.spec.priority_class_name.is_empty() {
                    pod.spec.priority_class_name = pc_name;
                }
                pod.spec.priority = Some(priority);
                return Ok(());
            }
        };

        let priority: i32;
        let preemption_policy: Option<PreemptionPolicy>;

        if pod.spec.priority_class_name.is_empty() {
            let (pc_name, p, pp) = self.get_default_priority();
            priority = p;
            preemption_policy = pp;
            pod.spec.priority_class_name = pc_name;
        } else {
            // Try resolving the priority class name
            match lister.get(&pod.spec.priority_class_name) {
                Some(pc) => {
                    priority = pc.value;
                    preemption_policy = pc.preemption_policy;
                }
                None => {
                    return Err(AdmissionError::forbidden(
                        &pod.name,
                        &pod.namespace,
                        "pods",
                        crate::admission::errors::FieldError {
                            field: "spec.priorityClassName".to_string(),
                            error_type: crate::admission::errors::FieldErrorType::Invalid,
                            value: format!(
                                "no PriorityClass with name {} was found",
                                pod.spec.priority_class_name
                            ),
                            supported_values: vec![],
                        },
                    ));
                }
            }
        }

        // If the pod contained a priority that differs from the one computed, error
        if let Some(existing_priority) = pod.spec.priority {
            if existing_priority != priority {
                return Err(AdmissionError::forbidden(
                    &pod.name,
                    &pod.namespace,
                    "pods",
                    crate::admission::errors::FieldError {
                        field: "spec.priority".to_string(),
                        error_type: crate::admission::errors::FieldErrorType::Invalid,
                        value: format!(
                            "the integer value of priority ({}) must not be provided in pod spec; priority admission controller computed {} from the given PriorityClass name",
                            existing_priority, priority
                        ),
                        supported_values: vec![],
                    },
                ));
            }
        }

        pod.spec.priority = Some(priority);
        pod.spec.preemption_policy = preemption_policy;

        Ok(())
    }
}

impl ValidationInterface for Plugin {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        if self.should_ignore(attributes) {
            return Ok(());
        }

        let resource = attributes.get_resource();
        let operation = attributes.get_operation();

        // Only validate priorityclasses
        if resource.resource != "priorityclasses" {
            return Ok(());
        }

        if operation != Operation::Create && operation != Operation::Update {
            return Ok(());
        }

        // Get priority class
        let obj = match attributes.get_object() {
            Some(o) => o,
            None => return Ok(()),
        };

        let pc = match obj.as_any().downcast_ref::<PriorityClass>() {
            Some(p) => p,
            None => {
                return Err(AdmissionError::bad_request(
                    "resource was marked with kind PriorityClass but was unable to be converted",
                ));
            }
        };

        // If the new PriorityClass tries to be the default priority,
        // make sure that no other priority class is marked as default
        if pc.global_default {
            if let Some(dpc) = self.get_default_priority_class() {
                if operation == Operation::Create || dpc.name != pc.name {
                    return Err(AdmissionError::forbidden(
                        &pc.name,
                        "",
                        "priorityclasses",
                        crate::admission::errors::FieldError {
                            field: "globalDefault".to_string(),
                            error_type: crate::admission::errors::FieldErrorType::Invalid,
                            value: format!(
                                "PriorityClass {} is already marked as default. Only one default can exist",
                                dpc.name
                            ),
                            supported_values: vec![],
                        },
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    fn create_priority_class_store() -> Arc<InMemoryPriorityClassStore> {
        let store = Arc::new(InMemoryPriorityClassStore::new());
        store.add(PriorityClass::new("high-priority", 1000));
        store.add(PriorityClass::new("low-priority", 100));
        store.add(PriorityClass::new("default", 0).with_global_default(true));
        store
    }

    #[test]
    fn test_handles() {
        let handler = Plugin::new();

        assert!(handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(handler.handles(Operation::Delete));
        assert!(!handler.handles(Operation::Connect));
    }

    #[test]
    fn test_admit_pod_with_priority_class() {
        let store = create_priority_class_store();
        let handler = Plugin::with_lister(store);

        let mut pod = Pod::new("test-pod", "default");
        pod.spec.priority_class_name = "high-priority".to_string();

        let mut attrs = AttributesRecord::new(
            "test-pod",
            "default",
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

        let obj = attrs.get_object().unwrap();
        let pod = obj.as_any().downcast_ref::<Pod>().unwrap();
        assert_eq!(pod.spec.priority, Some(1000));
    }

    #[test]
    fn test_admit_pod_without_priority_class_uses_default() {
        let store = create_priority_class_store();
        let handler = Plugin::with_lister(store);

        let pod = Pod::new("test-pod", "default");

        let mut attrs = AttributesRecord::new(
            "test-pod",
            "default",
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

        let obj = attrs.get_object().unwrap();
        let pod = obj.as_any().downcast_ref::<Pod>().unwrap();
        assert_eq!(pod.spec.priority, Some(0));
        assert_eq!(pod.spec.priority_class_name, "default");
    }

    #[test]
    fn test_admit_pod_nonexistent_priority_class() {
        let store = create_priority_class_store();
        let handler = Plugin::with_lister(store);

        let mut pod = Pod::new("test-pod", "default");
        pod.spec.priority_class_name = "nonexistent".to_string();

        let mut attrs = AttributesRecord::new(
            "test-pod",
            "default",
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
    fn test_admit_pod_conflicting_priority() {
        let store = create_priority_class_store();
        let handler = Plugin::with_lister(store);

        let mut pod = Pod::new("test-pod", "default");
        pod.spec.priority_class_name = "high-priority".to_string();
        pod.spec.priority = Some(500); // Conflicts with high-priority's value of 1000

        let mut attrs = AttributesRecord::new(
            "test-pod",
            "default",
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
    fn test_validate_priority_class_duplicate_default() {
        let store = create_priority_class_store();
        let handler = Plugin::with_lister(store);

        let pc = PriorityClass::new("another-default", 50).with_global_default(true);

        let attrs = AttributesRecord::new(
            "another-default",
            "",
            GroupVersionResource::new("scheduling.k8s.io", "v1", "priorityclasses"),
            "",
            Operation::Create,
            Some(Box::new(pc)),
            None,
            GroupVersionKind::new("scheduling.k8s.io", "v1", "PriorityClass"),
            false,
        );

        let result = handler.validate(&attrs);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_priority_class_non_default() {
        let store = create_priority_class_store();
        let handler = Plugin::with_lister(store);

        let pc = PriorityClass::new("new-priority", 500);

        let attrs = AttributesRecord::new(
            "new-priority",
            "",
            GroupVersionResource::new("scheduling.k8s.io", "v1", "priorityclasses"),
            "",
            Operation::Create,
            Some(Box::new(pc)),
            None,
            GroupVersionKind::new("scheduling.k8s.io", "v1", "PriorityClass"),
            false,
        );

        let result = handler.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ignore_subresource() {
        let handler = Plugin::new();

        let pod = Pod::new("test-pod", "default");
        let attrs = AttributesRecord::new(
            "test-pod",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "status",
            Operation::Update,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        assert!(handler.should_ignore(&attrs));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));
    }
}
