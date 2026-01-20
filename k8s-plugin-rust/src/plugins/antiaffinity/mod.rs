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

//! LimitPodHardAntiAffinityTopology admission controller.
//!
//! This admission controller denies any pod that defines AntiAffinity topology key
//! other than `kubernetes.io/hostname` in requiredDuringSchedulingIgnoredDuringExecution.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use crate::api::core::{Pod, LABEL_HOSTNAME};
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the LimitPodHardAntiAffinityTopology admission controller.
pub const PLUGIN_NAME: &str = "LimitPodHardAntiAffinityTopology";

/// Register the LimitPodHardAntiAffinityTopology plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Plugin contains the handler used by the admission controller.
/// It denies any pod that defines AntiAffinity topology key other than
/// `kubernetes.io/hostname` in requiredDuringSchedulingIgnoredDuringExecution.
pub struct Plugin {
    handler: Handler,
}

impl Plugin {
    /// Create a new instance of the LimitPodHardAntiAffinityTopology admission controller.
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
    /// Handles returns true for Create and Update operations.
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl ValidationInterface for Plugin {
    /// Validate will deny any pod that defines AntiAffinity topology key other than
    /// `kubernetes.io/hostname` in requiredDuringSchedulingIgnoredDuringExecution.
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // Ignore all calls to subresources or resources other than pods.
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        let resource = attributes.get_resource();
        if resource.group != "" || resource.resource != "pods" {
            return Ok(());
        }

        // Get the pod object
        let obj = attributes.get_object();
        let pod = match obj {
            Some(o) => match o.as_any().downcast_ref::<Pod>() {
                Some(p) => p,
                None => {
                    return Err(AdmissionError::bad_request(
                        "Resource was marked with kind Pod but was unable to be converted",
                    ));
                }
            },
            None => return Ok(()),
        };

        // Check affinity rules
        if let Some(ref affinity) = pod.spec.affinity {
            if let Some(ref pod_anti_affinity) = affinity.pod_anti_affinity {
                // Check RequiredDuringSchedulingIgnoredDuringExecution terms
                for term in &pod_anti_affinity.required_during_scheduling_ignored_during_execution {
                    if term.topology_key != LABEL_HOSTNAME {
                        return Err(AdmissionError::forbidden(
                            &pod.name,
                            &pod.namespace,
                            "pods",
                            crate::admission::errors::FieldError {
                                field: "affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution".to_string(),
                                error_type: crate::admission::errors::FieldErrorType::Invalid,
                                value: format!(
                                    "TopologyKey {} but only key {} is allowed",
                                    term.topology_key, LABEL_HOSTNAME
                                ),
                                supported_values: vec![LABEL_HOSTNAME.to_string()],
                            },
                        ));
                    }
                }

                // TODO: Uncomment this block when RequiredDuringSchedulingRequiredDuringExecution is implemented.
                // for term in &pod_anti_affinity.required_during_scheduling_required_during_execution {
                //     if term.topology_key != LABEL_HOSTNAME {
                //         return Err(...);
                //     }
                // }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::{
        Affinity, LabelSelector, LabelSelectorOperator, LabelSelectorRequirement, PodAffinityTerm,
        PodAntiAffinity, PodSpec, WeightedPodAffinityTerm,
    };

    /// Helper to create a label selector with a security expression
    fn security_label_selector() -> LabelSelector {
        LabelSelector {
            match_labels: Default::default(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "security".to_string(),
                operator: LabelSelectorOperator::In,
                values: vec!["S2".to_string()],
            }],
        }
    }

    /// TestInterPodAffinityAdmission ensures the hard PodAntiAffinity is denied
    /// if it defines TopologyKey other than kubernetes.io/hostname.
    #[test]
    fn test_inter_pod_affinity_admission() {
        let handler = Plugin::new();

        struct TestCase {
            name: &'static str,
            affinity: Option<Affinity>,
            error_expected: bool,
        }

        let tests = vec![
            // empty affinity its success.
            TestCase {
                name: "empty affinity",
                affinity: Some(Affinity::default()),
                error_expected: false,
            },
            // whatever topologyKey in preferredDuringSchedulingIgnoredDuringExecution, the admission should success.
            TestCase {
                name: "any topologyKey in preferred is allowed",
                affinity: Some(Affinity {
                    pod_anti_affinity: Some(PodAntiAffinity {
                        preferred_during_scheduling_ignored_during_execution: vec![
                            WeightedPodAffinityTerm {
                                weight: 5,
                                pod_affinity_term: PodAffinityTerm {
                                    label_selector: Some(security_label_selector()),
                                    topology_key: "az".to_string(),
                                    namespaces: vec![],
                                },
                            },
                        ],
                        required_during_scheduling_ignored_during_execution: vec![],
                    }),
                    pod_affinity: None,
                }),
                error_expected: false,
            },
            // valid topologyKey in requiredDuringSchedulingIgnoredDuringExecution,
            // plus any topologyKey in preferredDuringSchedulingIgnoredDuringExecution, then admission success.
            TestCase {
                name: "valid required + any preferred",
                affinity: Some(Affinity {
                    pod_anti_affinity: Some(PodAntiAffinity {
                        preferred_during_scheduling_ignored_during_execution: vec![
                            WeightedPodAffinityTerm {
                                weight: 5,
                                pod_affinity_term: PodAffinityTerm {
                                    label_selector: Some(security_label_selector()),
                                    topology_key: "az".to_string(),
                                    namespaces: vec![],
                                },
                            },
                        ],
                        required_during_scheduling_ignored_during_execution: vec![PodAffinityTerm {
                            label_selector: Some(security_label_selector()),
                            topology_key: LABEL_HOSTNAME.to_string(),
                            namespaces: vec![],
                        }],
                    }),
                    pod_affinity: None,
                }),
                error_expected: false,
            },
            // valid topologyKey in requiredDuringSchedulingIgnoredDuringExecution then admission success.
            TestCase {
                name: "valid required topologyKey",
                affinity: Some(Affinity {
                    pod_anti_affinity: Some(PodAntiAffinity {
                        preferred_during_scheduling_ignored_during_execution: vec![],
                        required_during_scheduling_ignored_during_execution: vec![PodAffinityTerm {
                            label_selector: Some(security_label_selector()),
                            topology_key: LABEL_HOSTNAME.to_string(),
                            namespaces: vec![],
                        }],
                    }),
                    pod_affinity: None,
                }),
                error_expected: false,
            },
            // invalid topologyKey in requiredDuringSchedulingIgnoredDuringExecution then admission fails.
            TestCase {
                name: "invalid required topologyKey",
                affinity: Some(Affinity {
                    pod_anti_affinity: Some(PodAntiAffinity {
                        preferred_during_scheduling_ignored_during_execution: vec![],
                        required_during_scheduling_ignored_during_execution: vec![PodAffinityTerm {
                            label_selector: Some(security_label_selector()),
                            topology_key: " zone ".to_string(),
                            namespaces: vec![],
                        }],
                    }),
                    pod_affinity: None,
                }),
                error_expected: true,
            },
            // list of requiredDuringSchedulingIgnoredDuringExecution middle element topologyKey is not valid.
            TestCase {
                name: "middle element invalid topologyKey",
                affinity: Some(Affinity {
                    pod_anti_affinity: Some(PodAntiAffinity {
                        preferred_during_scheduling_ignored_during_execution: vec![],
                        required_during_scheduling_ignored_during_execution: vec![
                            PodAffinityTerm {
                                label_selector: Some(security_label_selector()),
                                topology_key: LABEL_HOSTNAME.to_string(),
                                namespaces: vec![],
                            },
                            PodAffinityTerm {
                                label_selector: Some(security_label_selector()),
                                topology_key: " zone ".to_string(),
                                namespaces: vec![],
                            },
                            PodAffinityTerm {
                                label_selector: Some(security_label_selector()),
                                topology_key: LABEL_HOSTNAME.to_string(),
                                namespaces: vec![],
                            },
                        ],
                    }),
                    pod_affinity: None,
                }),
                error_expected: true,
            },
        ];

        for test in tests {
            let mut pod = Pod::new("name", "foo");
            pod.spec = PodSpec {
                affinity: test.affinity,
                ..Default::default()
            };

            let attrs = AttributesRecord::new(
                "name",
                "foo",
                GroupVersionResource::new("", "version", "pods"),
                "",
                Operation::Create,
                Some(Box::new(pod)),
                None,
                GroupVersionKind::new("", "version", "Pod"),
                false,
            );

            let result = handler.validate(&attrs);

            if test.error_expected && result.is_ok() {
                panic!(
                    "{}: Expected error for Anti Affinity but did not get an error",
                    test.name
                );
            }

            if !test.error_expected && result.is_err() {
                panic!(
                    "{}: Unexpected error {:?} for AntiAffinity",
                    test.name,
                    result.err()
                );
            }
        }
    }

    /// TestHandles verifies which operations the plugin handles.
    #[test]
    fn test_handles() {
        let handler = Plugin::new();

        let tests = [
            (Operation::Update, true),
            (Operation::Create, true),
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

    /// TestOtherResources ensures that this admission controller is a no-op for other resources,
    /// subresources, and non-pods.
    #[test]
    fn test_other_resources() {
        let handler = Plugin::new();
        let namespace = "testnamespace";
        let name = "testname";

        struct TestCase {
            name: &'static str,
            kind: &'static str,
            resource: &'static str,
            subresource: &'static str,
            object: Box<dyn crate::api::core::ApiObject>,
            expect_error: bool,
        }

        let tests = vec![
            TestCase {
                name: "non-pod resource",
                kind: "Foo",
                resource: "foos",
                subresource: "",
                object: Box::new(Pod::new(name, namespace)),
                expect_error: false,
            },
            TestCase {
                name: "pod subresource",
                kind: "Pod",
                resource: "pods",
                subresource: "eviction",
                object: Box::new(Pod::new(name, namespace)),
                expect_error: false,
            },
            TestCase {
                name: "non-pod object",
                kind: "Pod",
                resource: "pods",
                subresource: "",
                object: Box::new(crate::api::core::Service { spec: crate::api::core::ServiceSpec::default(),
                    name: name.to_string(),
                    namespace: namespace.to_string(),
                }),
                expect_error: true,
            },
        ];

        for tc in tests {
            let attrs = AttributesRecord::new(
                name,
                namespace,
                GroupVersionResource::new("", "version", tc.resource),
                tc.subresource,
                Operation::Create,
                Some(tc.object),
                None,
                GroupVersionKind::new("", "version", tc.kind),
                false,
            );

            let result = handler.validate(&attrs);

            if tc.expect_error {
                assert!(
                    result.is_err(),
                    "{}: unexpected nil error",
                    tc.name
                );
            } else {
                assert!(
                    result.is_ok(),
                    "{}: unexpected error: {:?}",
                    tc.name,
                    result.err()
                );
            }
        }
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));

        let plugin = plugins.new_from_plugins(PLUGIN_NAME, None).unwrap();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }
}
