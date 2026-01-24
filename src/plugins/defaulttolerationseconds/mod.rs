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

//! DefaultTolerationSeconds admission controller.
//!
//! This admission controller adds default tolerations for `notReady:NoExecute` and
//! `unreachable:NoExecute` taints with tolerationSeconds of 300s. If the pod already
//! specifies a toleration for these taints, the plugin won't touch it.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins,
};
use crate::api::core::{
    Pod, Toleration, TolerationEffect, TolerationOperator, TAINT_NODE_NOT_READY,
    TAINT_NODE_UNREACHABLE,
};
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the DefaultTolerationSeconds admission controller.
pub const PLUGIN_NAME: &str = "DefaultTolerationSeconds";

/// Default toleration seconds for not-ready and unreachable taints.
pub const DEFAULT_NOT_READY_TOLERATION_SECONDS: i64 = 300;
pub const DEFAULT_UNREACHABLE_TOLERATION_SECONDS: i64 = 300;

/// Register the DefaultTolerationSeconds plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Plugin contains the default tolerations to add to pods.
/// It will add default tolerations for every pod that tolerate taints
/// `notReady:NoExecute` and `unreachable:NoExecute`, with tolerationSeconds of 300s.
pub struct Plugin {
    handler: Handler,
    not_ready_toleration: Toleration,
    unreachable_toleration: Toleration,
}

impl Plugin {
    /// Create a new DefaultTolerationSeconds admission controller.
    pub fn new() -> Self {
        Self {
            handler: Handler::new_create_update(),
            not_ready_toleration: Toleration::with_seconds(
                TAINT_NODE_NOT_READY,
                TolerationOperator::Exists,
                Some(TolerationEffect::NoExecute),
                DEFAULT_NOT_READY_TOLERATION_SECONDS,
            ),
            unreachable_toleration: Toleration::with_seconds(
                TAINT_NODE_UNREACHABLE,
                TolerationOperator::Exists,
                Some(TolerationEffect::NoExecute),
                DEFAULT_UNREACHABLE_TOLERATION_SECONDS,
            ),
        }
    }

    /// Create a new plugin with custom toleration seconds.
    pub fn with_seconds(not_ready_seconds: i64, unreachable_seconds: i64) -> Self {
        Self {
            handler: Handler::new_create_update(),
            not_ready_toleration: Toleration::with_seconds(
                TAINT_NODE_NOT_READY,
                TolerationOperator::Exists,
                Some(TolerationEffect::NoExecute),
                not_ready_seconds,
            ),
            unreachable_toleration: Toleration::with_seconds(
                TAINT_NODE_UNREACHABLE,
                TolerationOperator::Exists,
                Some(TolerationEffect::NoExecute),
                unreachable_seconds,
            ),
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

impl MutationInterface for Plugin {
    /// Admit adds default tolerations to pods if they don't already have them.
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Only process pods
        let resource = attributes.get_resource();
        if !resource.group.is_empty() || resource.resource != "pods" {
            return Ok(());
        }

        // Only run on pods proper, not subresources
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        // Get the pod object mutably
        let obj = attributes.get_object_mut();
        let pod = match obj {
            Some(o) => match o.as_any_mut().downcast_mut::<Pod>() {
                Some(p) => p,
                None => {
                    return Err(AdmissionError::bad_request("expected *Pod but got different type".to_string()));
                }
            },
            None => return Ok(()),
        };

        let tolerations = &pod.spec.tolerations;

        // Check if pod already tolerates notReady:NoExecute
        let mut tolerates_node_not_ready = false;
        let mut tolerates_node_unreachable = false;

        for toleration in tolerations {
            // Check for not-ready toleration
            // A toleration matches if key matches (or is empty with Exists) and effect matches (or is empty)
            if (toleration.key == TAINT_NODE_NOT_READY || toleration.key.is_empty())
                && (toleration.effect == Some(TolerationEffect::NoExecute)
                    || toleration.effect.is_none())
            {
                tolerates_node_not_ready = true;
            }

            // Check for unreachable toleration
            if (toleration.key == TAINT_NODE_UNREACHABLE || toleration.key.is_empty())
                && (toleration.effect == Some(TolerationEffect::NoExecute)
                    || toleration.effect.is_none())
            {
                tolerates_node_unreachable = true;
            }
        }

        // Add default tolerations if not already present
        if !tolerates_node_not_ready {
            pod.spec.tolerations.push(self.not_ready_toleration.clone());
        }

        if !tolerates_node_unreachable {
            pod.spec
                .tolerations
                .push(self.unreachable_toleration.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::PodSpec;

    fn new_handler_for_test() -> Plugin {
        Plugin::new()
    }

    #[test]
    fn test_forgiveness_admission() {
        let default_toleration_seconds: i64 = 300;

        let plugin = new_handler_for_test();

        struct TestCase {
            description: &'static str,
            initial_tolerations: Vec<Toleration>,
            expected_tolerations: Vec<Toleration>,
        }

        let tests = vec![
            // Pod has no tolerations, expect add tolerations for both
            TestCase {
                description: "pod has no tolerations, expect add tolerations for not-ready and unreachable",
                initial_tolerations: vec![],
                expected_tolerations: vec![
                    Toleration::with_seconds(
                        TAINT_NODE_NOT_READY,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        default_toleration_seconds,
                    ),
                    Toleration::with_seconds(
                        TAINT_NODE_UNREACHABLE,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        default_toleration_seconds,
                    ),
                ],
            },
            // Pod has other tolerations, expect add both default tolerations
            TestCase {
                description: "pod has other tolerations, expect add both default tolerations",
                initial_tolerations: vec![Toleration {
                    key: "foo".to_string(),
                    operator: TolerationOperator::Equal,
                    value: "bar".to_string(),
                    effect: Some(TolerationEffect::NoSchedule),
                    toleration_seconds: Some(700),
                }],
                expected_tolerations: vec![
                    Toleration {
                        key: "foo".to_string(),
                        operator: TolerationOperator::Equal,
                        value: "bar".to_string(),
                        effect: Some(TolerationEffect::NoSchedule),
                        toleration_seconds: Some(700),
                    },
                    Toleration::with_seconds(
                        TAINT_NODE_NOT_READY,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        default_toleration_seconds,
                    ),
                    Toleration::with_seconds(
                        TAINT_NODE_UNREACHABLE,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        default_toleration_seconds,
                    ),
                ],
            },
            // Pod specified toleration for not-ready, expect add only unreachable
            TestCase {
                description: "pod has not-ready toleration, expect add only unreachable",
                initial_tolerations: vec![Toleration::with_seconds(
                    TAINT_NODE_NOT_READY,
                    TolerationOperator::Exists,
                    Some(TolerationEffect::NoExecute),
                    700,
                )],
                expected_tolerations: vec![
                    Toleration::with_seconds(
                        TAINT_NODE_NOT_READY,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        700,
                    ),
                    Toleration::with_seconds(
                        TAINT_NODE_UNREACHABLE,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        default_toleration_seconds,
                    ),
                ],
            },
            // Pod specified toleration for unreachable, expect add only not-ready
            TestCase {
                description: "pod has unreachable toleration, expect add only not-ready",
                initial_tolerations: vec![Toleration::with_seconds(
                    TAINT_NODE_UNREACHABLE,
                    TolerationOperator::Exists,
                    Some(TolerationEffect::NoExecute),
                    700,
                )],
                expected_tolerations: vec![
                    Toleration::with_seconds(
                        TAINT_NODE_UNREACHABLE,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        700,
                    ),
                    Toleration::with_seconds(
                        TAINT_NODE_NOT_READY,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        default_toleration_seconds,
                    ),
                ],
            },
            // Pod has both tolerations, expect no change
            TestCase {
                description: "pod has both tolerations, expect no change",
                initial_tolerations: vec![
                    Toleration::with_seconds(
                        TAINT_NODE_NOT_READY,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        700,
                    ),
                    Toleration::with_seconds(
                        TAINT_NODE_UNREACHABLE,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        700,
                    ),
                ],
                expected_tolerations: vec![
                    Toleration::with_seconds(
                        TAINT_NODE_NOT_READY,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        700,
                    ),
                    Toleration::with_seconds(
                        TAINT_NODE_UNREACHABLE,
                        TolerationOperator::Exists,
                        Some(TolerationEffect::NoExecute),
                        700,
                    ),
                ],
            },
            // Pod has wildcard toleration, expect no change
            TestCase {
                description: "pod has wildcard toleration, expect no change",
                initial_tolerations: vec![Toleration {
                    key: String::new(),
                    operator: TolerationOperator::Exists,
                    value: String::new(),
                    effect: None,
                    toleration_seconds: Some(700),
                }],
                expected_tolerations: vec![Toleration {
                    key: String::new(),
                    operator: TolerationOperator::Exists,
                    value: String::new(),
                    effect: None,
                    toleration_seconds: Some(700),
                }],
            },
        ];

        for test in tests {
            let mut pod = Pod::new("name", "foo");
            pod.spec = PodSpec {
                tolerations: test.initial_tolerations,
                ..Default::default()
            };

            let mut attrs = AttributesRecord::new(
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

            let result = plugin.admit(&mut attrs);
            assert!(
                result.is_ok(),
                "[{}]: unexpected error {:?}",
                test.description,
                result.err()
            );

            // Get the pod back and check tolerations
            let obj = attrs.get_object().unwrap();
            let pod = obj.as_any().downcast_ref::<Pod>().unwrap();

            assert_eq!(
                pod.spec.tolerations.len(),
                test.expected_tolerations.len(),
                "[{}]: expected {} tolerations, got {}",
                test.description,
                test.expected_tolerations.len(),
                pod.spec.tolerations.len()
            );

            for (i, expected) in test.expected_tolerations.iter().enumerate() {
                assert_eq!(
                    pod.spec.tolerations[i].key, expected.key,
                    "[{}]: toleration[{}] key mismatch",
                    test.description, i
                );
                assert_eq!(
                    pod.spec.tolerations[i].effect, expected.effect,
                    "[{}]: toleration[{}] effect mismatch",
                    test.description, i
                );
            }
        }
    }

    #[test]
    fn test_handles() {
        let handler = Plugin::new();

        let tests = [
            (Operation::Create, true),
            (Operation::Update, true),
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
    fn test_non_pod_resource() {
        let plugin = Plugin::new();

        let node = crate::api::core::Node::new("my-node");
        let mut attrs = AttributesRecord::new(
            "my-node",
            "",
            GroupVersionResource::new("", "v1", "nodes"),
            "",
            Operation::Create,
            Some(Box::new(node)),
            None,
            GroupVersionKind::new("", "v1", "Node"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok(), "should not error for non-pod resources");
    }

    #[test]
    fn test_subresource_ignored() {
        let plugin = Plugin::new();

        let mut pod = Pod::new("test", "default");
        pod.spec.tolerations = vec![];

        let mut attrs = AttributesRecord::new(
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

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        // Verify no tolerations were added (subresource ignored)
        let obj = attrs.get_object().unwrap();
        let pod = obj.as_any().downcast_ref::<Pod>().unwrap();
        assert!(
            pod.spec.tolerations.is_empty(),
            "no tolerations should be added for subresource requests"
        );
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
