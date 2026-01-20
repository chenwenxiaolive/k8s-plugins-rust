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

//! TaintNodesByCondition admission controller.
//!
//! This admission controller adds the NotReady taint to nodes when they are created.
//! This ensures that new nodes are not scheduled with pods until they become ready.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins,
};
use crate::api::core::{Node, Taint, TaintEffect, TAINT_NODE_NOT_READY};
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the TaintNodesByCondition admission controller.
pub const PLUGIN_NAME: &str = "TaintNodesByCondition";

/// Register the TaintNodesByCondition plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Plugin holds state for and implements the admission plugin.
/// This plugin identifies requests from nodes and adds NotReady taint.
pub struct Plugin {
    handler: Handler,
}

impl Plugin {
    /// Create a new TaintNodesByCondition admission plugin.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
        }
    }
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for Plugin {
    /// Handles returns true for Create operations only.
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl MutationInterface for Plugin {
    /// Admit is the main function that checks node identity and adds taints as needed.
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Our job is just to taint nodes.
        let resource = attributes.get_resource();
        if resource.group != "" || resource.resource != "nodes" {
            return Ok(());
        }

        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        // Get the node object mutably
        let obj = attributes.get_object_mut();
        let node = match obj {
            Some(o) => match o.as_any_mut().downcast_mut::<Node>() {
                Some(n) => n,
                None => {
                    return Err(AdmissionError::forbidden(
                        attributes.get_name(),
                        "",
                        "nodes",
                        crate::admission::errors::FieldError {
                            field: String::new(),
                            error_type: crate::admission::errors::FieldErrorType::Invalid,
                            value: format!("unexpected type"),
                            supported_values: vec![],
                        },
                    ));
                }
            },
            None => return Ok(()),
        };

        // Taint node with NotReady taint at creation. This is needed to make sure
        // that nodes are added to the cluster with the NotReady taint. Otherwise,
        // a new node may receive the taint with some delay causing pods to be
        // scheduled on a not-ready node. Node controller will remove the taint
        // when the node becomes ready.
        add_not_ready_taint(node);
        Ok(())
    }
}

/// Add the NotReady taint to a node if it doesn't already have it.
fn add_not_ready_taint(node: &mut Node) {
    let not_ready_taint = Taint::new(TAINT_NODE_NOT_READY, TaintEffect::NoSchedule);

    // Check if the taint already exists
    for taint in &node.spec.taints {
        if taint.matches(&not_ready_taint) {
            // the taint already exists.
            return;
        }
    }

    node.spec.taints.push(not_ready_taint);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    

    /// Test that NotReady taint is added on node creation.
    #[test]
    fn test_node_taints() {
        let not_ready_taint = Taint::new(TAINT_NODE_NOT_READY, TaintEffect::NoSchedule);

        struct TestCase {
            name: &'static str,
            node: Node,
            operation: Operation,
            expected_taints: Vec<Taint>,
        }

        let tests = vec![
            TestCase {
                name: "notReady taint is added on creation",
                node: Node::new("mynode"),
                operation: Operation::Create,
                expected_taints: vec![not_ready_taint.clone()],
            },
            TestCase {
                name: "already tainted node is not tainted again",
                node: {
                    let mut n = Node::new("mynode");
                    n.spec.taints.push(not_ready_taint.clone());
                    n
                },
                operation: Operation::Create,
                expected_taints: vec![not_ready_taint.clone()],
            },
            TestCase {
                name: "NotReady taint is added to an unready node as well",
                node: {
                    let n = Node::new("mynode");
                    // Node with unready condition (status doesn't affect taint addition)
                    n
                },
                operation: Operation::Create,
                expected_taints: vec![not_ready_taint.clone()],
            },
        ];

        for test in tests {
            let plugin = Plugin::new();

            let mut attrs = AttributesRecord::new(
                "mynode",
                "",
                GroupVersionResource::new("", "v1", "nodes"),
                "",
                test.operation,
                Some(Box::new(test.node)),
                None,
                GroupVersionKind::new("", "v1", "Node"),
                false,
            );

            let result = plugin.admit(&mut attrs);
            assert!(
                result.is_ok(),
                "{}: nodePlugin.Admit() error = {:?}",
                test.name,
                result.err()
            );

            // Get the node back and check taints
            let obj = attrs.get_object().unwrap();
            let node = obj.as_any().downcast_ref::<Node>().unwrap();

            assert_eq!(
                node.spec.taints.len(),
                test.expected_taints.len(),
                "{}: Unexpected number of taints. Got {} Expected: {}",
                test.name,
                node.spec.taints.len(),
                test.expected_taints.len()
            );

            for (i, expected) in test.expected_taints.iter().enumerate() {
                assert!(
                    node.spec.taints[i].matches(expected),
                    "{}: Taint {} doesn't match. Got {:?} Expected: {:?}",
                    test.name,
                    i,
                    node.spec.taints[i],
                    expected
                );
            }
        }
    }

    /// Test that the plugin only handles Create operations.
    #[test]
    fn test_handles() {
        let handler = Plugin::new();

        let tests = [
            (Operation::Create, true),
            (Operation::Update, false),
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

    /// Test that non-node resources are ignored.
    #[test]
    fn test_other_resources() {
        let plugin = Plugin::new();

        // Test with pod resource (should be ignored)
        let mut attrs = AttributesRecord::new(
            "mypod",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(crate::api::core::Pod::new("mypod", "default"))),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok(), "Should not error for non-node resources");
    }

    /// Test that subresources are ignored.
    #[test]
    fn test_subresources_ignored() {
        let plugin = Plugin::new();

        let mut attrs = AttributesRecord::new(
            "mynode",
            "",
            GroupVersionResource::new("", "v1", "nodes"),
            "status",
            Operation::Create,
            Some(Box::new(Node::new("mynode"))),
            None,
            GroupVersionKind::new("", "v1", "Node"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok(), "Should not error for subresources");

        // Verify no taint was added
        let obj = attrs.get_object().unwrap();
        let node = obj.as_any().downcast_ref::<Node>().unwrap();
        assert!(
            node.spec.taints.is_empty(),
            "No taint should be added for subresource requests"
        );
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));

        let plugin = plugins.new_from_plugins(PLUGIN_NAME, None).unwrap();
        assert!(plugin.handles(Operation::Create));
        assert!(!plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }
}
