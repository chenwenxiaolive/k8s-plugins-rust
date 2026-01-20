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

//! Admission attributes that describe an admission request.

use super::interfaces::Operation;
use crate::api::core::{ApiObject, Pod};

/// GroupVersionResource identifies a resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupVersionResource {
    pub group: String,
    pub version: String,
    pub resource: String,
}

impl GroupVersionResource {
    pub fn new(group: &str, version: &str, resource: &str) -> Self {
        Self {
            group: group.to_string(),
            version: version.to_string(),
            resource: resource.to_string(),
        }
    }

    /// Returns just the group and resource portion.
    pub fn group_resource(&self) -> GroupResource {
        GroupResource {
            group: self.group.clone(),
            resource: self.resource.clone(),
        }
    }
}

/// GroupResource identifies a resource without version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupResource {
    pub group: String,
    pub resource: String,
}

impl GroupResource {
    pub fn new(group: &str, resource: &str) -> Self {
        Self {
            group: group.to_string(),
            resource: resource.to_string(),
        }
    }
}

/// GroupVersionKind identifies a kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

impl GroupVersionKind {
    pub fn new(group: &str, version: &str, kind: &str) -> Self {
        Self {
            group: group.to_string(),
            version: version.to_string(),
            kind: kind.to_string(),
        }
    }
}

/// Attributes is an interface used by AdmissionController to get information about a request
/// that is used to make an admission decision.
pub trait Attributes {
    /// Returns the name of the object as presented in the request.
    fn get_name(&self) -> &str;

    /// Returns the namespace associated with the request (if any).
    fn get_namespace(&self) -> &str;

    /// Returns the resource being requested.
    fn get_resource(&self) -> &GroupVersionResource;

    /// Returns the name of the subresource being requested.
    fn get_subresource(&self) -> &str;

    /// Returns the operation being performed.
    fn get_operation(&self) -> Operation;

    /// Returns the object from the incoming request.
    fn get_object(&self) -> Option<&dyn ApiObject>;

    /// Returns the object as a mutable reference.
    fn get_object_mut(&mut self) -> Option<&mut (dyn ApiObject + 'static)>;

    /// Returns the existing object (only populated for UPDATE and DELETE requests).
    fn get_old_object(&self) -> Option<&dyn ApiObject>;

    /// Returns the kind of object being manipulated.
    fn get_kind(&self) -> &GroupVersionKind;

    /// Check if this request is a dry run.
    fn is_dry_run(&self) -> bool;
}

/// AttributesRecord is a concrete implementation of Attributes.
pub struct AttributesRecord {
    pub name: String,
    pub namespace: String,
    pub resource: GroupVersionResource,
    pub subresource: String,
    pub operation: Operation,
    pub object: Option<Box<dyn ApiObject>>,
    pub old_object: Option<Box<dyn ApiObject>>,
    pub kind: GroupVersionKind,
    pub dry_run: bool,
}

impl AttributesRecord {
    /// Create a new AttributesRecord for testing or general use.
    pub fn new(
        name: &str,
        namespace: &str,
        resource: GroupVersionResource,
        subresource: &str,
        operation: Operation,
        object: Option<Box<dyn ApiObject>>,
        old_object: Option<Box<dyn ApiObject>>,
        kind: GroupVersionKind,
        dry_run: bool,
    ) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            resource,
            subresource: subresource.to_string(),
            operation,
            object,
            old_object,
            kind,
            dry_run,
        }
    }

    /// Helper to create attributes for a Pod resource.
    pub fn new_pod(
        name: &str,
        namespace: &str,
        operation: Operation,
        pod: Pod,
        old_pod: Option<Pod>,
    ) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            resource: GroupVersionResource::new("", "v1", "pods"),
            subresource: String::new(),
            operation,
            object: Some(Box::new(pod)),
            old_object: old_pod.map(|p| Box::new(p) as Box<dyn ApiObject>),
            kind: GroupVersionKind::new("", "v1", "Pod"),
            dry_run: false,
        }
    }

    /// Get the pod from the object, if it is a pod.
    pub fn get_pod(&self) -> Option<&Pod> {
        self.object
            .as_ref()
            .and_then(|obj| obj.as_any().downcast_ref::<Pod>())
    }

    /// Get a mutable reference to the pod from the object.
    pub fn get_pod_mut(&mut self) -> Option<&mut Pod> {
        self.object
            .as_mut()
            .and_then(|obj| obj.as_any_mut().downcast_mut::<Pod>())
    }

    /// Get the old pod from the old object, if it is a pod.
    pub fn get_old_pod(&self) -> Option<&Pod> {
        self.old_object
            .as_ref()
            .and_then(|obj| obj.as_any().downcast_ref::<Pod>())
    }
}

impl Attributes for AttributesRecord {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_namespace(&self) -> &str {
        &self.namespace
    }

    fn get_resource(&self) -> &GroupVersionResource {
        &self.resource
    }

    fn get_subresource(&self) -> &str {
        &self.subresource
    }

    fn get_operation(&self) -> Operation {
        self.operation
    }

    fn get_object(&self) -> Option<&dyn ApiObject> {
        self.object.as_ref().map(|o| o.as_ref())
    }

    fn get_object_mut(&mut self) -> Option<&mut (dyn ApiObject + 'static)> {
        self.object.as_mut().map(|o| &mut **o)
    }

    fn get_old_object(&self) -> Option<&dyn ApiObject> {
        self.old_object.as_ref().map(|o| o.as_ref())
    }

    fn get_kind(&self) -> &GroupVersionKind {
        &self.kind
    }

    fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::core::{Container, PodSpec, PullPolicy};

    #[test]
    fn test_attributes_record_new_pod() {
        let pod = Pod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            spec: PodSpec { affinity: None, tolerations: vec![],
                init_containers: vec![],
                containers: vec![Container {
                    name: "test".to_string(),
                    image: "nginx".to_string(),
                    image_pull_policy: PullPolicy::IfNotPresent,
                    resources: crate::api::core::ResourceRequirements::default(),
                }],
                ephemeral_containers: vec![],
                volumes: vec![],
            },
        };

        let attrs = AttributesRecord::new_pod("test-pod", "default", Operation::Create, pod, None);

        assert_eq!(attrs.get_name(), "test-pod");
        assert_eq!(attrs.get_namespace(), "default");
        assert_eq!(attrs.get_operation(), Operation::Create);
        assert_eq!(attrs.get_resource().resource, "pods");
        assert!(attrs.get_pod().is_some());
    }

    #[test]
    fn test_group_version_resource() {
        let gvr = GroupVersionResource::new("apps", "v1", "deployments");
        assert_eq!(gvr.group, "apps");
        assert_eq!(gvr.version, "v1");
        assert_eq!(gvr.resource, "deployments");

        let gr = gvr.group_resource();
        assert_eq!(gr.group, "apps");
        assert_eq!(gr.resource, "deployments");
    }
}
