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

//! AlwaysPullImages admission controller.
//!
//! This admission controller modifies every new Pod to force the image pull policy to Always.
//! This is useful in a multitenant cluster so that users can be assured that their private
//! images can only be used by those who have the credentials to pull them.
//!
//! Without this admission controller, once an image has been pulled to a node, any pod from
//! any user can use it simply by knowing the image's name (assuming the Pod is scheduled
//! onto the right node), without any authorization check against the image.
//!
//! With this admission controller enabled, images are always pulled prior to starting
//! containers, which means valid credentials are required.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface,
    MutationInterface, Operation, Plugins, ValidationInterface,
    errors::field_not_supported,
};
use crate::api::core::{resource, Pod, PullPolicy};
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the AlwaysPullImages admission controller.
pub const PLUGIN_NAME: &str = "AlwaysPullImages";

/// Register the AlwaysPullImages plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(AlwaysPullImages::new()) as Arc<dyn Interface>)
    });
}

/// AlwaysPullImages is an implementation of admission.Interface.
/// It looks at all new pods and overrides each container's image pull policy to Always.
pub struct AlwaysPullImages {
    handler: Handler,
}

impl AlwaysPullImages {
    /// Create a new AlwaysPullImages admission controller.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
        }
    }

    /// Check if this request should be ignored (non-pod resources, subresources, or
    /// updates with no new images).
    fn should_ignore(&self, attributes: &dyn Attributes) -> bool {
        // Ignore all calls to subresources or resources other than pods.
        if !attributes.get_subresource().is_empty() {
            return true;
        }

        let gr = attributes.get_resource().group_resource();
        if gr != resource("pods") {
            return true;
        }

        // Check if it's an update with no new images
        if self.is_update_with_no_new_images(attributes) {
            return true;
        }

        false
    }

    /// Check if it's an update operation that doesn't change the images referenced by the pod spec.
    fn is_update_with_no_new_images(&self, attributes: &dyn Attributes) -> bool {
        if attributes.get_operation() != Operation::Update {
            return false;
        }

        let pod = match attributes.get_object() {
            Some(obj) => match obj.as_any().downcast_ref::<Pod>() {
                Some(p) => p,
                None => return false,
            },
            None => return false,
        };

        let old_pod = match attributes.get_old_object() {
            Some(obj) => match obj.as_any().downcast_ref::<Pod>() {
                Some(p) => p,
                None => return false,
            },
            None => return false,
        };

        let old_images = old_pod.spec.get_all_images();

        let mut has_new_image = false;
        pod.spec.visit_containers_with_path("spec", |c, _| {
            if !old_images.contains(&c.image) {
                has_new_image = true;
                return false; // Stop iteration
            }
            true
        });

        !has_new_image
    }
}

impl Default for AlwaysPullImages {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for AlwaysPullImages {
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl MutationInterface for AlwaysPullImages {
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Ignore all calls to subresources or resources other than pods.
        if self.should_ignore(attributes) {
            return Ok(());
        }

        // Get the pod object
        let pod = match attributes.get_object_mut() {
            Some(obj) => match obj.as_any_mut().downcast_mut::<Pod>() {
                Some(p) => p,
                None => {
                    return Err(AdmissionError::bad_request(
                        "Resource was marked with kind Pod but was unable to be converted",
                    ))
                }
            },
            None => {
                return Err(AdmissionError::bad_request(
                    "Resource was marked with kind Pod but was unable to be converted",
                ))
            }
        };

        // Set all container image pull policies to Always
        pod.spec
            .visit_containers_with_path_mut("spec", |c, _path| {
                c.image_pull_policy = PullPolicy::Always;
                true
            });

        // Also handle image volumes (KEP-4639)
        for v in &mut pod.spec.volumes {
            if let Some(ref mut img) = v.volume_source.image {
                img.pull_policy = PullPolicy::Always;
            }
        }

        Ok(())
    }
}

impl ValidationInterface for AlwaysPullImages {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        if self.should_ignore(attributes) {
            return Ok(());
        }

        let pod = match attributes.get_object() {
            Some(obj) => match obj.as_any().downcast_ref::<Pod>() {
                Some(p) => p,
                None => {
                    return Err(AdmissionError::bad_request(
                        "Resource was marked with kind Pod but was unable to be converted",
                    ))
                }
            },
            None => {
                return Err(AdmissionError::bad_request(
                    "Resource was marked with kind Pod but was unable to be converted",
                ))
            }
        };

        let mut all_errors: Vec<AdmissionError> = Vec::new();

        // Check all containers have PullAlways
        pod.spec.visit_containers_with_path("spec", |c, path| {
            if c.image_pull_policy != PullPolicy::Always {
                all_errors.push(AdmissionError::forbidden(
                    attributes.get_name(),
                    attributes.get_namespace(),
                    "pods",
                    field_not_supported(
                        &format!("{}.imagePullPolicy", path),
                        c.image_pull_policy.as_str(),
                        vec!["Always"],
                    ),
                ));
            }
            true
        });

        // Check image volumes (KEP-4639)
        for (i, v) in pod.spec.volumes.iter().enumerate() {
            if let Some(ref img) = v.volume_source.image {
                if img.pull_policy != PullPolicy::Always {
                    all_errors.push(AdmissionError::forbidden(
                        attributes.get_name(),
                        attributes.get_namespace(),
                        "pods",
                        field_not_supported(
                            &format!("spec.volumes[{}].image.pullPolicy", i),
                            img.pull_policy.as_str(),
                            vec!["Always"],
                        ),
                    ));
                }
            }
        }

        if !all_errors.is_empty() {
            return Err(AdmissionError::aggregate(all_errors));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::AttributesRecord;
    use crate::admission::attributes::{GroupVersionResource, GroupVersionKind};
    use crate::api::core::{Container, ImageVolumeSource, PodSpec, Service, Volume};

    /// Helper to create a pod attributes record for testing.
    fn new_pod_attributes(
        name: &str,
        namespace: &str,
        operation: Operation,
        pod: Pod,
        old_pod: Option<Pod>,
    ) -> AttributesRecord {
        AttributesRecord::new_pod(name, namespace, operation, pod, old_pod)
    }

    /// TestAdmission verifies all create requests for pods result in every container's image pull policy
    /// set to Always
    #[test]
    fn test_admission() {
        let handler = AlwaysPullImages::new();

        let pod = Pod { annotations: std::collections::HashMap::new(),
            name: "123".to_string(),
            namespace: "test".to_string(),
            spec: PodSpec { affinity: None, tolerations: vec![],
                init_containers: vec![
                    Container::new("init1", "image"),
                    Container::with_pull_policy("init2", "image", PullPolicy::Never),
                    Container::with_pull_policy("init3", "image", PullPolicy::IfNotPresent),
                    Container::with_pull_policy("init4", "image", PullPolicy::Always),
                ],
                containers: vec![
                    Container::new("ctr1", "image"),
                    Container::with_pull_policy("ctr2", "image", PullPolicy::Never),
                    Container::with_pull_policy("ctr3", "image", PullPolicy::IfNotPresent),
                    Container::with_pull_policy("ctr4", "image", PullPolicy::Always),
                ],
                ephemeral_containers: vec![],
                volumes: vec![
                    Volume::new_image(
                        "volume1",
                        ImageVolumeSource::new("image", PullPolicy::Never),
                    ),
                    Volume::new_image(
                        "volume2",
                        ImageVolumeSource::new("image", PullPolicy::IfNotPresent),
                    ),
                    Volume::new_image(
                        "volume3",
                        ImageVolumeSource::new("image", PullPolicy::Always),
                    ),
                ],
            },
        };

        let mut attrs = new_pod_attributes("123", "test", Operation::Create, pod, None);

        let result = handler.admit(&mut attrs);
        assert!(result.is_ok(), "Unexpected error returned from admission handler");

        // Check that all containers have PullAlways
        let pod = attrs.get_pod().unwrap();
        for c in &pod.spec.init_containers {
            assert_eq!(
                c.image_pull_policy,
                PullPolicy::Always,
                "Container {}: expected pull always, got {:?}",
                c.name,
                c.image_pull_policy
            );
        }
        for c in &pod.spec.containers {
            assert_eq!(
                c.image_pull_policy,
                PullPolicy::Always,
                "Container {}: expected pull always, got {:?}",
                c.name,
                c.image_pull_policy
            );
        }
        for v in &pod.spec.volumes {
            if let Some(ref img) = v.volume_source.image {
                assert_eq!(
                    img.pull_policy,
                    PullPolicy::Always,
                    "Image volume {}: expected pull always, got {:?}",
                    v.name,
                    img.pull_policy
                );
            }
        }
    }

    #[test]
    fn test_validate() {
        let handler = AlwaysPullImages::new();

        let pod = Pod { annotations: std::collections::HashMap::new(),
            name: "123".to_string(),
            namespace: "test".to_string(),
            spec: PodSpec { affinity: None, tolerations: vec![],
                init_containers: vec![
                    Container::new("init1", "image"), // Empty policy
                    Container::with_pull_policy("init2", "image", PullPolicy::Never),
                    Container::with_pull_policy("init3", "image", PullPolicy::IfNotPresent),
                    Container::with_pull_policy("init4", "image", PullPolicy::Always),
                ],
                containers: vec![
                    Container::new("ctr1", "image"), // Empty policy
                    Container::with_pull_policy("ctr2", "image", PullPolicy::Never),
                    Container::with_pull_policy("ctr3", "image", PullPolicy::IfNotPresent),
                    Container::with_pull_policy("ctr4", "image", PullPolicy::Always),
                ],
                ephemeral_containers: vec![],
                volumes: vec![
                    Volume::new_image(
                        "volume1",
                        ImageVolumeSource::new("image", PullPolicy::Empty),
                    ),
                    Volume::new_image(
                        "volume2",
                        ImageVolumeSource::new("image", PullPolicy::Never),
                    ),
                    Volume::new_image(
                        "volume3",
                        ImageVolumeSource::new("image", PullPolicy::IfNotPresent),
                    ),
                    Volume::new_image(
                        "volume4",
                        ImageVolumeSource::new("image", PullPolicy::Always),
                    ),
                ],
            },
        };

        let attrs = new_pod_attributes("123", "test", Operation::Create, pod, None);

        let result = handler.validate(&attrs);
        assert!(result.is_err(), "Expected validation error");

        let err = result.unwrap_err();
        let err_msg = err.to_string();

        // Check for expected errors (9 total: 3 init containers + 3 containers + 3 volumes)
        assert!(err_msg.contains("initContainers[0].imagePullPolicy"));
        assert!(err_msg.contains("initContainers[1].imagePullPolicy"));
        assert!(err_msg.contains("initContainers[2].imagePullPolicy"));
        assert!(err_msg.contains("containers[0].imagePullPolicy"));
        assert!(err_msg.contains("containers[1].imagePullPolicy"));
        assert!(err_msg.contains("containers[2].imagePullPolicy"));
        assert!(err_msg.contains("volumes[0].image.pullPolicy"));
        assert!(err_msg.contains("volumes[1].image.pullPolicy"));
        assert!(err_msg.contains("volumes[2].image.pullPolicy"));
    }

    /// TestOtherResources ensures that this admission controller is a no-op for other resources,
    /// subresources, and non-pods.
    #[test]
    fn test_other_resources() {
        let pod = Pod { annotations: std::collections::HashMap::new(),
            name: "testname".to_string(),
            namespace: "testnamespace".to_string(),
            spec: PodSpec { affinity: None, tolerations: vec![],
                init_containers: vec![],
                containers: vec![Container::with_pull_policy("ctr2", "image", PullPolicy::Never)],
                ephemeral_containers: vec![],
                volumes: vec![],
            },
        };

        struct TestCase {
            name: &'static str,
            kind: &'static str,
            resource: &'static str,
            subresource: &'static str,
            use_service: bool,
            expect_error: bool,
        }

        let test_cases = vec![
            TestCase {
                name: "non-pod resource",
                kind: "Foo",
                resource: "foos",
                subresource: "",
                use_service: false,
                expect_error: false,
            },
            TestCase {
                name: "pod subresource",
                kind: "Pod",
                resource: "pods",
                subresource: "exec",
                use_service: false,
                expect_error: false,
            },
            TestCase {
                name: "non-pod object",
                kind: "Pod",
                resource: "pods",
                subresource: "",
                use_service: true,
                expect_error: true,
            },
        ];

        for tc in test_cases {
            let handler = AlwaysPullImages::new();

            let mut attrs = if tc.use_service {
                AttributesRecord::new(
                    "testname",
                    "testnamespace",
                    GroupVersionResource::new("", "version", tc.resource),
                    tc.subresource,
                    Operation::Create,
                    Some(Box::new(Service { spec: crate::api::core::ServiceSpec::default(),
                        name: "test".to_string(),
                        namespace: "default".to_string(),
                    })),
                    None,
                    GroupVersionKind::new("", "version", tc.kind),
                    false,
                )
            } else {
                AttributesRecord::new(
                    "testname",
                    "testnamespace",
                    GroupVersionResource::new("", "version", tc.resource),
                    tc.subresource,
                    Operation::Create,
                    Some(Box::new(pod.clone())),
                    None,
                    GroupVersionKind::new("", "version", tc.kind),
                    false,
                )
            };

            let result = handler.admit(&mut attrs);

            if tc.expect_error {
                assert!(result.is_err(), "{}: unexpected nil error", tc.name);
                continue;
            }

            assert!(result.is_ok(), "{}: unexpected error: {:?}", tc.name, result);

            // For non-error cases with pod, check policy wasn't changed
            if !tc.use_service {
                if let Some(p) = attrs.get_pod() {
                    if !p.spec.containers.is_empty() {
                        assert_eq!(
                            p.spec.containers[0].image_pull_policy,
                            PullPolicy::Never,
                            "{}: image pull policy was changed",
                            tc.name
                        );
                    }
                }
            }
        }
    }

    /// TestUpdatePod ensures that this admission controller is a no-op for update pod if no
    /// images were changed in the new pod spec.
    #[test]
    fn test_update_pod() {
        let old_pod = Pod { annotations: std::collections::HashMap::new(),
            name: "testname".to_string(),
            namespace: "testnamespace".to_string(),
            spec: PodSpec { affinity: None, tolerations: vec![],
                init_containers: vec![],
                containers: vec![Container::with_pull_policy(
                    "ctr2",
                    "image",
                    PullPolicy::IfNotPresent,
                )],
                ephemeral_containers: vec![],
                volumes: vec![],
            },
        };

        // Only add new annotation (no image change)
        let pod = Pod { annotations: std::collections::HashMap::new(),
            name: "testname".to_string(),
            namespace: "testnamespace".to_string(),
            spec: PodSpec { affinity: None, tolerations: vec![],
                init_containers: vec![],
                containers: vec![Container::with_pull_policy(
                    "ctr2",
                    "image",
                    PullPolicy::IfNotPresent,
                )],
                ephemeral_containers: vec![],
                volumes: vec![],
            },
        };

        // Add new label and change image
        let pod_with_new_image = Pod { annotations: std::collections::HashMap::new(),
            name: "testname".to_string(),
            namespace: "testnamespace".to_string(),
            spec: PodSpec { affinity: None, tolerations: vec![],
                init_containers: vec![],
                containers: vec![Container::with_pull_policy(
                    "ctr2",
                    "image2", // Different image!
                    PullPolicy::IfNotPresent,
                )],
                ephemeral_containers: vec![],
                volumes: vec![],
            },
        };

        struct TestCase {
            name: &'static str,
            pod: Pod,
            old_pod: Pod,
            expect_ignore: bool,
        }

        let test_cases = vec![
            TestCase {
                name: "update IfNotPresent pod annotations",
                pod: pod.clone(),
                old_pod: old_pod.clone(),
                expect_ignore: true,
            },
            TestCase {
                name: "update IfNotPresent pod image",
                pod: pod_with_new_image,
                old_pod: old_pod.clone(),
                expect_ignore: false,
            },
        ];

        for tc in test_cases {
            let handler = AlwaysPullImages::new();

            let mut attrs = AttributesRecord::new(
                "testname",
                "testnamespace",
                GroupVersionResource::new("", "v1", "pods"),
                "", // No subresource
                Operation::Update,
                Some(Box::new(tc.pod)),
                Some(Box::new(tc.old_pod)),
                GroupVersionKind::new("", "v1", "Pod"),
                false,
            );

            let result = handler.admit(&mut attrs);
            assert!(result.is_ok(), "{}: unexpected error: {:?}", tc.name, result);

            let pod = attrs.get_pod().unwrap();
            if tc.expect_ignore {
                assert_eq!(
                    pod.spec.containers[0].image_pull_policy,
                    PullPolicy::IfNotPresent,
                    "{}: image pull policy was changed when it should have been ignored",
                    tc.name
                );
            } else {
                assert_eq!(
                    pod.spec.containers[0].image_pull_policy,
                    PullPolicy::Always,
                    "{}: image pull policy was not changed when it should have been",
                    tc.name
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
    }
}
