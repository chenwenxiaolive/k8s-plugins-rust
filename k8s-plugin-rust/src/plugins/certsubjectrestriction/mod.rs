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

//! CertificateSubjectRestriction admission controller.
//!
//! This admission controller prevents CSRs with signer `kubernetes.io/kube-apiserver-client`
//! from using the `system:masters` group in their subject.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the CertificateSubjectRestriction admission controller.
pub const PLUGIN_NAME: &str = "CertificateSubjectRestriction";

/// The signer name that is restricted.
pub const KUBE_APISERVER_CLIENT_SIGNER: &str = "kubernetes.io/kube-apiserver-client";

/// The group that is not allowed with the kube-apiserver-client signer.
pub const SYSTEM_MASTERS_GROUP: &str = "system:masters";

/// Register the CertificateSubjectRestriction plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Plugin validates CertificateSigningRequests to prevent system:masters group usage.
pub struct Plugin {
    handler: Handler,
}

impl Plugin {
    /// Create a new CertificateSubjectRestriction admission controller.
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

impl ValidationInterface for Plugin {
    /// Validate prevents CSRs with kube-apiserver-client signer from using system:masters group.
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // Only process certificatesigningrequests
        let resource = attributes.get_resource();
        if resource.resource != "certificatesigningrequests" {
            return Ok(());
        }

        // Ignore subresources like "approve"
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        // Get the CSR object
        let obj = attributes.get_object();
        let csr = match obj {
            Some(o) => match o.as_any().downcast_ref::<CertificateSigningRequest>() {
                Some(c) => c,
                None => {
                    return Err(AdmissionError::bad_request(
                        "expected CertificateSigningRequest but got different type",
                    ));
                }
            },
            None => return Ok(()),
        };

        // Only check kube-apiserver-client signer
        if csr.spec.signer_name != KUBE_APISERVER_CLIENT_SIGNER {
            return Ok(());
        }

        // Check if any organization is system:masters
        for org in &csr.spec.groups {
            if org == SYSTEM_MASTERS_GROUP {
                return Err(AdmissionError::forbidden(
                    &csr.name,
                    "",
                    "certificatesigningrequests",
                    crate::admission::errors::FieldError {
                        field: "spec.request".to_string(),
                        error_type: crate::admission::errors::FieldErrorType::Invalid,
                        value: format!(
                            "use of {} signer with {} group is not allowed",
                            KUBE_APISERVER_CLIENT_SIGNER, SYSTEM_MASTERS_GROUP
                        ),
                        supported_values: vec![],
                    },
                ));
            }
        }

        Ok(())
    }
}

/// CertificateSigningRequest represents a CSR resource.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateSigningRequest {
    pub name: String,
    pub spec: CertificateSigningRequestSpec,
}

impl CertificateSigningRequest {
    pub fn new(name: &str, signer_name: &str, groups: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            spec: CertificateSigningRequestSpec {
                signer_name: signer_name.to_string(),
                groups,
                request: Vec::new(),
            },
        }
    }
}

impl crate::api::core::ApiObject for CertificateSigningRequest {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "CertificateSigningRequest"
    }
}

/// CertificateSigningRequestSpec is the spec for a CSR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CertificateSigningRequestSpec {
    pub signer_name: String,
    pub groups: Vec<String>,
    pub request: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    #[test]
    fn test_ignored_resource() {
        let plugin = Plugin::new();

        let pod = crate::api::core::Pod::new("test", "default");
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

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should ignore non-CSR resources");
    }

    #[test]
    fn test_ignored_subresource() {
        let plugin = Plugin::new();

        let csr = CertificateSigningRequest::new(
            "test-csr",
            KUBE_APISERVER_CLIENT_SIGNER,
            vec![SYSTEM_MASTERS_GROUP.to_string()],
        );

        let attrs = AttributesRecord::new(
            "test-csr",
            "",
            GroupVersionResource::new("certificates.k8s.io", "v1", "certificatesigningrequests"),
            "approve", // subresource
            Operation::Update,
            Some(Box::new(csr)),
            None,
            GroupVersionKind::new("certificates.k8s.io", "v1", "CertificateSigningRequest"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should ignore subresources");
    }

    #[test]
    fn test_other_signer_allowed() {
        let plugin = Plugin::new();

        let csr = CertificateSigningRequest::new(
            "test-csr",
            "kubernetes.io/kubelet-serving",
            vec![SYSTEM_MASTERS_GROUP.to_string()],
        );

        let attrs = AttributesRecord::new(
            "test-csr",
            "",
            GroupVersionResource::new("certificates.k8s.io", "v1", "certificatesigningrequests"),
            "",
            Operation::Create,
            Some(Box::new(csr)),
            None,
            GroupVersionKind::new("certificates.k8s.io", "v1", "CertificateSigningRequest"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow system:masters with other signers");
    }

    #[test]
    fn test_other_group_allowed() {
        let plugin = Plugin::new();

        let csr = CertificateSigningRequest::new(
            "test-csr",
            KUBE_APISERVER_CLIENT_SIGNER,
            vec!["system:admin".to_string()],
        );

        let attrs = AttributesRecord::new(
            "test-csr",
            "",
            GroupVersionResource::new("certificates.k8s.io", "v1", "certificatesigningrequests"),
            "",
            Operation::Create,
            Some(Box::new(csr)),
            None,
            GroupVersionKind::new("certificates.k8s.io", "v1", "CertificateSigningRequest"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow other groups with kube-apiserver-client signer");
    }

    #[test]
    fn test_system_masters_rejected() {
        let plugin = Plugin::new();

        let csr = CertificateSigningRequest::new(
            "test-csr",
            KUBE_APISERVER_CLIENT_SIGNER,
            vec![SYSTEM_MASTERS_GROUP.to_string()],
        );

        let attrs = AttributesRecord::new(
            "test-csr",
            "",
            GroupVersionResource::new("certificates.k8s.io", "v1", "certificatesigningrequests"),
            "",
            Operation::Create,
            Some(Box::new(csr)),
            None,
            GroupVersionKind::new("certificates.k8s.io", "v1", "CertificateSigningRequest"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(
            result.is_err(),
            "Should reject system:masters with kube-apiserver-client signer"
        );
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
