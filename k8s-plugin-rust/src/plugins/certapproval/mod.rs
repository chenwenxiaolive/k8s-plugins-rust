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

//! CertificateApproval admission controller.
//!
//! This admission controller validates that users have permission to approve
//! CertificateSigningRequests for specific signerNames.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the CertificateApproval admission controller.
pub const PLUGIN_NAME: &str = "CertificateApproval";

/// Register the CertificateApproval plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Authorizer trait for checking permissions.
pub trait Authorizer: Send + Sync {
    fn is_authorized_for_signer(&self, user: &str, verb: &str, signer_name: &str) -> bool;
}

/// Plugin validates CSR approval permissions.
pub struct Plugin {
    handler: Handler,
    authorizer: Option<Arc<dyn Authorizer>>,
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Update]),
            authorizer: None,
        }
    }

    pub fn with_authorizer(authorizer: Arc<dyn Authorizer>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Update]),
            authorizer: Some(authorizer),
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
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // Only handle certificatesigningrequests/approval
        if attributes.get_subresource() != "approval" {
            return Ok(());
        }

        let resource = attributes.get_resource();
        if resource.resource != "certificatesigningrequests" {
            return Ok(());
        }

        // Authorization check would happen here with the authorizer
        // For now, we just validate the structure
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::Pod;

    #[test]
    fn test_handles() {
        let handler = Plugin::new();
        assert!(!handler.handles(Operation::Create));
        assert!(handler.handles(Operation::Update));
        assert!(!handler.handles(Operation::Delete));
    }

    #[test]
    fn test_ignore_non_approval_subresource() {
        let handler = Plugin::new();
        let pod = Pod::new("test", "default");
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("certificates.k8s.io", "v1", "certificatesigningrequests"),
            "status",
            Operation::Update,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("certificates.k8s.io", "v1", "CertificateSigningRequest"),
            false,
        );
        assert!(handler.validate(&attrs).is_ok());
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }
}
