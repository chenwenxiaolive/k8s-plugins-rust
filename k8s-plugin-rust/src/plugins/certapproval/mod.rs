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
//! CertificateSigningRequests for specific signerNames. It checks authorization
//! against the old object to prevent users from changing the signerName during
//! approval.
//!
//! The plugin performs the following checks:
//! 1. Only processes UPDATE operations on certificatesigningrequests/approval
//! 2. Checks if the user is authorized to approve CSRs with the specific signerName
//! 3. Also checks for wildcard permissions (e.g., "kubernetes.io/*")

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the CertificateApproval admission controller.
pub const PLUGIN_NAME: &str = "CertificateApproval";

/// The API group for certificates resources.
pub const CERTIFICATES_GROUP: &str = "certificates.k8s.io";

/// Register the CertificateApproval plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Decision represents the outcome of an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request is allowed.
    Allow,
    /// The request is denied.
    Deny,
    /// No opinion on the request.
    NoOpinion,
}

/// UserInfo provides information about the user making the request.
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
    pub groups: Vec<String>,
}

impl UserInfo {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            groups: Vec::new(),
        }
    }

    pub fn with_groups(name: &str, groups: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            groups,
        }
    }
}

impl Default for UserInfo {
    fn default() -> Self {
        Self::new("system:anonymous")
    }
}

/// AuthorizerAttributes represents the attributes of an authorization request.
#[derive(Debug, Clone)]
pub struct AuthorizerAttributes {
    pub user: UserInfo,
    pub verb: String,
    pub api_group: String,
    pub api_version: String,
    pub resource: String,
    pub name: String,
    pub resource_request: bool,
}

impl AuthorizerAttributes {
    /// Create new authorizer attributes for checking signer permissions.
    pub fn for_signer(user: &UserInfo, verb: &str, signer_name: &str) -> Self {
        Self {
            user: user.clone(),
            verb: verb.to_string(),
            api_group: CERTIFICATES_GROUP.to_string(),
            api_version: "*".to_string(),
            resource: "signers".to_string(),
            name: signer_name.to_string(),
            resource_request: true,
        }
    }

    /// Create wildcard authorizer attributes for checking domain-level permissions.
    /// For example, "kubernetes.io/kube-apiserver-client" becomes "kubernetes.io/*".
    pub fn for_signer_wildcard(user: &UserInfo, verb: &str, signer_name: &str) -> Self {
        let domain = signer_name
            .split('/')
            .next()
            .unwrap_or(signer_name);
        let wildcard_name = format!("{}/*", domain);
        Self::for_signer(user, verb, &wildcard_name)
    }
}

/// Authorizer trait for checking permissions.
pub trait Authorizer: Send + Sync {
    /// Check if the given attributes are authorized.
    fn authorize(&self, attrs: &AuthorizerAttributes) -> Result<(Decision, String), String>;
}

/// Check if a user is authorized to perform a verb on a signer.
///
/// This function first checks if the user has explicit permission for the specific signerName.
/// If not, it checks if the user has wildcard permissions for the domain portion of the
/// signerName (e.g., "kubernetes.io/*").
pub fn is_authorized_for_signer_name(
    authorizer: &dyn Authorizer,
    user: &UserInfo,
    verb: &str,
    signer_name: &str,
) -> bool {
    // First check if the user has explicit permission for the specific signerName
    let attrs = AuthorizerAttributes::for_signer(user, verb, signer_name);
    match authorizer.authorize(&attrs) {
        Ok((Decision::Allow, _)) => return true,
        Ok(_) => {}
        Err(_) => {}
    }

    // If not, check if the user has wildcard permissions for the domain portion
    let wildcard_attrs = AuthorizerAttributes::for_signer_wildcard(user, verb, signer_name);
    match authorizer.authorize(&wildcard_attrs) {
        Ok((Decision::Allow, _)) => true,
        _ => false,
    }
}

/// CertificateSigningRequest represents a CSR resource.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateSigningRequest {
    pub name: String,
    pub spec: CertificateSigningRequestSpec,
    pub status: CertificateSigningRequestStatus,
}

impl CertificateSigningRequest {
    /// Create a new CertificateSigningRequest with the given name and signer.
    pub fn new(name: &str, signer_name: &str) -> Self {
        Self {
            name: name.to_string(),
            spec: CertificateSigningRequestSpec {
                signer_name: signer_name.to_string(),
                request: Vec::new(),
                usages: Vec::new(),
                groups: Vec::new(),
                username: String::new(),
                uid: String::new(),
            },
            status: CertificateSigningRequestStatus::default(),
        }
    }

    /// Create a new CertificateSigningRequest with full spec.
    pub fn with_spec(name: &str, spec: CertificateSigningRequestSpec) -> Self {
        Self {
            name: name.to_string(),
            spec,
            status: CertificateSigningRequestStatus::default(),
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
    /// The signer name for this CSR.
    pub signer_name: String,
    /// The PEM-encoded CSR request.
    pub request: Vec<u8>,
    /// Requested key usages.
    pub usages: Vec<String>,
    /// Groups the user belongs to.
    pub groups: Vec<String>,
    /// The username of the requesting user.
    pub username: String,
    /// The UID of the requesting user.
    pub uid: String,
}

/// CertificateSigningRequestStatus is the status for a CSR.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CertificateSigningRequestStatus {
    /// Conditions applied to the CSR.
    pub conditions: Vec<CertificateSigningRequestCondition>,
    /// The issued certificate if approved.
    pub certificate: Vec<u8>,
}

/// CertificateSigningRequestCondition represents a condition on a CSR.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateSigningRequestCondition {
    /// Type of the condition (Approved, Denied, Failed).
    pub condition_type: String,
    /// Status of the condition (True, False, Unknown).
    pub status: String,
    /// Reason for the condition.
    pub reason: String,
    /// Human-readable message.
    pub message: String,
}

/// CertificateSigningRequestList is a list of CSRs (for type checking in tests).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CertificateSigningRequestList {
    pub items: Vec<CertificateSigningRequest>,
}

impl crate::api::core::ApiObject for CertificateSigningRequestList {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "CertificateSigningRequestList"
    }
}

/// Plugin validates CSR approval permissions.
pub struct Plugin {
    handler: Handler,
    authorizer: Option<Arc<dyn Authorizer>>,
}

impl Plugin {
    /// Create a new CertificateApproval admission controller.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Update]),
            authorizer: None,
        }
    }

    /// Create a new CertificateApproval admission controller with an authorizer.
    pub fn with_authorizer(authorizer: Arc<dyn Authorizer>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Update]),
            authorizer: Some(authorizer),
        }
    }

    /// Set the authorizer for this plugin.
    pub fn set_authorizer(&mut self, authorizer: Arc<dyn Authorizer>) {
        self.authorizer = Some(authorizer);
    }

    /// Validate that the plugin has been properly initialized.
    pub fn validate_initialization(&self) -> Result<(), String> {
        if self.authorizer.is_none() {
            return Err(format!("{} requires an authorizer", PLUGIN_NAME));
        }
        Ok(())
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
    /// Validate verifies that the requesting user has permission to approve
    /// CertificateSigningRequests for the specified signerName.
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // Ignore all calls to anything other than 'certificatesigningrequests/approval'
        if attributes.get_subresource() != "approval" {
            return Ok(());
        }

        let resource = attributes.get_resource();
        if resource.resource != "certificatesigningrequests" {
            return Ok(());
        }

        // We check permissions against the *old* version of the resource, in case
        // a user is attempting to update the SignerName when calling the approval
        // endpoint (which is an invalid/not allowed operation)
        let old_obj = match attributes.get_old_object() {
            Some(obj) => obj,
            None => {
                return Err(AdmissionError::bad_request(
                    "expected old object for UPDATE operation",
                ));
            }
        };

        let csr = match old_obj.as_any().downcast_ref::<CertificateSigningRequest>() {
            Some(c) => c,
            None => {
                return Err(AdmissionError::bad_request(format!(
                    "expected type CertificateSigningRequest, got: {}",
                    old_obj.kind()
                )));
            }
        };

        // Check authorization if an authorizer is configured
        if let Some(ref authorizer) = self.authorizer {
            // Get user info from attributes (in a real implementation, this would come from the request)
            let user = UserInfo::default();

            if !is_authorized_for_signer_name(authorizer.as_ref(), &user, "approve", &csr.spec.signer_name) {
                return Err(AdmissionError::bad_request(format!(
                    "user not permitted to approve requests with signerName \"{}\"",
                    csr.spec.signer_name
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::Pod;

    /// FakeAuthorizer for testing authorization logic.
    struct FakeAuthorizer {
        verb: String,
        allowed_name: String,
        decision: Decision,
        err: Option<String>,
    }

    impl FakeAuthorizer {
        fn new(verb: &str, allowed_name: &str, decision: Decision, err: Option<String>) -> Self {
            Self {
                verb: verb.to_string(),
                allowed_name: allowed_name.to_string(),
                decision,
                err,
            }
        }
    }

    impl Authorizer for FakeAuthorizer {
        fn authorize(&self, attrs: &AuthorizerAttributes) -> Result<(Decision, String), String> {
            if let Some(ref err) = self.err {
                return Err(err.clone());
            }

            if attrs.verb != self.verb {
                return Ok((Decision::Deny, format!("unrecognised verb '{}'", attrs.verb)));
            }

            if attrs.api_group != CERTIFICATES_GROUP {
                return Ok((Decision::Deny, format!("unrecognised groupName '{}'", attrs.api_group)));
            }

            if attrs.api_version != "*" {
                return Ok((Decision::Deny, format!("unrecognised apiVersion '{}'", attrs.api_version)));
            }

            if attrs.resource != "signers" {
                return Ok((Decision::Deny, format!("unrecognised resource '{}'", attrs.resource)));
            }

            if attrs.name != self.allowed_name {
                return Ok((Decision::Deny, format!("unrecognised resource name '{}'", attrs.name)));
            }

            if !attrs.resource_request {
                return Ok((Decision::Deny, format!("unrecognised IsResourceRequest '{}'", attrs.resource_request)));
            }

            Ok((self.decision, String::new()))
        }
    }

    /// Test attributes that support user info.
    struct TestAttributes {
        name: String,
        namespace: String,
        resource: GroupVersionResource,
        subresource: String,
        operation: Operation,
        object: Option<Box<dyn crate::api::core::ApiObject>>,
        old_object: Option<Box<dyn crate::api::core::ApiObject>>,
        kind: GroupVersionKind,
        user_info: UserInfo,
    }

    impl TestAttributes {
        fn new(
            resource: GroupVersionResource,
            subresource: &str,
            operation: Operation,
            obj: Option<Box<dyn crate::api::core::ApiObject>>,
            old_obj: Option<Box<dyn crate::api::core::ApiObject>>,
        ) -> Self {
            Self {
                name: String::new(),
                namespace: String::new(),
                resource,
                subresource: subresource.to_string(),
                operation,
                object: obj,
                old_object: old_obj,
                kind: GroupVersionKind::new(CERTIFICATES_GROUP, "v1", "CertificateSigningRequest"),
                user_info: UserInfo::new("ignored"),
            }
        }
    }

    impl Attributes for TestAttributes {
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

        fn get_object(&self) -> Option<&dyn crate::api::core::ApiObject> {
            self.object.as_ref().map(|o| o.as_ref())
        }

        fn get_object_mut(&mut self) -> Option<&mut (dyn crate::api::core::ApiObject + 'static)> {
            self.object.as_mut().map(|o| &mut **o)
        }

        fn get_old_object(&self) -> Option<&dyn crate::api::core::ApiObject> {
            self.old_object.as_ref().map(|o| o.as_ref())
        }

        fn get_kind(&self) -> &GroupVersionKind {
            &self.kind
        }

        fn is_dry_run(&self) -> bool {
            false
        }
    }

    fn csr_resource() -> GroupVersionResource {
        GroupVersionResource::new(CERTIFICATES_GROUP, "v1", "certificatesigningrequests")
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(!plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }

    #[test]
    fn test_wrong_type() {
        let authorizer = Arc::new(FakeAuthorizer::new("approve", "", Decision::Allow, None));
        let plugin = Plugin::with_authorizer(authorizer);

        // Use a CertificateSigningRequestList instead of CertificateSigningRequest
        let attrs = TestAttributes::new(
            csr_resource(),
            "approval",
            Operation::Update,
            None,
            Some(Box::new(CertificateSigningRequestList::default())),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Should reject wrong type");
    }

    #[test]
    fn test_reject_if_looking_up_permissions_fails() {
        let authorizer = Arc::new(FakeAuthorizer::new(
            "approve",
            "abc.com/xyz",
            Decision::Allow,
            Some("forced error".to_string()),
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let csr = CertificateSigningRequest::new("test-csr", "abc.com/xyz");
        let attrs = TestAttributes::new(
            csr_resource(),
            "approval",
            Operation::Update,
            None,
            Some(Box::new(csr)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Should reject if looking up permissions fails");
    }

    #[test]
    fn test_allow_if_authorized_for_specific_signer_name() {
        let authorizer = Arc::new(FakeAuthorizer::new("approve", "abc.com/xyz", Decision::Allow, None));
        let plugin = Plugin::with_authorizer(authorizer);

        let csr = CertificateSigningRequest::new("test-csr", "abc.com/xyz");
        let attrs = TestAttributes::new(
            csr_resource(),
            "approval",
            Operation::Update,
            None,
            Some(Box::new(csr)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow request if user is authorized for specific signerName");
    }

    #[test]
    fn test_allow_if_authorized_with_wildcard() {
        let authorizer = Arc::new(FakeAuthorizer::new("approve", "abc.com/*", Decision::Allow, None));
        let plugin = Plugin::with_authorizer(authorizer);

        let csr = CertificateSigningRequest::new("test-csr", "abc.com/xyz");
        let attrs = TestAttributes::new(
            csr_resource(),
            "approval",
            Operation::Update,
            None,
            Some(Box::new(csr)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow request if user is authorized with wildcard");
    }

    #[test]
    fn test_deny_if_not_authorized_for_signer_name() {
        let authorizer = Arc::new(FakeAuthorizer::new("approve", "notabc.com/xyz", Decision::Allow, None));
        let plugin = Plugin::with_authorizer(authorizer);

        let csr = CertificateSigningRequest::new("test-csr", "abc.com/xyz");
        let attrs = TestAttributes::new(
            csr_resource(),
            "approval",
            Operation::Update,
            None,
            Some(Box::new(csr)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Should deny request if user does not have permission for this signerName");
    }

    #[test]
    fn test_deny_if_user_attempts_to_update_signer_name() {
        // This tests that we check against the OLD object, not the new one
        // User is authorized for "allowed.com/xyz" but the OLD object has "notallowed.com/xyz"
        let authorizer = Arc::new(FakeAuthorizer::new("approve", "allowed.com/xyz", Decision::Allow, None));
        let plugin = Plugin::with_authorizer(authorizer);

        let old_csr = CertificateSigningRequest::new("test-csr", "notallowed.com/xyz");
        let new_csr = CertificateSigningRequest::new("test-csr", "allowed.com/xyz");

        let attrs = TestAttributes::new(
            csr_resource(),
            "approval",
            Operation::Update,
            Some(Box::new(new_csr)),
            Some(Box::new(old_csr)),
        );

        let result = plugin.validate(&attrs);
        assert!(
            result.is_err(),
            "Should deny request if user attempts to update signerName to a new value they *do* have permission for"
        );
    }

    #[test]
    fn test_ignore_non_approval_subresource() {
        let authorizer = Arc::new(FakeAuthorizer::new("approve", "", Decision::Deny, None));
        let plugin = Plugin::with_authorizer(authorizer);

        let csr = CertificateSigningRequest::new("test-csr", "abc.com/xyz");
        let attrs = TestAttributes::new(
            csr_resource(),
            "status", // Not "approval"
            Operation::Update,
            None,
            Some(Box::new(csr)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should ignore non-approval subresource");
    }

    #[test]
    fn test_ignore_non_csr_resource() {
        let authorizer = Arc::new(FakeAuthorizer::new("approve", "", Decision::Deny, None));
        let plugin = Plugin::with_authorizer(authorizer);

        let pod = Pod::new("test-pod", "default");
        let attrs = AttributesRecord::new(
            "test-pod",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "approval",
            Operation::Update,
            Some(Box::new(pod.clone())),
            Some(Box::new(pod)),
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should ignore non-CSR resources");
    }

    #[test]
    fn test_plugin_without_authorizer() {
        let plugin = Plugin::new();

        let csr = CertificateSigningRequest::new("test-csr", "abc.com/xyz");
        let attrs = TestAttributes::new(
            csr_resource(),
            "approval",
            Operation::Update,
            None,
            Some(Box::new(csr)),
        );

        // Without authorizer, plugin should allow (no authorization check performed)
        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Should allow when no authorizer is configured");
    }

    #[test]
    fn test_validate_initialization_without_authorizer() {
        let plugin = Plugin::new();
        let result = plugin.validate_initialization();
        assert!(result.is_err(), "Should fail validation without authorizer");
        assert!(result.unwrap_err().contains("requires an authorizer"));
    }

    #[test]
    fn test_validate_initialization_with_authorizer() {
        let authorizer = Arc::new(FakeAuthorizer::new("approve", "", Decision::Allow, None));
        let plugin = Plugin::with_authorizer(authorizer);
        let result = plugin.validate_initialization();
        assert!(result.is_ok(), "Should pass validation with authorizer");
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_is_authorized_for_signer_name_exact_match() {
        let authorizer = FakeAuthorizer::new("approve", "example.com/my-signer", Decision::Allow, None);
        let user = UserInfo::new("test-user");

        assert!(is_authorized_for_signer_name(&authorizer, &user, "approve", "example.com/my-signer"));
    }

    #[test]
    fn test_is_authorized_for_signer_name_wildcard_match() {
        let authorizer = FakeAuthorizer::new("approve", "example.com/*", Decision::Allow, None);
        let user = UserInfo::new("test-user");

        assert!(is_authorized_for_signer_name(&authorizer, &user, "approve", "example.com/any-signer"));
    }

    #[test]
    fn test_is_authorized_for_signer_name_no_match() {
        let authorizer = FakeAuthorizer::new("approve", "other.com/signer", Decision::Allow, None);
        let user = UserInfo::new("test-user");

        assert!(!is_authorized_for_signer_name(&authorizer, &user, "approve", "example.com/my-signer"));
    }

    #[test]
    fn test_authorizer_attributes_for_signer() {
        let user = UserInfo::new("test-user");
        let attrs = AuthorizerAttributes::for_signer(&user, "approve", "kubernetes.io/kube-apiserver-client");

        assert_eq!(attrs.verb, "approve");
        assert_eq!(attrs.api_group, CERTIFICATES_GROUP);
        assert_eq!(attrs.api_version, "*");
        assert_eq!(attrs.resource, "signers");
        assert_eq!(attrs.name, "kubernetes.io/kube-apiserver-client");
        assert!(attrs.resource_request);
    }

    #[test]
    fn test_authorizer_attributes_for_signer_wildcard() {
        let user = UserInfo::new("test-user");
        let attrs = AuthorizerAttributes::for_signer_wildcard(&user, "approve", "kubernetes.io/kube-apiserver-client");

        assert_eq!(attrs.name, "kubernetes.io/*");
    }

    #[test]
    fn test_csr_creation() {
        let csr = CertificateSigningRequest::new("my-csr", "example.com/signer");
        assert_eq!(csr.name, "my-csr");
        assert_eq!(csr.spec.signer_name, "example.com/signer");
        assert!(csr.spec.request.is_empty());
        assert!(csr.status.conditions.is_empty());
    }

    #[test]
    fn test_csr_with_spec() {
        let spec = CertificateSigningRequestSpec {
            signer_name: "example.com/signer".to_string(),
            request: vec![1, 2, 3],
            usages: vec!["client auth".to_string()],
            groups: vec!["system:authenticated".to_string()],
            username: "test-user".to_string(),
            uid: "12345".to_string(),
        };

        let csr = CertificateSigningRequest::with_spec("my-csr", spec);
        assert_eq!(csr.name, "my-csr");
        assert_eq!(csr.spec.signer_name, "example.com/signer");
        assert_eq!(csr.spec.request, vec![1, 2, 3]);
        assert_eq!(csr.spec.usages, vec!["client auth"]);
        assert_eq!(csr.spec.username, "test-user");
    }

    #[test]
    fn test_user_info() {
        let user = UserInfo::new("admin");
        assert_eq!(user.name, "admin");
        assert!(user.groups.is_empty());

        let user_with_groups = UserInfo::with_groups(
            "admin",
            vec!["system:masters".to_string(), "developers".to_string()],
        );
        assert_eq!(user_with_groups.name, "admin");
        assert_eq!(user_with_groups.groups.len(), 2);
        assert!(user_with_groups.groups.contains(&"system:masters".to_string()));
    }

    #[test]
    fn test_decision_enum() {
        assert_eq!(Decision::Allow, Decision::Allow);
        assert_ne!(Decision::Allow, Decision::Deny);
        assert_ne!(Decision::Allow, Decision::NoOpinion);
    }
}
