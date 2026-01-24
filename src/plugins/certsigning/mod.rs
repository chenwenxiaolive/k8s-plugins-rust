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

//! CertificateSigning admission controller.
//!
//! This admission controller validates that users have permission to sign
//! CertificateSigningRequests for specific signerNames. It checks the
//! `certificatesigningrequests/status` subresource on UPDATE operations.
//!
//! The plugin verifies that when the status.certificate or status.conditions
//! field is modified, the user has the "sign" permission for the CSR's signerName.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
    errors::{FieldError, FieldErrorType},
};
use std::any::Any;
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the CertificateSigning admission controller.
pub const PLUGIN_NAME: &str = "CertificateSigning";

/// CSR group resource identifier.
const CSR_RESOURCE: &str = "certificatesigningrequests";
/// Certificates API group.
const CERTIFICATES_GROUP: &str = "certificates.k8s.io";

/// Register the CertificateSigning plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

// ============================================================================
// Types for CertificateSigningRequest
// ============================================================================

/// Condition type for CertificateSigningRequest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestConditionType {
    /// The certificate request has been approved.
    Approved,
    /// The certificate request has been denied.
    Denied,
    /// The certificate request has failed.
    Failed,
}

impl RequestConditionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RequestConditionType::Approved => "Approved",
            RequestConditionType::Denied => "Denied",
            RequestConditionType::Failed => "Failed",
        }
    }
}

/// CertificateSigningRequestCondition describes a condition of a CSR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSigningRequestCondition {
    /// Type of the condition.
    pub condition_type: RequestConditionType,
    /// Status of the condition (True, False, Unknown).
    pub status: String,
    /// Reason for the condition.
    pub reason: String,
    /// Message with details about the condition.
    pub message: String,
    /// Last update time.
    pub last_update_time: Option<String>,
    /// Last transition time.
    pub last_transition_time: Option<String>,
}

impl CertificateSigningRequestCondition {
    pub fn new(condition_type: RequestConditionType) -> Self {
        Self {
            condition_type,
            status: "True".to_string(),
            reason: String::new(),
            message: String::new(),
            last_update_time: None,
            last_transition_time: None,
        }
    }
}

/// CertificateSigningRequestSpec contains the certificate request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub struct CertificateSigningRequestSpec {
    /// The PEM-encoded x509 certificate signing request.
    pub request: Vec<u8>,
    /// The signer name for this request.
    pub signer_name: String,
    /// Expiration seconds for the issued certificate.
    pub expiration_seconds: Option<i32>,
    /// Usages for the certificate.
    pub usages: Vec<String>,
    /// Username of the requesting user.
    pub username: String,
    /// UID of the requesting user.
    pub uid: String,
    /// Groups of the requesting user.
    pub groups: Vec<String>,
}


/// CertificateSigningRequestStatus contains the status of the request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertificateSigningRequestStatus {
    /// Conditions applied to the request.
    pub conditions: Vec<CertificateSigningRequestCondition>,
    /// The issued certificate (PEM-encoded).
    pub certificate: Vec<u8>,
}

/// CertificateSigningRequest object.
#[derive(Debug, Clone)]
pub struct CertificateSigningRequest {
    /// Name of the CSR.
    pub name: String,
    /// Namespace (CSRs are cluster-scoped, but we include for consistency).
    pub namespace: String,
    /// Spec of the CSR.
    pub spec: CertificateSigningRequestSpec,
    /// Status of the CSR.
    pub status: CertificateSigningRequestStatus,
}

impl CertificateSigningRequest {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: String::new(),
            spec: CertificateSigningRequestSpec::default(),
            status: CertificateSigningRequestStatus::default(),
        }
    }

    pub fn with_signer_name(mut self, signer_name: &str) -> Self {
        self.spec.signer_name = signer_name.to_string();
        self
    }

    pub fn with_certificate(mut self, certificate: Vec<u8>) -> Self {
        self.status.certificate = certificate;
        self
    }

    pub fn with_conditions(mut self, conditions: Vec<CertificateSigningRequestCondition>) -> Self {
        self.status.conditions = conditions;
        self
    }
}

impl crate::api::core::ApiObject for CertificateSigningRequest {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "CertificateSigningRequest"
    }
}

// ============================================================================
// Authorizer trait and helpers
// ============================================================================

/// UserInfo provides information about the user making the request.
pub trait UserInfo: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_uid(&self) -> &str;
    fn get_groups(&self) -> &[String];
}

/// Default user info implementation.
#[derive(Debug, Clone)]
pub struct DefaultUserInfo {
    pub name: String,
    pub uid: String,
    pub groups: Vec<String>,
}

impl DefaultUserInfo {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            uid: String::new(),
            groups: Vec::new(),
        }
    }
}

impl UserInfo for DefaultUserInfo {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_uid(&self) -> &str {
        &self.uid
    }

    fn get_groups(&self) -> &[String] {
        &self.groups
    }
}

/// Authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The authorizer allows the action.
    Allow,
    /// The authorizer denies the action.
    Deny,
    /// The authorizer has no opinion on the action.
    NoOpinion,
}

/// Authorizer attributes for authorization checks.
#[derive(Debug, Clone)]
pub struct AuthorizerAttributes {
    pub user: String,
    pub verb: String,
    pub api_group: String,
    pub api_version: String,
    pub resource: String,
    pub name: String,
    pub is_resource_request: bool,
}

impl AuthorizerAttributes {
    pub fn new_for_signer(user: &str, verb: &str, signer_name: &str) -> Self {
        Self {
            user: user.to_string(),
            verb: verb.to_string(),
            api_group: CERTIFICATES_GROUP.to_string(),
            api_version: "*".to_string(),
            resource: "signers".to_string(),
            name: signer_name.to_string(),
            is_resource_request: true,
        }
    }
}

/// Authorizer trait for checking permissions.
pub trait Authorizer: Send + Sync {
    /// Authorize checks if the given attributes are allowed.
    /// Returns (decision, reason, error).
    fn authorize(&self, attrs: &AuthorizerAttributes) -> (Decision, String, Option<String>);
}

/// Check if a user is authorized for a specific signer name.
/// This implements the same logic as the Go certauthorization.IsAuthorizedForSignerName.
pub fn is_authorized_for_signer_name(
    authorizer: &dyn Authorizer,
    user: &str,
    verb: &str,
    signer_name: &str,
) -> bool {
    // First check if the user has explicit permission for the given signerName
    let attrs = AuthorizerAttributes::new_for_signer(user, verb, signer_name);
    let (decision, _reason, err) = authorizer.authorize(&attrs);

    if err.is_some() {
        // Log error and continue to wildcard check
    } else if decision == Decision::Allow {
        return true;
    }

    // If not, check if the user has wildcard permissions for the domain portion
    // e.g., 'kubernetes.io/*'
    let wildcard_name = build_wildcard_signer_name(signer_name);
    let attrs = AuthorizerAttributes::new_for_signer(user, verb, &wildcard_name);
    let (decision, _reason, err) = authorizer.authorize(&attrs);

    if err.is_some() {
        return false;
    }

    decision == Decision::Allow
}

/// Build a wildcard signer name from a specific signer name.
/// e.g., "kubernetes.io/kube-apiserver-client" -> "kubernetes.io/*"
fn build_wildcard_signer_name(signer_name: &str) -> String {
    if let Some(pos) = signer_name.find('/') {
        format!("{}/*", &signer_name[..pos])
    } else {
        format!("{}/*", signer_name)
    }
}

/// Helper to create a FieldError for authorization failures.
fn authorization_field_error(message: &str) -> FieldError {
    FieldError {
        field: String::new(),
        error_type: FieldErrorType::Invalid,
        value: message.to_string(),
        supported_values: vec![],
    }
}

// ============================================================================
// Plugin implementation
// ============================================================================

/// Plugin validates that users have permission to sign CSRs.
pub struct Plugin {
    handler: Handler,
    authorizer: Option<Arc<dyn Authorizer>>,
}

impl Plugin {
    /// Create a new CertificateSigning plugin.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Update]),
            authorizer: None,
        }
    }

    /// Create a new plugin with an authorizer.
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

    /// Validate that the plugin is properly initialized.
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
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // Ignore all calls to anything other than 'certificatesigningrequests/status'.
        if attributes.get_subresource() != "status" {
            return Ok(());
        }

        let resource = attributes.get_resource();
        if resource.resource != CSR_RESOURCE {
            return Ok(());
        }

        // Get the old CSR
        let old_csr = match attributes.get_old_object() {
            Some(obj) => match obj.as_any().downcast_ref::<CertificateSigningRequest>() {
                Some(csr) => csr,
                None => {
                    return Err(AdmissionError::forbidden(
                        attributes.get_name(),
                        attributes.get_namespace(),
                        CSR_RESOURCE,
                        authorization_field_error(&format!(
                            "expected type CertificateSigningRequest, got: {:?}",
                            obj.as_any().type_id()
                        )),
                    ));
                }
            },
            None => {
                return Err(AdmissionError::forbidden(
                    attributes.get_name(),
                    attributes.get_namespace(),
                    CSR_RESOURCE,
                    authorization_field_error("old object is required for UPDATE operations"),
                ));
            }
        };

        // Get the new CSR
        let csr = match attributes.get_object() {
            Some(obj) => match obj.as_any().downcast_ref::<CertificateSigningRequest>() {
                Some(csr) => csr,
                None => {
                    return Err(AdmissionError::forbidden(
                        attributes.get_name(),
                        attributes.get_namespace(),
                        CSR_RESOURCE,
                        authorization_field_error(&format!(
                            "expected type CertificateSigningRequest, got: {:?}",
                            obj.as_any().type_id()
                        )),
                    ));
                }
            },
            None => {
                return Err(AdmissionError::forbidden(
                    attributes.get_name(),
                    attributes.get_namespace(),
                    CSR_RESOURCE,
                    authorization_field_error("object is required"),
                ));
            }
        };

        // Only run if the status.certificate or status.conditions field has been changed
        if old_csr.status.certificate == csr.status.certificate
            && old_csr.status.conditions == csr.status.conditions
        {
            return Ok(());
        }

        // Check authorization
        let authorizer = match &self.authorizer {
            Some(authz) => authz,
            None => {
                // If no authorizer is set, we cannot validate - deny by default
                return Err(AdmissionError::forbidden(
                    attributes.get_name(),
                    attributes.get_namespace(),
                    CSR_RESOURCE,
                    authorization_field_error("no authorizer configured"),
                ));
            }
        };

        // Use the OLD CSR's signer name for authorization (immutable field)
        if !is_authorized_for_signer_name(
            authorizer.as_ref(),
            "user", // In a real implementation, this would come from the request context
            "sign",
            &old_csr.spec.signer_name,
        ) {
            return Err(AdmissionError::forbidden(
                attributes.get_name(),
                attributes.get_namespace(),
                CSR_RESOURCE,
                authorization_field_error(&format!(
                    "user not permitted to sign requests with signerName {:?}",
                    old_csr.spec.signer_name
                )),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{GroupVersionKind, GroupVersionResource};
    use crate::admission::AttributesRecord;
    use crate::api::core::ApiObject;

    /// Fake authorizer for testing.
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
        fn authorize(&self, attrs: &AuthorizerAttributes) -> (Decision, String, Option<String>) {
            if let Some(ref err) = self.err {
                return (self.decision, "forced error".to_string(), Some(err.clone()));
            }

            if attrs.verb != self.verb {
                return (
                    Decision::Deny,
                    format!("unrecognised verb '{}'", attrs.verb),
                    None,
                );
            }

            if attrs.api_group != CERTIFICATES_GROUP {
                return (
                    Decision::Deny,
                    format!("unrecognised groupName '{}'", attrs.api_group),
                    None,
                );
            }

            if attrs.api_version != "*" {
                return (
                    Decision::Deny,
                    format!("unrecognised apiVersion '{}'", attrs.api_version),
                    None,
                );
            }

            if attrs.resource != "signers" {
                return (
                    Decision::Deny,
                    format!("unrecognised resource '{}'", attrs.resource),
                    None,
                );
            }

            if attrs.name != self.allowed_name {
                return (
                    Decision::Deny,
                    format!("unrecognised resource name '{}'", attrs.name),
                    None,
                );
            }

            if !attrs.is_resource_request {
                return (
                    Decision::Deny,
                    format!("unrecognised IsResourceRequest '{}'", attrs.is_resource_request),
                    None,
                );
            }

            (self.decision, String::new(), None)
        }
    }

    /// Helper to create CSR attributes for testing.
    fn new_csr_attributes(
        name: &str,
        subresource: &str,
        operation: Operation,
        csr: CertificateSigningRequest,
        old_csr: Option<CertificateSigningRequest>,
    ) -> AttributesRecord {
        AttributesRecord::new(
            name,
            "",
            GroupVersionResource::new(CERTIFICATES_GROUP, "v1", CSR_RESOURCE),
            subresource,
            operation,
            Some(Box::new(csr)),
            old_csr.map(|c| Box::new(c) as Box<dyn crate::api::core::ApiObject>),
            GroupVersionKind::new(CERTIFICATES_GROUP, "v1", "CertificateSigningRequest"),
            false,
        )
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Create));
        assert!(!plugin.handles(Operation::Delete));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_wrong_type() {
        // When the object is not a CertificateSigningRequest, validation should fail
        let authorizer = Arc::new(FakeAuthorizer::new("sign", "", Decision::Allow, None));
        let plugin = Plugin::with_authorizer(authorizer);

        // Use a Pod instead of a CSR - this should trigger the type error
        let pod = crate::api::core::Pod::new("test", "default");

        let attrs = AttributesRecord::new(
            "test",
            "",
            GroupVersionResource::new(CERTIFICATES_GROUP, "v1", CSR_RESOURCE),
            "status",
            Operation::Update,
            Some(Box::new(pod.clone())),
            Some(Box::new(pod)),
            GroupVersionKind::new(CERTIFICATES_GROUP, "v1", "CertificateSigningRequest"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Expected error for wrong type");
    }

    #[test]
    fn test_allowed_if_certificate_and_conditions_unchanged() {
        // Even with an authorizer that returns an error, if the certificate
        // and conditions are unchanged, the request should be allowed
        let authorizer = Arc::new(FakeAuthorizer::new(
            "sign",
            "",
            Decision::Allow,
            Some("faked error".to_string()),
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let old_csr = CertificateSigningRequest::new("test")
            .with_signer_name("abc.com/xyz")
            .with_certificate(b"data".to_vec());

        let csr = CertificateSigningRequest::new("test")
            .with_signer_name("abc.com/xyz")
            .with_certificate(b"data".to_vec());

        let attrs = new_csr_attributes("test", "status", Operation::Update, csr, Some(old_csr));

        let result = plugin.validate(&attrs);
        assert!(
            result.is_ok(),
            "Expected success when certificate and conditions unchanged"
        );
    }

    #[test]
    fn test_deny_request_if_authz_fails_on_certificate_change() {
        let authorizer = Arc::new(FakeAuthorizer::new(
            "sign",
            "abc.com/xyz",
            Decision::Allow,
            Some("test error".to_string()),
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let old_csr =
            CertificateSigningRequest::new("test").with_signer_name("abc.com/xyz");

        let csr = CertificateSigningRequest::new("test")
            .with_signer_name("abc.com/xyz")
            .with_certificate(b"data".to_vec());

        let attrs = new_csr_attributes("test", "status", Operation::Update, csr, Some(old_csr));

        let result = plugin.validate(&attrs);
        assert!(
            result.is_err(),
            "Expected error when authz lookup fails on certificate change"
        );
    }

    #[test]
    fn test_deny_request_if_authz_fails_on_condition_change() {
        let authorizer = Arc::new(FakeAuthorizer::new(
            "sign",
            "abc.com/xyz",
            Decision::Allow,
            Some("test error".to_string()),
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let old_csr =
            CertificateSigningRequest::new("test").with_signer_name("abc.com/xyz");

        let csr = CertificateSigningRequest::new("test")
            .with_signer_name("abc.com/xyz")
            .with_conditions(vec![CertificateSigningRequestCondition::new(
                RequestConditionType::Failed,
            )]);

        let attrs = new_csr_attributes("test", "status", Operation::Update, csr, Some(old_csr));

        let result = plugin.validate(&attrs);
        assert!(
            result.is_err(),
            "Expected error when authz lookup fails on condition change"
        );
    }

    #[test]
    fn test_allow_request_if_user_authorized_for_specific_signer_name() {
        let authorizer = Arc::new(FakeAuthorizer::new(
            "sign",
            "abc.com/xyz",
            Decision::Allow,
            None,
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let old_csr =
            CertificateSigningRequest::new("test").with_signer_name("abc.com/xyz");

        let csr = CertificateSigningRequest::new("test")
            .with_signer_name("abc.com/xyz")
            .with_certificate(b"data".to_vec());

        let attrs = new_csr_attributes("test", "status", Operation::Update, csr, Some(old_csr));

        let result = plugin.validate(&attrs);
        assert!(
            result.is_ok(),
            "Expected success when user is authorized for specific signerName"
        );
    }

    #[test]
    fn test_allow_request_if_user_authorized_with_wildcard() {
        let authorizer = Arc::new(FakeAuthorizer::new(
            "sign",
            "abc.com/*",
            Decision::Allow,
            None,
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let old_csr =
            CertificateSigningRequest::new("test").with_signer_name("abc.com/xyz");

        let csr = CertificateSigningRequest::new("test")
            .with_signer_name("abc.com/xyz")
            .with_certificate(b"data".to_vec());

        let attrs = new_csr_attributes("test", "status", Operation::Update, csr, Some(old_csr));

        let result = plugin.validate(&attrs);
        assert!(
            result.is_ok(),
            "Expected success when user is authorized with wildcard"
        );
    }

    #[test]
    fn test_deny_request_if_user_not_permitted_for_signer_name() {
        let authorizer = Arc::new(FakeAuthorizer::new(
            "sign",
            "notabc.com/xyz",
            Decision::Allow,
            None,
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let old_csr =
            CertificateSigningRequest::new("test").with_signer_name("abc.com/xyz");

        let csr = CertificateSigningRequest::new("test")
            .with_signer_name("abc.com/xyz")
            .with_certificate(b"data".to_vec());

        let attrs = new_csr_attributes("test", "status", Operation::Update, csr, Some(old_csr));

        let result = plugin.validate(&attrs);
        assert!(
            result.is_err(),
            "Expected error when user does not have permission for signerName"
        );
    }

    #[test]
    fn test_deny_request_if_user_updates_signer_name_to_allowed_value() {
        // User attempts to update signerName to a value they DO have permission for,
        // but the authorization check uses the OLD signerName, which they don't have
        // permission for
        let authorizer = Arc::new(FakeAuthorizer::new(
            "sign",
            "allowed.com/xyz",
            Decision::Allow,
            None,
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let old_csr =
            CertificateSigningRequest::new("test").with_signer_name("notallowed.com/xyz");

        let csr = CertificateSigningRequest::new("test")
            .with_signer_name("allowed.com/xyz")
            .with_certificate(b"data".to_vec());

        let attrs = new_csr_attributes("test", "status", Operation::Update, csr, Some(old_csr));

        let result = plugin.validate(&attrs);
        assert!(
            result.is_err(),
            "Expected error when user attempts to update signerName to allowed value"
        );
    }

    #[test]
    fn test_ignore_non_status_subresource() {
        let authorizer = Arc::new(FakeAuthorizer::new(
            "sign",
            "",
            Decision::Deny,
            Some("should not be called".to_string()),
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let old_csr = CertificateSigningRequest::new("test").with_signer_name("abc.com/xyz");
        let csr = CertificateSigningRequest::new("test")
            .with_signer_name("abc.com/xyz")
            .with_certificate(b"data".to_vec());

        // Use "approval" instead of "status"
        let attrs = new_csr_attributes("test", "approval", Operation::Update, csr, Some(old_csr));

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected success for non-status subresource");
    }

    #[test]
    fn test_ignore_non_csr_resource() {
        let authorizer = Arc::new(FakeAuthorizer::new(
            "sign",
            "",
            Decision::Deny,
            Some("should not be called".to_string()),
        ));
        let plugin = Plugin::with_authorizer(authorizer);

        let pod = crate::api::core::Pod::new("test", "default");

        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "status",
            Operation::Update,
            Some(Box::new(pod.clone())),
            Some(Box::new(pod)),
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected success for non-CSR resource");
    }

    #[test]
    fn test_validate_initialization_without_authorizer() {
        let plugin = Plugin::new();
        let result = plugin.validate_initialization();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires an authorizer"));
    }

    #[test]
    fn test_validate_initialization_with_authorizer() {
        let authorizer = Arc::new(FakeAuthorizer::new("sign", "", Decision::Allow, None));
        let plugin = Plugin::with_authorizer(authorizer);
        let result = plugin.validate_initialization();
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_wildcard_signer_name() {
        assert_eq!(
            build_wildcard_signer_name("kubernetes.io/kube-apiserver-client"),
            "kubernetes.io/*"
        );
        assert_eq!(build_wildcard_signer_name("example.com/my-signer"), "example.com/*");
        assert_eq!(build_wildcard_signer_name("no-slash"), "no-slash/*");
    }

    #[test]
    fn test_is_authorized_for_signer_name_exact_match() {
        let authorizer = FakeAuthorizer::new("sign", "abc.com/xyz", Decision::Allow, None);

        assert!(is_authorized_for_signer_name(
            &authorizer,
            "user",
            "sign",
            "abc.com/xyz"
        ));
    }

    #[test]
    fn test_is_authorized_for_signer_name_wildcard_match() {
        let authorizer = FakeAuthorizer::new("sign", "abc.com/*", Decision::Allow, None);

        assert!(is_authorized_for_signer_name(
            &authorizer,
            "user",
            "sign",
            "abc.com/xyz"
        ));
    }

    #[test]
    fn test_is_authorized_for_signer_name_no_match() {
        let authorizer = FakeAuthorizer::new("sign", "other.com/xyz", Decision::Allow, None);

        assert!(!is_authorized_for_signer_name(
            &authorizer,
            "user",
            "sign",
            "abc.com/xyz"
        ));
    }

    #[test]
    fn test_csr_condition_equality() {
        let cond1 = CertificateSigningRequestCondition::new(RequestConditionType::Approved);
        let cond2 = CertificateSigningRequestCondition::new(RequestConditionType::Approved);
        let cond3 = CertificateSigningRequestCondition::new(RequestConditionType::Denied);

        assert_eq!(cond1, cond2);
        assert_ne!(cond1, cond3);
    }

    #[test]
    fn test_csr_status_equality() {
        let status1 = CertificateSigningRequestStatus {
            certificate: b"data".to_vec(),
            conditions: vec![CertificateSigningRequestCondition::new(
                RequestConditionType::Approved,
            )],
        };
        let status2 = CertificateSigningRequestStatus {
            certificate: b"data".to_vec(),
            conditions: vec![CertificateSigningRequestCondition::new(
                RequestConditionType::Approved,
            )],
        };
        let status3 = CertificateSigningRequestStatus {
            certificate: b"different".to_vec(),
            conditions: vec![],
        };

        assert_eq!(status1, status2);
        assert_ne!(status1, status3);
    }

    #[test]
    fn test_csr_api_object_kind() {
        let csr = CertificateSigningRequest::new("test");
        assert_eq!(csr.kind(), "CertificateSigningRequest");
    }

    #[test]
    fn test_request_condition_type_as_str() {
        assert_eq!(RequestConditionType::Approved.as_str(), "Approved");
        assert_eq!(RequestConditionType::Denied.as_str(), "Denied");
        assert_eq!(RequestConditionType::Failed.as_str(), "Failed");
    }

    #[test]
    fn test_default_user_info() {
        let user = DefaultUserInfo::new("test-user");
        assert_eq!(user.get_name(), "test-user");
        assert_eq!(user.get_uid(), "");
        assert!(user.get_groups().is_empty());
    }

    #[test]
    fn test_authorizer_attributes_new_for_signer() {
        let attrs = AuthorizerAttributes::new_for_signer("test-user", "sign", "example.com/signer");
        assert_eq!(attrs.user, "test-user");
        assert_eq!(attrs.verb, "sign");
        assert_eq!(attrs.api_group, "certificates.k8s.io");
        assert_eq!(attrs.api_version, "*");
        assert_eq!(attrs.resource, "signers");
        assert_eq!(attrs.name, "example.com/signer");
        assert!(attrs.is_resource_request);
    }
}
