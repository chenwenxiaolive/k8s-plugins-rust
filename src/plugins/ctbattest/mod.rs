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

//! ClusterTrustBundleAttest admission controller.
//!
//! In order to create or update a ClusterTrustBundle that sets signerName,
//! you must have the following permission: group=certificates.k8s.io
//! resource=signers resourceName=<the signer name> verb=attest.
//!
//! This plugin validates that users have the appropriate authorization to
//! attest ClusterTrustBundles for specific signerNames.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use std::any::Any;
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the ClusterTrustBundleAttest admission controller.
pub const PLUGIN_NAME: &str = "ClusterTrustBundleAttest";

/// The certificates API group.
pub const CERTIFICATES_API_GROUP: &str = "certificates.k8s.io";

/// Register the ClusterTrustBundleAttest plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

// ============================================================================
// ClusterTrustBundle Types
// ============================================================================

/// OwnerReference contains enough information to let you identify an owning object.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OwnerReference {
    /// API version of the referent.
    pub api_version: String,
    /// Kind of the referent.
    pub kind: String,
    /// Name of the referent.
    pub name: String,
    /// UID of the referent.
    pub uid: String,
}

/// ObjectMeta contains metadata that all persisted resources must have.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ObjectMeta {
    /// Name of the object.
    pub name: String,
    /// List of objects depended by this object.
    pub owner_references: Vec<OwnerReference>,
    /// List of finalizers.
    pub finalizers: Vec<String>,
}

/// ClusterTrustBundleSpec contains the signer name and trust anchors.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ClusterTrustBundleSpec {
    /// SignerName is the name of the signer that issued the certificates in this bundle.
    pub signer_name: String,
    /// TrustBundle contains the individual X.509 trust anchors.
    pub trust_bundle: String,
}

/// ClusterTrustBundle is a cluster-scoped container for X.509 trust anchors.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ClusterTrustBundle {
    /// Standard object metadata.
    pub metadata: ObjectMeta,
    /// Spec defines the trust bundle specification.
    pub spec: ClusterTrustBundleSpec,
}

impl ClusterTrustBundle {
    /// Create a new ClusterTrustBundle with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            metadata: ObjectMeta {
                name: name.to_string(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec::default(),
        }
    }

    /// Create a new ClusterTrustBundle with the given name and signer name.
    pub fn with_signer(name: &str, signer_name: &str) -> Self {
        Self {
            metadata: ObjectMeta {
                name: name.to_string(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: signer_name.to_string(),
                trust_bundle: String::new(),
            },
        }
    }
}

impl crate::api::core::ApiObject for ClusterTrustBundle {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "ClusterTrustBundle"
    }
}

/// ClusterTrustBundleList contains a list of ClusterTrustBundle objects.
/// Used for testing wrong type scenarios.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ClusterTrustBundleList {
    /// Items is a list of ClusterTrustBundle objects.
    pub items: Vec<ClusterTrustBundle>,
}

impl crate::api::core::ApiObject for ClusterTrustBundleList {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "ClusterTrustBundleList"
    }
}

// ============================================================================
// Authorization Types
// ============================================================================

/// Decision represents an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The authorizer allows the action.
    Allow,
    /// The authorizer denies the action.
    Deny,
    /// The authorizer has no opinion on the action.
    NoOpinion,
}

/// AuthorizerAttributes contains information about an authorization request.
#[derive(Debug, Clone)]
pub struct AuthorizerAttributes {
    /// The user making the request.
    pub user: String,
    /// The verb being requested.
    pub verb: String,
    /// The resource name being requested.
    pub name: String,
    /// The API group of the resource.
    pub api_group: String,
    /// The API version of the resource.
    pub api_version: String,
    /// The resource type.
    pub resource: String,
    /// Whether this is a resource request.
    pub resource_request: bool,
}

/// Authorizer trait for checking permissions.
pub trait Authorizer: Send + Sync {
    /// Authorize checks if the given attributes are authorized.
    /// Returns the decision, a reason string, and an optional error.
    fn authorize(&self, attrs: &AuthorizerAttributes) -> (Decision, String, Option<String>);
}

/// Check if the user is authorized to perform the given verb on the signer.
///
/// First checks for explicit permission on the signerName.
/// If not, checks for wildcard permissions on the domain portion (e.g., "kubernetes.io/*").
pub fn is_authorized_for_signer_name(
    authz: &dyn Authorizer,
    user: &str,
    verb: &str,
    signer_name: &str,
) -> bool {
    // First check if the user has explicit permission for the given signerName.
    let attrs = build_attributes(user, verb, signer_name);
    let (decision, _reason, err) = authz.authorize(&attrs);
    if err.is_some() {
        // Log error and continue to wildcard check
    } else if decision == Decision::Allow {
        return true;
    }

    // If not, check if the user has wildcard permissions for the domain portion.
    let attrs = build_wildcard_attributes(user, verb, signer_name);
    let (decision, _reason, err) = authz.authorize(&attrs);
    if err.is_some() {
        // Log error
    } else if decision == Decision::Allow {
        return true;
    }

    false
}

fn build_attributes(user: &str, verb: &str, signer_name: &str) -> AuthorizerAttributes {
    AuthorizerAttributes {
        user: user.to_string(),
        verb: verb.to_string(),
        name: signer_name.to_string(),
        api_group: CERTIFICATES_API_GROUP.to_string(),
        api_version: "*".to_string(),
        resource: "signers".to_string(),
        resource_request: true,
    }
}

fn build_wildcard_attributes(user: &str, verb: &str, signer_name: &str) -> AuthorizerAttributes {
    let domain = signer_name.split('/').next().unwrap_or(signer_name);
    let wildcard_name = format!("{}/*", domain);
    build_attributes(user, verb, &wildcard_name)
}

// ============================================================================
// GC Fields Check
// ============================================================================

/// Check if the update is only mutating GC-managed fields (ownerReferences, finalizers).
///
/// This supports storage migration and GC workflows where the semantics of the bundle
/// are unchanged but metadata fields managed by the garbage collector are modified.
pub fn is_only_mutating_gc_fields(new_bundle: &ClusterTrustBundle, old_bundle: &ClusterTrustBundle) -> bool {
    // Compare everything except ownerReferences and finalizers
    // If they are equal after ignoring GC fields, return true

    // Check if spec is the same
    if new_bundle.spec != old_bundle.spec {
        return false;
    }

    // Check if name is the same
    if new_bundle.metadata.name != old_bundle.metadata.name {
        return false;
    }

    // The only differences allowed are in ownerReferences and finalizers
    true
}

// ============================================================================
// Feature Gate
// ============================================================================

/// FeatureGate trait for checking if features are enabled.
pub trait FeatureGate: Send + Sync {
    /// Check if the ClusterTrustBundle feature is enabled.
    fn cluster_trust_bundle_enabled(&self) -> bool;
}

/// Default feature gate that always returns true (feature enabled).
#[derive(Debug, Clone, Default)]
pub struct DefaultFeatureGate {
    pub cluster_trust_bundle_enabled: bool,
}

impl DefaultFeatureGate {
    pub fn new(enabled: bool) -> Self {
        Self {
            cluster_trust_bundle_enabled: enabled,
        }
    }
}

impl FeatureGate for DefaultFeatureGate {
    fn cluster_trust_bundle_enabled(&self) -> bool {
        self.cluster_trust_bundle_enabled
    }
}

// ============================================================================
// User Info
// ============================================================================

/// UserInfo contains information about the user making the request.
#[derive(Debug, Clone, Default)]
pub struct UserInfo {
    /// The name of the user.
    pub name: String,
    /// The groups the user belongs to.
    pub groups: Vec<String>,
}

impl UserInfo {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            groups: Vec::new(),
        }
    }
}

// ============================================================================
// Plugin
// ============================================================================

/// Plugin is the ClusterTrustBundle attest plugin.
///
/// In order to create or update a ClusterTrustBundle that sets signerName,
/// you must have the following permission: group=certificates.k8s.io
/// resource=signers resourceName=<the signer name> verb=attest.
pub struct Plugin {
    handler: Handler,
    /// The authorizer used to check permissions.
    authorizer: Option<Arc<dyn Authorizer>>,
    /// Whether the feature gates have been inspected.
    inspected_feature_gates: bool,
    /// Whether the ClusterTrustBundle feature is enabled.
    enabled: bool,
}

impl Plugin {
    /// Create a new Plugin instance.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            authorizer: None,
            inspected_feature_gates: false,
            enabled: true, // Default to enabled for backwards compatibility
        }
    }

    /// Create a new Plugin with an authorizer.
    pub fn with_authorizer(authorizer: Arc<dyn Authorizer>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            authorizer: Some(authorizer),
            inspected_feature_gates: false,
            enabled: true,
        }
    }

    /// Set the authorizer for the plugin.
    pub fn set_authorizer(&mut self, authz: Arc<dyn Authorizer>) {
        self.authorizer = Some(authz);
    }

    /// Inspect feature gates to determine if the plugin should be enabled.
    pub fn inspect_feature_gates(&mut self, feature_gate: &dyn FeatureGate) {
        self.enabled = feature_gate.cluster_trust_bundle_enabled();
        self.inspected_feature_gates = true;
    }

    /// Validate that the plugin was initialized correctly.
    pub fn validate_initialization(&self) -> Result<(), String> {
        if self.authorizer.is_none() {
            return Err(format!("{} requires an authorizer", PLUGIN_NAME));
        }
        if !self.inspected_feature_gates {
            return Err(format!("{} did not see feature gates", PLUGIN_NAME));
        }
        Ok(())
    }

    /// Internal validation logic.
    fn validate_internal(
        &self,
        attributes: &dyn Attributes,
        user: &str,
    ) -> AdmissionResult<()> {
        // If feature is disabled, allow everything
        if !self.enabled {
            return Ok(());
        }

        // Only handle clustertrustbundles
        let resource = attributes.get_resource();
        if resource.group != CERTIFICATES_API_GROUP || resource.resource != "clustertrustbundles" {
            return Ok(());
        }

        // Get the new bundle
        let new_bundle = match attributes.get_object() {
            Some(obj) => match obj.as_any().downcast_ref::<ClusterTrustBundle>() {
                Some(bundle) => bundle,
                None => {
                    return Err(AdmissionError::Forbidden(Box::new(crate::admission::errors::ForbiddenError {
                        name: attributes.get_name().to_string(),
                        namespace: String::new(),
                        resource: "clustertrustbundles".to_string(),
                        field_error: crate::admission::errors::FieldError {
                            field: String::new(),
                            error_type: crate::admission::errors::FieldErrorType::Invalid,
                            value: format!("expected type ClusterTrustBundle, got: {}",
                                obj.kind()),
                            supported_values: vec![],
                        },
                    })));
                }
            },
            None => return Ok(()),
        };

        // If signer name isn't specified, we don't need to perform the attest check.
        if new_bundle.spec.signer_name.is_empty() {
            return Ok(());
        }

        // Skip the attest check when the semantics of the bundle are unchanged
        // to support storage migration and GC workflows.
        if attributes.get_operation() == Operation::Update {
            if let Some(old_obj) = attributes.get_old_object() {
                if let Some(old_bundle) = old_obj.as_any().downcast_ref::<ClusterTrustBundle>() {
                    if is_only_mutating_gc_fields(new_bundle, old_bundle) {
                        return Ok(());
                    }
                }
            }
        }

        // Check authorization
        if let Some(ref authz) = self.authorizer {
            if !is_authorized_for_signer_name(
                authz.as_ref(),
                user,
                "attest",
                &new_bundle.spec.signer_name,
            ) {
                return Err(AdmissionError::Forbidden(Box::new(crate::admission::errors::ForbiddenError {
                    name: new_bundle.metadata.name.clone(),
                    namespace: String::new(),
                    resource: "clustertrustbundles".to_string(),
                    field_error: crate::admission::errors::FieldError {
                        field: String::new(),
                        error_type: crate::admission::errors::FieldErrorType::Invalid,
                        value: format!(
                            "user not permitted to attest for signerName \"{}\"",
                            new_bundle.spec.signer_name
                        ),
                        supported_values: vec![],
                    },
                })));
            }
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
        // Use a default user name for validation
        // In production, this would come from the request context
        self.validate_internal(attributes, "ignored")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    /// Test authorizer that allows specific signer names.
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
                return (Decision::Deny, "forced error".to_string(), Some(err.clone()));
            }
            if attrs.verb != self.verb {
                return (
                    Decision::Deny,
                    format!("unrecognised verb '{}'", attrs.verb),
                    None,
                );
            }
            if attrs.api_group != CERTIFICATES_API_GROUP {
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
            if !attrs.resource_request {
                return (
                    Decision::Deny,
                    format!("unrecognised IsResourceRequest '{}'", attrs.resource_request),
                    None,
                );
            }
            (self.decision, String::new(), None)
        }
    }

    fn create_test_attributes(
        operation: Operation,
        obj: Option<Box<dyn crate::api::core::ApiObject>>,
        old_obj: Option<Box<dyn crate::api::core::ApiObject>>,
    ) -> AttributesRecord {
        AttributesRecord::new(
            "test-bundle",
            "",
            GroupVersionResource::new(CERTIFICATES_API_GROUP, "v1", "clustertrustbundles"),
            "",
            operation,
            obj,
            old_obj,
            GroupVersionKind::new(CERTIFICATES_API_GROUP, "v1", "ClusterTrustBundle"),
            false,
        )
    }

    fn create_enabled_plugin(authz: Arc<dyn Authorizer>) -> Plugin {
        let mut plugin = Plugin::with_authorizer(authz);
        plugin.inspect_feature_gates(&DefaultFeatureGate::new(true));
        plugin
    }

    fn create_disabled_plugin(authz: Arc<dyn Authorizer>) -> Plugin {
        let mut plugin = Plugin::with_authorizer(authz);
        plugin.inspect_feature_gates(&DefaultFeatureGate::new(false));
        plugin
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_wrong_type_on_create() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let list = ClusterTrustBundleList::default();
        let attrs = create_test_attributes(Operation::Create, Some(Box::new(list)), None);

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Expected error for wrong type on create");
    }

    #[test]
    fn test_wrong_type_on_update() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let list = ClusterTrustBundleList::default();
        let attrs = create_test_attributes(Operation::Update, Some(Box::new(list)), None);

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Expected error for wrong type on update");
    }

    #[test]
    fn test_reject_requests_if_looking_up_permissions_fails() {
        let authz = Arc::new(FakeAuthorizer::new(
            "attest",
            "",
            Decision::Deny,
            Some("forced error".to_string()),
        ));
        let plugin = create_enabled_plugin(authz);

        let bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        let attrs = create_test_attributes(Operation::Update, Some(Box::new(bundle)), None);

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Expected rejection when permission lookup fails");
    }

    #[test]
    fn test_allow_create_if_no_signer_name_specified() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "abc.com/xyz", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let bundle = ClusterTrustBundle::new("test");
        let attrs = create_test_attributes(Operation::Create, Some(Box::new(bundle)), None);

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected allow when no signer name specified on create");
    }

    #[test]
    fn test_allow_update_if_no_signer_name_specified() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "abc.com/xyz", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let old_bundle = ClusterTrustBundle::new("test");
        let new_bundle = ClusterTrustBundle::new("test");
        let attrs = create_test_attributes(
            Operation::Update,
            Some(Box::new(new_bundle)),
            Some(Box::new(old_bundle)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected allow when no signer name specified on update");
    }

    #[test]
    fn test_allow_create_if_user_authorized_for_specific_signer_name() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "abc.com/xyz", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        let attrs = create_test_attributes(Operation::Create, Some(Box::new(bundle)), None);

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected allow for authorized specific signerName on create");
    }

    #[test]
    fn test_allow_update_if_user_authorized_for_specific_signer_name() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "abc.com/xyz", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let old_bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        let new_bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        // Modify something other than GC fields to trigger auth check
        let mut new_bundle = new_bundle;
        new_bundle.spec.trust_bundle = "changed".to_string();

        let attrs = create_test_attributes(
            Operation::Update,
            Some(Box::new(new_bundle)),
            Some(Box::new(old_bundle)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected allow for authorized specific signerName on update");
    }

    #[test]
    fn test_allow_create_if_user_authorized_with_wildcard() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "abc.com/*", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        let attrs = create_test_attributes(Operation::Create, Some(Box::new(bundle)), None);

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected allow for wildcard authorization on create");
    }

    #[test]
    fn test_allow_update_if_user_authorized_with_wildcard() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "abc.com/*", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let old_bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        let new_bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        // Modify something other than GC fields to trigger auth check
        let mut new_bundle = new_bundle;
        new_bundle.spec.trust_bundle = "changed".to_string();

        let attrs = create_test_attributes(
            Operation::Update,
            Some(Box::new(new_bundle)),
            Some(Box::new(old_bundle)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected allow for wildcard authorization on update");
    }

    #[test]
    fn test_deny_create_if_user_not_authorized() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "notabc.com/xyz", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        let attrs = create_test_attributes(Operation::Create, Some(Box::new(bundle)), None);

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Expected denial when user not authorized on create");
    }

    #[test]
    fn test_deny_update_if_user_not_authorized() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "notabc.com/xyz", Decision::Allow, None));
        let plugin = create_enabled_plugin(authz);

        let bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        let attrs = create_test_attributes(Operation::Update, Some(Box::new(bundle)), None);

        let result = plugin.validate(&attrs);
        assert!(result.is_err(), "Expected denial when user not authorized on update");
    }

    #[test]
    fn test_allow_noop_update() {
        // Even with a broken authorizer, no-op updates should be allowed
        let authz = Arc::new(FakeAuthorizer::new(
            "attest",
            "",
            Decision::Deny,
            Some("broken".to_string()),
        ));
        let plugin = create_enabled_plugin(authz);

        let old_bundle = ClusterTrustBundle::with_signer("test", "panda.com/foo");
        let new_bundle = ClusterTrustBundle::with_signer("test", "panda.com/foo");
        let attrs = create_test_attributes(
            Operation::Update,
            Some(Box::new(new_bundle)),
            Some(Box::new(old_bundle)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected allow for no-op update");
    }

    #[test]
    fn test_allow_finalizer_update() {
        // Even with a broken authorizer, finalizer/ownerRef updates should be allowed
        let authz = Arc::new(FakeAuthorizer::new(
            "attest",
            "",
            Decision::Deny,
            Some("broken".to_string()),
        ));
        let plugin = create_enabled_plugin(authz);

        let old_bundle = ClusterTrustBundle::with_signer("test", "panda.com/foo");
        let mut new_bundle = ClusterTrustBundle::with_signer("test", "panda.com/foo");
        new_bundle.metadata.owner_references.push(OwnerReference {
            api_version: "something".to_string(),
            ..Default::default()
        });

        let attrs = create_test_attributes(
            Operation::Update,
            Some(Box::new(new_bundle)),
            Some(Box::new(old_bundle)),
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected allow for finalizer update");
    }

    #[test]
    fn test_feature_gate_disabled() {
        let authz = Arc::new(FakeAuthorizer::new(
            "attest",
            "",
            Decision::Deny,
            Some("broken".to_string()),
        ));
        let plugin = create_disabled_plugin(authz);

        // This would normally fail, but feature gate is disabled
        let bundle = ClusterTrustBundle::with_signer("test", "abc.com/xyz");
        let attrs = create_test_attributes(Operation::Create, Some(Box::new(bundle)), None);

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected allow when feature gate is disabled");
    }

    #[test]
    fn test_ignore_non_clustertrustbundle_resources() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "", Decision::Deny, None));
        let plugin = create_enabled_plugin(authz);

        // Create attributes for a different resource
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
        assert!(result.is_ok(), "Expected allow for non-clustertrustbundle resources");
    }

    #[test]
    fn test_validate_initialization_missing_authorizer() {
        let plugin = Plugin::new();
        let result = plugin.validate_initialization();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires an authorizer"));
    }

    #[test]
    fn test_validate_initialization_missing_feature_gates() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "", Decision::Allow, None));
        let plugin = Plugin::with_authorizer(authz);
        let result = plugin.validate_initialization();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("did not see feature gates"));
    }

    #[test]
    fn test_validate_initialization_success() {
        let authz = Arc::new(FakeAuthorizer::new("attest", "", Decision::Allow, None));
        let mut plugin = Plugin::with_authorizer(authz);
        plugin.inspect_feature_gates(&DefaultFeatureGate::new(true));
        let result = plugin.validate_initialization();
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_only_mutating_gc_fields_same_spec() {
        let old = ClusterTrustBundle::with_signer("test", "example.com/signer");
        let new = ClusterTrustBundle::with_signer("test", "example.com/signer");
        assert!(is_only_mutating_gc_fields(&new, &old));
    }

    #[test]
    fn test_is_only_mutating_gc_fields_different_spec() {
        let old = ClusterTrustBundle::with_signer("test", "example.com/signer");
        let mut new = ClusterTrustBundle::with_signer("test", "example.com/signer");
        new.spec.trust_bundle = "new-bundle".to_string();
        assert!(!is_only_mutating_gc_fields(&new, &old));
    }

    #[test]
    fn test_is_only_mutating_gc_fields_only_owner_refs_changed() {
        let old = ClusterTrustBundle::with_signer("test", "example.com/signer");
        let mut new = ClusterTrustBundle::with_signer("test", "example.com/signer");
        new.metadata.owner_references.push(OwnerReference {
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            name: "owner".to_string(),
            uid: "abc-123".to_string(),
        });
        assert!(is_only_mutating_gc_fields(&new, &old));
    }

    #[test]
    fn test_is_only_mutating_gc_fields_only_finalizers_changed() {
        let old = ClusterTrustBundle::with_signer("test", "example.com/signer");
        let mut new = ClusterTrustBundle::with_signer("test", "example.com/signer");
        new.metadata.finalizers.push("kubernetes.io/some-finalizer".to_string());
        assert!(is_only_mutating_gc_fields(&new, &old));
    }

    #[test]
    fn test_build_wildcard_attributes() {
        let attrs = build_wildcard_attributes("user", "attest", "kubernetes.io/kubelet-serving");
        assert_eq!(attrs.name, "kubernetes.io/*");
        assert_eq!(attrs.verb, "attest");
        assert_eq!(attrs.resource, "signers");
    }

    #[test]
    fn test_build_attributes() {
        let attrs = build_attributes("user", "attest", "example.com/my-signer");
        assert_eq!(attrs.user, "user");
        assert_eq!(attrs.verb, "attest");
        assert_eq!(attrs.name, "example.com/my-signer");
        assert_eq!(attrs.api_group, CERTIFICATES_API_GROUP);
        assert_eq!(attrs.api_version, "*");
        assert_eq!(attrs.resource, "signers");
        assert!(attrs.resource_request);
    }

    #[test]
    fn test_cluster_trust_bundle_new() {
        let bundle = ClusterTrustBundle::new("my-bundle");
        assert_eq!(bundle.metadata.name, "my-bundle");
        assert!(bundle.spec.signer_name.is_empty());
    }

    #[test]
    fn test_cluster_trust_bundle_with_signer() {
        let bundle = ClusterTrustBundle::with_signer("my-bundle", "example.com/signer");
        assert_eq!(bundle.metadata.name, "my-bundle");
        assert_eq!(bundle.spec.signer_name, "example.com/signer");
    }
}
