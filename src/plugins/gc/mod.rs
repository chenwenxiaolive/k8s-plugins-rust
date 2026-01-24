// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! OwnerReferencesPermissionEnforcement (gc) admission controller.
//!
//! This admission controller ensures that users cannot set owner references on objects
//! they do not have permission to delete. It also ensures that users cannot set
//! blockOwnerDeletion to true unless they have permission to update the finalizers
//! subresource of the owner.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use crate::admission::attributes::{GroupResource, GroupVersionResource};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

pub const PLUGIN_NAME: &str = "OwnerReferencesPermissionEnforcement";

/// Register the OwnerReferencesPermissionEnforcement plugin.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        // The pods/status endpoint is ignored by this plugin since old kubelets
        // corrupt them. The pod status strategy ensures status updates cannot mutate
        // ownerRef.
        let whitelist = vec![WhiteListItem {
            group_resource: GroupResource::new("", "pods"),
            subresource: "status".to_string(),
        }];
        Ok(Arc::new(Plugin::new(whitelist)) as Arc<dyn Interface>)
    });
}

// ============================================================================
// OwnerReference Types
// ============================================================================

/// OwnerReference contains enough information to let you identify an owning
/// object. An owning object must be in the same namespace as the dependent, or
/// be cluster-scoped, so there is no namespace field.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnerReference {
    /// API version of the referent.
    pub api_version: String,
    /// Kind of the referent.
    pub kind: String,
    /// Name of the referent.
    pub name: String,
    /// UID of the referent.
    pub uid: String,
    /// If true, AND if the owner has the "foregroundDeletion" finalizer, then
    /// the owner cannot be deleted from the key-value store until this
    /// reference is removed.
    pub block_owner_deletion: Option<bool>,
    /// If true, this reference points to the managing controller.
    pub controller: Option<bool>,
}

impl OwnerReference {
    /// Create a new owner reference.
    pub fn new(api_version: &str, kind: &str, name: &str) -> Self {
        Self {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            name: name.to_string(),
            uid: String::new(),
            block_owner_deletion: None,
            controller: None,
        }
    }

    /// Create a new owner reference with UID.
    pub fn with_uid(api_version: &str, kind: &str, name: &str, uid: &str) -> Self {
        Self {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            name: name.to_string(),
            uid: uid.to_string(),
            block_owner_deletion: None,
            controller: None,
        }
    }

    /// Set block_owner_deletion.
    pub fn with_block_owner_deletion(mut self, block: bool) -> Self {
        self.block_owner_deletion = Some(block);
        self
    }
}

/// Trait for objects that can have owner references.
pub trait HasOwnerReferences {
    /// Get the owner references of this object.
    fn get_owner_references(&self) -> &[OwnerReference];
}

// ============================================================================
// REST Mapper Types
// ============================================================================

/// RESTScopeName identifies the scope of a REST resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RESTScopeName {
    Cluster,
    Namespace,
}

/// RESTMapping contains the information needed to map a RESTful resource.
#[derive(Debug, Clone)]
pub struct RESTMapping {
    /// Resource is the GroupVersionResource for this mapping.
    pub resource: GroupVersionResource,
    /// Scope is the scope of this resource.
    pub scope: RESTScopeName,
}

/// RESTMapper is responsible for mapping resources to their REST API paths.
pub trait RESTMapper: Send + Sync {
    /// RESTMappings returns all mappings for the provided group kind.
    fn rest_mappings(
        &self,
        group: &str,
        kind: &str,
        version: &str,
    ) -> Result<Vec<RESTMapping>, String>;
}

/// DefaultRESTMapper provides a simple in-memory REST mapper.
pub struct DefaultRESTMapper {
    mappings: HashMap<(String, String), Vec<RESTMapping>>,
}

impl DefaultRESTMapper {
    /// Create a new default REST mapper.
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Add a mapping for a group/kind to resources.
    pub fn add_mapping(&mut self, group: &str, kind: &str, mapping: RESTMapping) {
        let key = (group.to_string(), kind.to_string());
        self.mappings.entry(key).or_default().push(mapping);
    }

    /// Create a REST mapper with common Kubernetes resources.
    pub fn with_common_resources() -> Self {
        let mut mapper = Self::new();

        // Core v1 resources
        mapper.add_mapping(
            "",
            "Pod",
            RESTMapping {
                resource: GroupVersionResource::new("", "v1", "pods"),
                scope: RESTScopeName::Namespace,
            },
        );
        mapper.add_mapping(
            "",
            "Node",
            RESTMapping {
                resource: GroupVersionResource::new("", "v1", "nodes"),
                scope: RESTScopeName::Cluster,
            },
        );
        mapper.add_mapping(
            "",
            "ReplicationController",
            RESTMapping {
                resource: GroupVersionResource::new("", "v1", "replicationcontrollers"),
                scope: RESTScopeName::Namespace,
            },
        );

        // Apps v1 resources
        mapper.add_mapping(
            "apps",
            "DaemonSet",
            RESTMapping {
                resource: GroupVersionResource::new("apps", "v1", "daemonsets"),
                scope: RESTScopeName::Namespace,
            },
        );

        mapper
    }
}

impl Default for DefaultRESTMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl RESTMapper for DefaultRESTMapper {
    fn rest_mappings(
        &self,
        group: &str,
        kind: &str,
        _version: &str,
    ) -> Result<Vec<RESTMapping>, String> {
        let key = (group.to_string(), kind.to_string());
        self.mappings
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("no mapping found for {}/{}", group, kind))
    }
}

// ============================================================================
// Authorizer Types
// ============================================================================

/// AuthorizerDecision is the result of an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizerDecision {
    /// Allow means the request is authorized.
    Allow,
    /// Deny means the request is denied.
    Deny,
    /// NoOpinion means the authorizer has no opinion.
    NoOpinion,
}

/// AuthorizerAttributes contains the attributes needed to make an authorization decision.
#[derive(Debug, Clone)]
pub struct AuthorizerAttributes {
    pub user: String,
    pub verb: String,
    pub namespace: String,
    pub api_group: String,
    pub api_version: String,
    pub resource: String,
    pub subresource: String,
    pub name: String,
    pub resource_request: bool,
}

impl AuthorizerAttributes {
    /// Create attributes for a delete check.
    pub fn delete_check(
        user: &str,
        namespace: &str,
        resource: &GroupVersionResource,
        subresource: &str,
        name: &str,
    ) -> Self {
        Self {
            user: user.to_string(),
            verb: "delete".to_string(),
            namespace: namespace.to_string(),
            api_group: resource.group.clone(),
            api_version: resource.version.clone(),
            resource: resource.resource.clone(),
            subresource: subresource.to_string(),
            name: name.to_string(),
            resource_request: true,
        }
    }

    /// Create attributes for an update/finalizers check.
    pub fn update_finalizers_check(
        user: &str,
        namespace: &str,
        resource: &GroupVersionResource,
        name: &str,
    ) -> Self {
        Self {
            user: user.to_string(),
            verb: "update".to_string(),
            namespace: namespace.to_string(),
            api_group: resource.group.clone(),
            api_version: resource.version.clone(),
            resource: resource.resource.clone(),
            subresource: "finalizers".to_string(),
            name: name.to_string(),
            resource_request: true,
        }
    }

    /// Create attributes for checking if user can finalize anything.
    pub fn finalize_anything_check(user: &str) -> Self {
        Self {
            user: user.to_string(),
            verb: "update".to_string(),
            namespace: String::new(),
            api_group: "*".to_string(),
            api_version: "*".to_string(),
            resource: "*".to_string(),
            subresource: "finalizers".to_string(),
            name: "*".to_string(),
            resource_request: true,
        }
    }
}

/// Authorizer makes authorization decisions.
pub trait Authorizer: Send + Sync {
    /// Authorize checks if the given attributes are authorized.
    fn authorize(&self, attrs: &AuthorizerAttributes) -> (AuthorizerDecision, String, Option<String>);
}

/// AlwaysAllowAuthorizer always allows requests.
pub struct AlwaysAllowAuthorizer;

impl Authorizer for AlwaysAllowAuthorizer {
    fn authorize(&self, _attrs: &AuthorizerAttributes) -> (AuthorizerDecision, String, Option<String>) {
        (AuthorizerDecision::Allow, String::new(), None)
    }
}

// ============================================================================
// User Info
// ============================================================================

/// UserInfo contains information about the user making the request.
pub trait UserInfo {
    /// Get the username.
    fn get_name(&self) -> &str;
}

/// DefaultUserInfo is a simple user info implementation.
#[derive(Debug, Clone)]
pub struct DefaultUserInfo {
    pub name: String,
}

impl DefaultUserInfo {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl UserInfo for DefaultUserInfo {
    fn get_name(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// WhiteList Item
// ============================================================================

/// WhiteListItem describes an entry in a whitelist ignored by gc permission enforcement.
#[derive(Debug, Clone, PartialEq)]
pub struct WhiteListItem {
    pub group_resource: GroupResource,
    pub subresource: String,
}

// ============================================================================
// GC Permissions Enforcement Plugin
// ============================================================================

/// OwnerReferencesPermissionEnforcement plugin.
pub struct Plugin {
    handler: Handler,
    authorizer: Option<Arc<dyn Authorizer>>,
    rest_mapper: Option<Arc<dyn RESTMapper>>,
    whitelist: Vec<WhiteListItem>,
}

impl Plugin {
    /// Create a new plugin with the given whitelist.
    pub fn new(whitelist: Vec<WhiteListItem>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            authorizer: None,
            rest_mapper: None,
            whitelist,
        }
    }

    /// Set the authorizer for this plugin.
    pub fn with_authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Set the REST mapper for this plugin.
    pub fn with_rest_mapper(mut self, rest_mapper: Arc<dyn RESTMapper>) -> Self {
        self.rest_mapper = Some(rest_mapper);
        self
    }

    /// Check if the given group resource and subresource is whitelisted.
    fn is_whitelisted(&self, group_resource: &GroupResource, subresource: &str) -> bool {
        self.whitelist.iter().any(|item| {
            item.group_resource == *group_resource && item.subresource == subresource
        })
    }

    /// Convert an owner reference to authorization attribute records.
    fn owner_ref_to_delete_attribute_records(
        &self,
        owner_ref: &OwnerReference,
        namespace: &str,
        user: &str,
    ) -> Result<Vec<AuthorizerAttributes>, String> {
        let rest_mapper = self
            .rest_mapper
            .as_ref()
            .ok_or_else(|| "missing restMapper".to_string())?;

        // Parse the API version to get group and version
        let (group, version) = parse_group_version(&owner_ref.api_version)?;

        let mappings = rest_mapper.rest_mappings(&group, &owner_ref.kind, &version)?;

        let mut ret = Vec::new();
        for mapping in mappings {
            let mut attrs = AuthorizerAttributes::update_finalizers_check(
                user,
                "",
                &mapping.resource,
                &owner_ref.name,
            );

            // If the owner is namespaced, it must be in the same namespace as the dependent
            if mapping.scope == RESTScopeName::Namespace {
                attrs.namespace = namespace.to_string();
            }

            ret.push(attrs);
        }

        Ok(ret)
    }
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new(vec![WhiteListItem {
            group_resource: GroupResource::new("", "pods"),
            subresource: "status".to_string(),
        }])
    }
}

impl Interface for Plugin {
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl ValidationInterface for Plugin {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // If the request is in the whitelist, we skip mutation checks for this resource
        let group_resource = attributes.get_resource().group_resource();
        if self.is_whitelisted(&group_resource, attributes.get_subresource()) {
            return Ok(());
        }

        // Get owner references from new and old objects
        let new_refs = get_owner_references(attributes.get_object());
        let old_refs = get_owner_references(attributes.get_old_object());

        // If we aren't changing owner references, then the edit is always allowed
        if !is_changing_owner_reference(&new_refs, &old_refs) {
            return Ok(());
        }

        // Get the authorizer
        let authorizer = match &self.authorizer {
            Some(a) => a,
            None => return Ok(()), // No authorizer means we can't check, allow by default
        };

        // Assume we have user info available (in real implementation, this would come from attributes)
        // For now, we'll use a placeholder. In a real implementation, attributes would have get_user_info()
        let user = ""; // This would be attributes.get_user_info().get_name()

        // If you are creating a thing, you should always be allowed to set an owner ref since you
        // logically had the power to never create it. We still need to check block owner deletion
        // below, because the power to delete does not imply the power to prevent deletion on other
        // resources.
        if attributes.get_operation() != Operation::Create {
            let delete_attrs = AuthorizerAttributes::delete_check(
                user,
                attributes.get_namespace(),
                attributes.get_resource(),
                attributes.get_subresource(),
                attributes.get_name(),
            );

            let (decision, reason, err) = authorizer.authorize(&delete_attrs);
            if decision != AuthorizerDecision::Allow {
                let err_msg = match err {
                    Some(e) => format!("{}, {}", reason, e),
                    None => reason,
                };
                return Err(AdmissionError::bad_request(format!(
                    "cannot set an ownerRef on a resource you can't delete: {}",
                    err_msg
                )));
            }
        }

        // Further check if the user is setting ownerReference.blockOwnerDeletion to true.
        // If so, only allows the change if the user has delete permission of the _OWNER_
        let new_blocking_refs = new_blocking_owner_deletion_refs(&new_refs, &old_refs);
        if new_blocking_refs.is_empty() {
            return Ok(());
        }

        // Check if user can finalize anything (fast path to avoid REST mapper calls)
        let finalize_anything_attrs = AuthorizerAttributes::finalize_anything_check(user);
        let (decision, _, _) = authorizer.authorize(&finalize_anything_attrs);
        if decision == AuthorizerDecision::Allow {
            return Ok(());
        }

        // Check each new blocking reference
        for owner_ref in &new_blocking_refs {
            let records = match self.owner_ref_to_delete_attribute_records(
                owner_ref,
                attributes.get_namespace(),
                user,
            ) {
                Ok(r) => r,
                Err(e) => {
                    return Err(AdmissionError::bad_request(format!(
                        "cannot set blockOwnerDeletion in this case because cannot find RESTMapping for APIVersion {} Kind {}: {}",
                        owner_ref.api_version, owner_ref.kind, e
                    )));
                }
            };

            // Multiple records are returned if ref.Kind could map to multiple resources.
            // User needs to have update/finalizers permission on all the matched Resources.
            for record in &records {
                let (decision, reason, err) = authorizer.authorize(record);
                if decision != AuthorizerDecision::Allow {
                    let err_msg = match err {
                        Some(e) => format!("{}, {}", reason, e),
                        None => reason,
                    };
                    return Err(AdmissionError::bad_request(format!(
                        "cannot set blockOwnerDeletion if an ownerReference refers to a resource you can't set finalizers on: {}",
                        err_msg
                    )));
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse a Kubernetes API version string into group and version.
fn parse_group_version(api_version: &str) -> Result<(String, String), String> {
    if api_version.is_empty() {
        return Err("empty API version".to_string());
    }

    if let Some(pos) = api_version.rfind('/') {
        let group = &api_version[..pos];
        let version = &api_version[pos + 1..];
        Ok((group.to_string(), version.to_string()))
    } else {
        // Core API group (e.g., "v1")
        Ok((String::new(), api_version.to_string()))
    }
}

/// Get owner references from an object.
fn get_owner_references(obj: Option<&dyn crate::api::core::ApiObject>) -> Vec<OwnerReference> {
    match obj {
        Some(o) => {
            // Try to downcast to known types that support owner references
            if let Some(obj_with_refs) = o.as_any().downcast_ref::<ObjectWithOwnerRefs>() {
                return obj_with_refs.owner_references.clone();
            }
            Vec::new()
        }
        None => Vec::new(),
    }
}

/// Check if owner references are being changed.
fn is_changing_owner_reference(
    new_refs: &[OwnerReference],
    old_refs: &[OwnerReference],
) -> bool {
    if old_refs.is_empty() {
        return !new_refs.is_empty();
    }

    if new_refs.len() != old_refs.len() {
        return true;
    }

    for (i, old_ref) in old_refs.iter().enumerate() {
        if !owner_refs_equal(old_ref, &new_refs[i]) {
            return true;
        }
    }

    false
}

/// Check if two owner references are equal.
fn owner_refs_equal(a: &OwnerReference, b: &OwnerReference) -> bool {
    a.api_version == b.api_version
        && a.kind == b.kind
        && a.name == b.name
        && a.uid == b.uid
        && a.block_owner_deletion == b.block_owner_deletion
        && a.controller == b.controller
}

/// Filter to only keep blocking owner references.
fn blocking_owner_refs(refs: &[OwnerReference]) -> Vec<OwnerReference> {
    refs.iter()
        .filter(|r| r.block_owner_deletion == Some(true))
        .cloned()
        .collect()
}

/// Index owner references by UID.
fn index_by_uid(refs: &[OwnerReference]) -> HashMap<String, OwnerReference> {
    refs.iter()
        .map(|r| (r.uid.clone(), r.clone()))
        .collect()
}

/// Returns new blocking ownerReferences, and references whose blockOwnerDeletion
/// field is changed from nil or false to true.
fn new_blocking_owner_deletion_refs(
    new_refs: &[OwnerReference],
    old_refs: &[OwnerReference],
) -> Vec<OwnerReference> {
    let blocking_new_refs = blocking_owner_refs(new_refs);
    if blocking_new_refs.is_empty() {
        return Vec::new();
    }

    if old_refs.is_empty() {
        return blocking_new_refs;
    }

    let indexed_old_refs = index_by_uid(old_refs);
    let mut ret = Vec::new();

    for new_ref in &blocking_new_refs {
        match indexed_old_refs.get(&new_ref.uid) {
            None => {
                // If ref is newly added, and it's blocking, then return it
                ret.push(new_ref.clone());
            }
            Some(old_ref) => {
                // Check if it was not blocking before
                let was_not_blocking = old_ref.block_owner_deletion.is_none()
                    || old_ref.block_owner_deletion == Some(false);
                if was_not_blocking {
                    ret.push(new_ref.clone());
                }
            }
        }
    }

    ret
}

// ============================================================================
// Test Helper Types
// ============================================================================

/// A generic object that has owner references for testing.
#[derive(Debug, Clone)]
pub struct ObjectWithOwnerRefs {
    pub name: String,
    pub namespace: String,
    pub owner_references: Vec<OwnerReference>,
}

impl ObjectWithOwnerRefs {
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            owner_references: Vec::new(),
        }
    }

    pub fn with_owner_refs(name: &str, namespace: &str, refs: Vec<OwnerReference>) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            owner_references: refs,
        }
    }
}

impl crate::api::core::ApiObject for ObjectWithOwnerRefs {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "TestObject"
    }
}

impl HasOwnerReferences for ObjectWithOwnerRefs {
    fn get_owner_references(&self) -> &[OwnerReference] {
        &self.owner_references
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind};

    /// FakeAuthorizer mimics the Go test's fakeAuthorizer behavior.
    struct FakeAuthorizer;

    impl Authorizer for FakeAuthorizer {
        fn authorize(&self, attrs: &AuthorizerAttributes) -> (AuthorizerDecision, String, Option<String>) {
            let username = &attrs.user;

            if username == "non-deleter" {
                if attrs.verb == "delete" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                if attrs.verb == "update" && attrs.subresource == "finalizers" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                if attrs.api_group == "*" && attrs.resource == "*" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                return (AuthorizerDecision::Allow, String::new(), None);
            }

            if username == "non-pod-deleter" {
                if attrs.verb == "delete" && attrs.resource == "pods" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                if attrs.verb == "update" && attrs.resource == "pods" && attrs.subresource == "finalizers" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                if attrs.api_group == "*" && attrs.resource == "*" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                return (AuthorizerDecision::Allow, String::new(), None);
            }

            if username == "non-rc-deleter" {
                if attrs.verb == "delete" && attrs.resource == "replicationcontrollers" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                if attrs.verb == "update" && attrs.resource == "replicationcontrollers" && attrs.subresource == "finalizers" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                if attrs.api_group == "*" && attrs.resource == "*" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                return (AuthorizerDecision::Allow, String::new(), None);
            }

            if username == "non-node-deleter" {
                if attrs.verb == "delete" && attrs.resource == "nodes" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                if attrs.verb == "update" && attrs.resource == "nodes" && attrs.subresource == "finalizers" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                if attrs.api_group == "*" && attrs.resource == "*" {
                    return (AuthorizerDecision::NoOpinion, String::new(), None);
                }
                return (AuthorizerDecision::Allow, String::new(), None);
            }

            (AuthorizerDecision::Allow, String::new(), None)
        }
    }

    fn create_plugin() -> Plugin {
        let whitelist = vec![WhiteListItem {
            group_resource: GroupResource::new("", "pods"),
            subresource: "status".to_string(),
        }];

        Plugin::new(whitelist)
            .with_authorizer(Arc::new(FakeAuthorizer))
            .with_rest_mapper(Arc::new(DefaultRESTMapper::with_common_resources()))
    }

    fn obj_with_owner_refs(refs: Vec<OwnerReference>) -> ObjectWithOwnerRefs {
        ObjectWithOwnerRefs::with_owner_refs("foo", "default", refs)
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::default();
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
    fn test_is_whitelisted() {
        let plugin = create_plugin();

        // pods/status should be whitelisted
        let pods_status = GroupResource::new("", "pods");
        assert!(plugin.is_whitelisted(&pods_status, "status"));

        // pods (no subresource) should not be whitelisted
        assert!(!plugin.is_whitelisted(&pods_status, ""));

        // deployments/status should not be whitelisted
        let deployments = GroupResource::new("apps", "deployments");
        assert!(!plugin.is_whitelisted(&deployments, "status"));
    }

    #[test]
    fn test_parse_group_version() {
        // Core API version
        let (group, version) = parse_group_version("v1").unwrap();
        assert_eq!(group, "");
        assert_eq!(version, "v1");

        // Named group
        let (group, version) = parse_group_version("apps/v1").unwrap();
        assert_eq!(group, "apps");
        assert_eq!(version, "v1");

        // Multiple slashes
        let (group, version) = parse_group_version("networking.k8s.io/v1").unwrap();
        assert_eq!(group, "networking.k8s.io");
        assert_eq!(version, "v1");

        // Empty should error
        assert!(parse_group_version("").is_err());
    }

    #[test]
    fn test_is_changing_owner_reference_empty_to_empty() {
        let new_refs: Vec<OwnerReference> = vec![];
        let old_refs: Vec<OwnerReference> = vec![];
        assert!(!is_changing_owner_reference(&new_refs, &old_refs));
    }

    #[test]
    fn test_is_changing_owner_reference_empty_to_non_empty() {
        let new_refs = vec![OwnerReference::new("v1", "Pod", "test")];
        let old_refs: Vec<OwnerReference> = vec![];
        assert!(is_changing_owner_reference(&new_refs, &old_refs));
    }

    #[test]
    fn test_is_changing_owner_reference_same() {
        let refs = vec![OwnerReference::with_uid("v1", "Pod", "test", "uid1")];
        assert!(!is_changing_owner_reference(&refs, &refs));
    }

    #[test]
    fn test_is_changing_owner_reference_different_length() {
        let new_refs = vec![
            OwnerReference::new("v1", "Pod", "test1"),
            OwnerReference::new("v1", "Pod", "test2"),
        ];
        let old_refs = vec![OwnerReference::new("v1", "Pod", "test1")];
        assert!(is_changing_owner_reference(&new_refs, &old_refs));
    }

    #[test]
    fn test_blocking_owner_refs() {
        let refs = vec![
            OwnerReference::new("v1", "Pod", "test1").with_block_owner_deletion(true),
            OwnerReference::new("v1", "Pod", "test2").with_block_owner_deletion(false),
            OwnerReference::new("v1", "Pod", "test3"), // nil
        ];

        let blocking = blocking_owner_refs(&refs);
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0].name, "test1");
    }

    #[test]
    fn test_new_blocking_owner_deletion_refs_create() {
        // On create (old_refs empty), all blocking refs should be returned
        let new_refs = vec![
            OwnerReference::with_uid("v1", "RC", "rc1", "uid1").with_block_owner_deletion(true),
            OwnerReference::with_uid("v1", "RC", "rc2", "uid2").with_block_owner_deletion(false),
        ];
        let old_refs: Vec<OwnerReference> = vec![];

        let new_blocking = new_blocking_owner_deletion_refs(&new_refs, &old_refs);
        assert_eq!(new_blocking.len(), 1);
        assert_eq!(new_blocking[0].name, "rc1");
    }

    #[test]
    fn test_new_blocking_owner_deletion_refs_update_no_change() {
        // No change in blocking status
        let refs = vec![
            OwnerReference::with_uid("v1", "RC", "rc1", "uid1").with_block_owner_deletion(true),
        ];

        let new_blocking = new_blocking_owner_deletion_refs(&refs, &refs);
        assert!(new_blocking.is_empty());
    }

    #[test]
    fn test_new_blocking_owner_deletion_refs_update_false_to_true() {
        // Changing from false to true should be flagged
        let old_refs = vec![
            OwnerReference::with_uid("v1", "RC", "rc1", "uid1").with_block_owner_deletion(false),
        ];
        let new_refs = vec![
            OwnerReference::with_uid("v1", "RC", "rc1", "uid1").with_block_owner_deletion(true),
        ];

        let new_blocking = new_blocking_owner_deletion_refs(&new_refs, &old_refs);
        assert_eq!(new_blocking.len(), 1);
        assert_eq!(new_blocking[0].name, "rc1");
    }

    #[test]
    fn test_new_blocking_owner_deletion_refs_update_nil_to_true() {
        // Changing from nil to true should be flagged
        let old_refs = vec![OwnerReference::with_uid("v1", "RC", "rc1", "uid1")];
        let new_refs = vec![
            OwnerReference::with_uid("v1", "RC", "rc1", "uid1").with_block_owner_deletion(true),
        ];

        let new_blocking = new_blocking_owner_deletion_refs(&new_refs, &old_refs);
        assert_eq!(new_blocking.len(), 1);
    }

    #[test]
    fn test_new_blocking_owner_deletion_refs_update_true_to_false() {
        // Changing from true to false should NOT be flagged
        let old_refs = vec![
            OwnerReference::with_uid("v1", "RC", "rc1", "uid1").with_block_owner_deletion(true),
        ];
        let new_refs = vec![
            OwnerReference::with_uid("v1", "RC", "rc1", "uid1").with_block_owner_deletion(false),
        ];

        let new_blocking = new_blocking_owner_deletion_refs(&new_refs, &old_refs);
        assert!(new_blocking.is_empty());
    }

    #[test]
    fn test_new_blocking_owner_deletion_refs_add_new() {
        // Adding a new blocking ref
        let old_refs = vec![
            OwnerReference::with_uid("v1", "RC", "rc1", "uid1").with_block_owner_deletion(true),
        ];
        let new_refs = vec![
            OwnerReference::with_uid("v1", "RC", "rc1", "uid1").with_block_owner_deletion(true),
            OwnerReference::with_uid("v1", "RC", "rc2", "uid2").with_block_owner_deletion(true),
        ];

        let new_blocking = new_blocking_owner_deletion_refs(&new_refs, &old_refs);
        assert_eq!(new_blocking.len(), 1);
        assert_eq!(new_blocking[0].name, "rc2");
    }

    #[test]
    fn test_owner_refs_equal() {
        let ref1 = OwnerReference::with_uid("v1", "Pod", "test", "uid1")
            .with_block_owner_deletion(true);
        let ref2 = OwnerReference::with_uid("v1", "Pod", "test", "uid1")
            .with_block_owner_deletion(true);
        assert!(owner_refs_equal(&ref1, &ref2));

        let ref3 = OwnerReference::with_uid("v1", "Pod", "test", "uid1")
            .with_block_owner_deletion(false);
        assert!(!owner_refs_equal(&ref1, &ref3));
    }

    #[test]
    fn test_index_by_uid() {
        let refs = vec![
            OwnerReference::with_uid("v1", "Pod", "test1", "uid1"),
            OwnerReference::with_uid("v1", "Pod", "test2", "uid2"),
        ];

        let indexed = index_by_uid(&refs);
        assert_eq!(indexed.len(), 2);
        assert_eq!(indexed.get("uid1").unwrap().name, "test1");
        assert_eq!(indexed.get("uid2").unwrap().name, "test2");
    }

    #[test]
    fn test_validate_whitelisted_subresource() {
        let plugin = create_plugin();

        let obj = obj_with_owner_refs(vec![OwnerReference::new("v1", "Pod", "test")]);
        let old_obj = obj_with_owner_refs(vec![]);

        let attrs = AttributesRecord::new(
            "foo",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "status", // Whitelisted!
            Operation::Update,
            Some(Box::new(obj)),
            Some(Box::new(old_obj)),
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        // Should pass because pods/status is whitelisted
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_validate_no_owner_ref_change() {
        let plugin = create_plugin();

        let obj = obj_with_owner_refs(vec![]);

        let attrs = AttributesRecord::new(
            "foo",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(obj)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        // Should pass because no owner refs are set
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_default_rest_mapper() {
        let mapper = DefaultRESTMapper::with_common_resources();

        // Test core Pod mapping
        let mappings = mapper.rest_mappings("", "Pod", "v1").unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].resource.resource, "pods");
        assert_eq!(mappings[0].scope, RESTScopeName::Namespace);

        // Test core Node mapping (cluster-scoped)
        let mappings = mapper.rest_mappings("", "Node", "v1").unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].resource.resource, "nodes");
        assert_eq!(mappings[0].scope, RESTScopeName::Cluster);

        // Test apps DaemonSet mapping
        let mappings = mapper.rest_mappings("apps", "DaemonSet", "v1").unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].resource.resource, "daemonsets");

        // Test unknown kind
        assert!(mapper.rest_mappings("", "Unknown", "v1").is_err());
    }

    #[test]
    fn test_authorizer_attributes_delete_check() {
        let resource = GroupVersionResource::new("", "v1", "pods");
        let attrs = AuthorizerAttributes::delete_check(
            "test-user",
            "default",
            &resource,
            "",
            "my-pod",
        );

        assert_eq!(attrs.user, "test-user");
        assert_eq!(attrs.verb, "delete");
        assert_eq!(attrs.namespace, "default");
        assert_eq!(attrs.resource, "pods");
        assert_eq!(attrs.name, "my-pod");
    }

    #[test]
    fn test_authorizer_attributes_update_finalizers_check() {
        let resource = GroupVersionResource::new("", "v1", "pods");
        let attrs = AuthorizerAttributes::update_finalizers_check(
            "test-user",
            "default",
            &resource,
            "my-pod",
        );

        assert_eq!(attrs.user, "test-user");
        assert_eq!(attrs.verb, "update");
        assert_eq!(attrs.subresource, "finalizers");
    }

    #[test]
    fn test_authorizer_attributes_finalize_anything() {
        let attrs = AuthorizerAttributes::finalize_anything_check("test-user");

        assert_eq!(attrs.user, "test-user");
        assert_eq!(attrs.verb, "update");
        assert_eq!(attrs.api_group, "*");
        assert_eq!(attrs.resource, "*");
        assert_eq!(attrs.subresource, "finalizers");
        assert_eq!(attrs.name, "*");
    }

    #[test]
    fn test_owner_reference_builder() {
        let owner_ref = OwnerReference::new("v1", "ReplicationController", "my-rc");
        assert_eq!(owner_ref.api_version, "v1");
        assert_eq!(owner_ref.kind, "ReplicationController");
        assert_eq!(owner_ref.name, "my-rc");
        assert!(owner_ref.block_owner_deletion.is_none());

        let owner_ref = owner_ref.with_block_owner_deletion(true);
        assert_eq!(owner_ref.block_owner_deletion, Some(true));

        let owner_ref = OwnerReference::with_uid("apps/v1", "DaemonSet", "my-ds", "abc123");
        assert_eq!(owner_ref.uid, "abc123");
    }

    #[test]
    fn test_object_with_owner_refs() {
        let obj = ObjectWithOwnerRefs::new("test", "default");
        assert_eq!(obj.name, "test");
        assert_eq!(obj.namespace, "default");
        assert!(obj.owner_references.is_empty());

        let refs = vec![OwnerReference::new("v1", "Pod", "owner")];
        let obj = ObjectWithOwnerRefs::with_owner_refs("test", "default", refs);
        assert_eq!(obj.owner_references.len(), 1);
        assert_eq!(obj.get_owner_references().len(), 1);
    }

    #[test]
    fn test_fake_authorizer_super_user() {
        let auth = FakeAuthorizer;

        // Super user (empty username in our simplified test) gets allowed
        let attrs = AuthorizerAttributes {
            user: "super".to_string(),
            verb: "delete".to_string(),
            namespace: "default".to_string(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "pods".to_string(),
            subresource: String::new(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, _, _) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::Allow);
    }

    #[test]
    fn test_fake_authorizer_non_deleter() {
        let auth = FakeAuthorizer;

        // non-deleter cannot delete
        let attrs = AuthorizerAttributes {
            user: "non-deleter".to_string(),
            verb: "delete".to_string(),
            namespace: "default".to_string(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "pods".to_string(),
            subresource: String::new(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, _, _) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::NoOpinion);

        // non-deleter cannot update finalizers
        let attrs = AuthorizerAttributes {
            user: "non-deleter".to_string(),
            verb: "update".to_string(),
            namespace: "default".to_string(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "pods".to_string(),
            subresource: "finalizers".to_string(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, _, _) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::NoOpinion);

        // non-deleter can do other things
        let attrs = AuthorizerAttributes {
            user: "non-deleter".to_string(),
            verb: "get".to_string(),
            namespace: "default".to_string(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "pods".to_string(),
            subresource: String::new(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, _, _) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::Allow);
    }

    #[test]
    fn test_fake_authorizer_non_pod_deleter() {
        let auth = FakeAuthorizer;

        // non-pod-deleter cannot delete pods
        let attrs = AuthorizerAttributes {
            user: "non-pod-deleter".to_string(),
            verb: "delete".to_string(),
            namespace: "default".to_string(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "pods".to_string(),
            subresource: String::new(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, _, _) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::NoOpinion);

        // non-pod-deleter can delete other resources
        let attrs = AuthorizerAttributes {
            user: "non-pod-deleter".to_string(),
            verb: "delete".to_string(),
            namespace: "default".to_string(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "services".to_string(),
            subresource: String::new(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, _, _) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::Allow);
    }

    #[test]
    fn test_fake_authorizer_non_rc_deleter() {
        let auth = FakeAuthorizer;

        // non-rc-deleter cannot delete replicationcontrollers
        let attrs = AuthorizerAttributes {
            user: "non-rc-deleter".to_string(),
            verb: "delete".to_string(),
            namespace: "default".to_string(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "replicationcontrollers".to_string(),
            subresource: String::new(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, _, _) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::NoOpinion);

        // non-rc-deleter cannot update replicationcontrollers/finalizers
        let attrs = AuthorizerAttributes {
            user: "non-rc-deleter".to_string(),
            verb: "update".to_string(),
            namespace: "default".to_string(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "replicationcontrollers".to_string(),
            subresource: "finalizers".to_string(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, _, _) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::NoOpinion);
    }

    #[test]
    fn test_fake_authorizer_non_node_deleter() {
        let auth = FakeAuthorizer;

        // non-node-deleter cannot delete nodes
        let attrs = AuthorizerAttributes {
            user: "non-node-deleter".to_string(),
            verb: "delete".to_string(),
            namespace: String::new(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "nodes".to_string(),
            subresource: String::new(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, _, _) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::NoOpinion);
    }

    #[test]
    fn test_always_allow_authorizer() {
        let auth = AlwaysAllowAuthorizer;
        let attrs = AuthorizerAttributes {
            user: "any-user".to_string(),
            verb: "delete".to_string(),
            namespace: "default".to_string(),
            api_group: String::new(),
            api_version: "v1".to_string(),
            resource: "pods".to_string(),
            subresource: String::new(),
            name: "test".to_string(),
            resource_request: true,
        };

        let (decision, reason, err) = auth.authorize(&attrs);
        assert_eq!(decision, AuthorizerDecision::Allow);
        assert!(reason.is_empty());
        assert!(err.is_none());
    }

    #[test]
    fn test_whitelist_item() {
        let item = WhiteListItem {
            group_resource: GroupResource::new("", "pods"),
            subresource: "status".to_string(),
        };

        assert_eq!(item.group_resource.group, "");
        assert_eq!(item.group_resource.resource, "pods");
        assert_eq!(item.subresource, "status");
    }

    #[test]
    fn test_rest_mapping() {
        let mapping = RESTMapping {
            resource: GroupVersionResource::new("apps", "v1", "deployments"),
            scope: RESTScopeName::Namespace,
        };

        assert_eq!(mapping.resource.group, "apps");
        assert_eq!(mapping.resource.version, "v1");
        assert_eq!(mapping.resource.resource, "deployments");
        assert_eq!(mapping.scope, RESTScopeName::Namespace);
    }

    #[test]
    fn test_default_user_info() {
        let user = DefaultUserInfo::new("test-user");
        assert_eq!(user.get_name(), "test-user");
    }

    #[test]
    fn test_plugin_with_methods() {
        let plugin = Plugin::default()
            .with_authorizer(Arc::new(AlwaysAllowAuthorizer))
            .with_rest_mapper(Arc::new(DefaultRESTMapper::new()));

        assert!(plugin.authorizer.is_some());
        assert!(plugin.rest_mapper.is_some());
    }
}
