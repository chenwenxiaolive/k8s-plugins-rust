// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! ServiceAccount admission controller.
//!
//! This admission controller:
//! 1. If the pod does not specify a ServiceAccount, it sets the pod's ServiceAccount to "default"
//! 2. It ensures the ServiceAccount referenced by the pod exists
//! 3. If LimitSecretReferences is true, it rejects the pod if the pod references Secret objects
//!    which the pod's ServiceAccount does not reference
//! 4. If the pod does not contain any ImagePullSecrets, the ImagePullSecrets of the service account are added
//! 5. If MountServiceAccountToken is true, it adds a VolumeMount with the pod's ServiceAccount's api token

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins, ValidationInterface,
};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, RwLock};

/// Plugin name for ServiceAccount admission controller.
pub const PLUGIN_NAME: &str = "ServiceAccount";

/// DefaultServiceAccountName is the name of the default service account to set on pods.
pub const DEFAULT_SERVICE_ACCOUNT_NAME: &str = "default";

/// EnforceMountableSecretsAnnotation indicates that a service account should enforce mountable secrets.
pub const ENFORCE_MOUNTABLE_SECRETS_ANNOTATION: &str = "kubernetes.io/enforce-mountable-secrets";

/// ServiceAccountVolumeName is the prefix name for volumes that mount ServiceAccount secrets.
pub const SERVICE_ACCOUNT_VOLUME_NAME: &str = "kube-api-access";

/// DefaultAPITokenMountPath is the path that ServiceAccountToken secrets are automounted to.
pub const DEFAULT_API_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// MirrorPodAnnotationKey is the annotation key for mirror pods.
pub const MIRROR_POD_ANNOTATION_KEY: &str = "kubernetes.io/config.mirror";

/// Default token expiration seconds.
pub const DEFAULT_TOKEN_EXPIRATION_SECONDS: i64 = 3607;

/// Default volume mode for projected volumes.
pub const PROJECTED_VOLUME_DEFAULT_MODE: i32 = 0o644;

/// Register the ServiceAccount plugin.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

// ============================================================================
// Types for ServiceAccount plugin
// ============================================================================

/// LocalObjectReference contains enough information to let you locate the referenced object.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LocalObjectReference {
    pub name: String,
}

/// ObjectReference contains enough information to let you inspect or modify the referred object.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ObjectReference {
    pub name: String,
    pub namespace: String,
}

/// ServiceAccount binds together a name with a set of secrets.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceAccount {
    pub name: String,
    pub namespace: String,
    pub annotations: HashMap<String, String>,
    /// Secrets contains the list of secrets allowed to be used by pods running using this ServiceAccount.
    pub secrets: Vec<ObjectReference>,
    /// ImagePullSecrets contains the list of references to secrets in the same namespace for pulling images.
    pub image_pull_secrets: Vec<LocalObjectReference>,
    /// AutomountServiceAccountToken indicates whether pods running as this service account
    /// should have an API token automatically mounted.
    pub automount_service_account_token: Option<bool>,
}

impl ServiceAccount {
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            annotations: HashMap::new(),
            secrets: Vec::new(),
            image_pull_secrets: Vec::new(),
            automount_service_account_token: None,
        }
    }
}

/// SecretVolumeSource adapts a Secret into a volume.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretVolumeSource {
    pub secret_name: String,
}

/// SecretKeySelector selects a key of a Secret.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretKeySelector {
    pub name: String,
    pub key: String,
}

/// SecretEnvSource selects a Secret to populate environment variables.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretEnvSource {
    pub name: String,
}

/// EnvVarSource represents a source for the value of an EnvVar.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EnvVarSource {
    pub secret_key_ref: Option<SecretKeySelector>,
}

/// EnvVar represents an environment variable present in a Container.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
    pub value_from: Option<EnvVarSource>,
}

/// EnvFromSource represents a source for environment variables.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EnvFromSource {
    pub secret_ref: Option<SecretEnvSource>,
}

/// VolumeMount describes a mounting of a Volume within a container.
#[derive(Debug, Clone, PartialEq)]
pub struct VolumeMount {
    pub name: String,
    pub mount_path: String,
    pub read_only: bool,
}

/// KeyToPath maps a key to a file path.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyToPath {
    pub key: String,
    pub path: String,
}

/// ConfigMapProjection projects a configmap into a projected volume.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigMapProjection {
    pub name: String,
    pub items: Vec<KeyToPath>,
}

/// ObjectFieldSelector selects a field of an object.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectFieldSelector {
    pub api_version: String,
    pub field_path: String,
}

/// DownwardAPIVolumeFile represents information to create a file in a downward API volume.
#[derive(Debug, Clone, PartialEq)]
pub struct DownwardAPIVolumeFile {
    pub path: String,
    pub field_ref: Option<ObjectFieldSelector>,
}

/// DownwardAPIProjection projects downward API info into a projected volume.
#[derive(Debug, Clone, PartialEq)]
pub struct DownwardAPIProjection {
    pub items: Vec<DownwardAPIVolumeFile>,
}

/// ServiceAccountTokenProjection projects a service account token into a projected volume.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceAccountTokenProjection {
    pub path: String,
    pub expiration_seconds: i64,
}

/// VolumeProjection can project several sources into the same directory.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VolumeProjection {
    pub service_account_token: Option<ServiceAccountTokenProjection>,
    pub config_map: Option<ConfigMapProjection>,
    pub downward_api: Option<DownwardAPIProjection>,
}

/// ProjectedVolumeSource represents a projected volume source.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectedVolumeSource {
    pub sources: Vec<VolumeProjection>,
    pub default_mode: Option<i32>,
}

/// ServiceAccountVolumeSource represents a service account volume.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceAccountVolumeSource {
    pub secret: Option<SecretVolumeSource>,
    pub projected: Option<ProjectedVolumeSource>,
}

/// ServiceAccountVolume represents a volume for service account tokens.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceAccountVolume {
    pub name: String,
    pub source: ServiceAccountVolumeSource,
}

/// Container represents a container with environment and volume mount info.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Container {
    pub name: String,
    pub env: Vec<EnvVar>,
    pub env_from: Vec<EnvFromSource>,
    pub volume_mounts: Vec<VolumeMount>,
}

/// EphemeralContainer is a container that may be added to an existing pod for debugging.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EphemeralContainer {
    pub name: String,
    pub env: Vec<EnvVar>,
    pub env_from: Vec<EnvFromSource>,
}

/// PodSpec represents a pod specification for service account admission.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PodSpec {
    pub service_account_name: String,
    pub automount_service_account_token: Option<bool>,
    pub containers: Vec<Container>,
    pub init_containers: Vec<Container>,
    pub ephemeral_containers: Vec<EphemeralContainer>,
    pub volumes: Vec<ServiceAccountVolume>,
    pub image_pull_secrets: Vec<LocalObjectReference>,
}

/// Pod represents a pod for service account admission.
#[derive(Debug, Clone, PartialEq)]
pub struct Pod {
    pub name: String,
    pub namespace: String,
    pub annotations: HashMap<String, String>,
    pub spec: PodSpec,
}

impl Pod {
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            annotations: HashMap::new(),
            spec: PodSpec::default(),
        }
    }

    /// Check if this is a mirror pod.
    pub fn is_mirror_pod(&self) -> bool {
        self.annotations.contains_key(MIRROR_POD_ANNOTATION_KEY)
    }
}

impl crate::api::core::ApiObject for Pod {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "Pod"
    }
}

// ============================================================================
// ServiceAccount Store Trait
// ============================================================================

/// Trait for service account store operations.
pub trait ServiceAccountStore: Send + Sync {
    fn get(&self, namespace: &str, name: &str) -> Option<ServiceAccount>;
}

/// In-memory service account store for testing.
pub struct InMemoryServiceAccountStore {
    accounts: RwLock<HashMap<String, ServiceAccount>>,
}

impl InMemoryServiceAccountStore {
    pub fn new() -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
        }
    }

    pub fn add(&self, sa: ServiceAccount) {
        let key = format!("{}/{}", sa.namespace, sa.name);
        let mut accounts = self.accounts.write().unwrap();
        accounts.insert(key, sa);
    }
}

impl Default for InMemoryServiceAccountStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceAccountStore for InMemoryServiceAccountStore {
    fn get(&self, namespace: &str, name: &str) -> Option<ServiceAccount> {
        let key = format!("{}/{}", namespace, name);
        let accounts = self.accounts.read().unwrap();
        accounts.get(&key).cloned()
    }
}

// ============================================================================
// Plugin Implementation
// ============================================================================

/// ServiceAccount admission plugin.
pub struct Plugin {
    handler: Handler,
    /// LimitSecretReferences rejects pods that reference secrets their service accounts do not reference.
    pub limit_secret_references: bool,
    /// MountServiceAccountToken creates Volume and VolumeMounts for the service account token.
    pub mount_service_account_token: bool,
    /// Service account store.
    service_account_store: Option<Arc<dyn ServiceAccountStore>>,
    /// Name generator function.
    generate_name: fn(&str) -> String,
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            limit_secret_references: false,
            mount_service_account_token: true,
            service_account_store: None,
            generate_name: default_generate_name,
        }
    }

    pub fn with_service_account_store(mut self, store: Arc<dyn ServiceAccountStore>) -> Self {
        self.service_account_store = Some(store);
        self
    }

    pub fn with_generate_name(mut self, f: fn(&str) -> String) -> Self {
        self.generate_name = f;
        self
    }

    /// Get a service account from the store.
    fn get_service_account(&self, namespace: &str, name: &str) -> Option<ServiceAccount> {
        self.service_account_store.as_ref()?.get(namespace, name)
    }

    /// Check if the service account enforces mountable secrets.
    fn enforce_mountable_secrets(&self, sa: &ServiceAccount) -> bool {
        if self.limit_secret_references {
            return true;
        }

        if let Some(value) = sa.annotations.get(ENFORCE_MOUNTABLE_SECRETS_ANNOTATION) {
            return value.parse::<bool>().unwrap_or(false);
        }

        false
    }

    /// Check if a pod should automount the service account token.
    fn should_automount(&self, sa: &ServiceAccount, pod: &Pod) -> bool {
        // Pod's preference wins
        if let Some(automount) = pod.spec.automount_service_account_token {
            return automount;
        }
        // Then service account's
        if let Some(automount) = sa.automount_service_account_token {
            return automount;
        }
        // Default to true for backwards compatibility
        true
    }

    /// Mount the service account token volume.
    fn mount_service_account_token_volume(&self, _sa: &ServiceAccount, pod: &mut Pod) {
        // Find existing token volume
        let mut token_volume_name = String::new();
        let mut has_token_volume = false;

        for volume in &pod.spec.volumes {
            if volume.name.starts_with(&format!("{}-", SERVICE_ACCOUNT_VOLUME_NAME)) {
                token_volume_name = volume.name.clone();
                has_token_volume = true;
                break;
            }
        }

        // Generate volume name if needed
        if token_volume_name.is_empty() {
            token_volume_name = (self.generate_name)(&format!("{}-", SERVICE_ACCOUNT_VOLUME_NAME));
        }

        // Create the volume mount
        let volume_mount = VolumeMount {
            name: token_volume_name.clone(),
            read_only: true,
            mount_path: DEFAULT_API_TOKEN_MOUNT_PATH.to_string(),
        };

        // Add volume mount to containers that don't already have one at the default path
        let mut needs_token_volume = false;

        for container in &mut pod.spec.init_containers {
            let has_mount = container
                .volume_mounts
                .iter()
                .any(|vm| vm.mount_path == DEFAULT_API_TOKEN_MOUNT_PATH);
            if !has_mount {
                container.volume_mounts.push(volume_mount.clone());
                needs_token_volume = true;
            }
        }

        for container in &mut pod.spec.containers {
            let has_mount = container
                .volume_mounts
                .iter()
                .any(|vm| vm.mount_path == DEFAULT_API_TOKEN_MOUNT_PATH);
            if !has_mount {
                container.volume_mounts.push(volume_mount.clone());
                needs_token_volume = true;
            }
        }

        // Add the volume if needed
        if !has_token_volume && needs_token_volume {
            pod.spec.volumes.push(ServiceAccountVolume {
                name: token_volume_name,
                source: ServiceAccountVolumeSource {
                    projected: Some(token_volume_source()),
                    ..Default::default()
                },
            });
        }
    }

    /// Limit secret references for a pod.
    fn limit_secret_references_for_pod(
        &self,
        sa: &ServiceAccount,
        pod: &Pod,
    ) -> Result<(), String> {
        // Build set of mountable secrets
        let mountable_secrets: HashSet<String> =
            sa.secrets.iter().map(|s| s.name.clone()).collect();

        // Check volume secrets
        for volume in &pod.spec.volumes {
            if let Some(ref secret) = volume.source.secret {
                if !mountable_secrets.contains(&secret.secret_name) {
                    return Err(format!(
                        "volume with secret.secretName=\"{}\" is not allowed because service account {} does not reference that secret",
                        secret.secret_name, sa.name
                    ));
                }
            }
        }

        // Check init container secrets
        for container in &pod.spec.init_containers {
            self.check_container_secrets(&mountable_secrets, container, "init container", &sa.name)?;
        }

        // Check container secrets
        for container in &pod.spec.containers {
            self.check_container_secrets(&mountable_secrets, container, "container", &sa.name)?;
        }

        // Check image pull secrets
        let pull_secrets: HashSet<String> = sa
            .image_pull_secrets
            .iter()
            .map(|s| s.name.clone())
            .collect();

        for (i, pull_secret_ref) in pod.spec.image_pull_secrets.iter().enumerate() {
            if !pull_secrets.contains(&pull_secret_ref.name) {
                return Err(format!(
                    "imagePullSecrets[{}].name=\"{}\" is not allowed because service account {} does not reference that imagePullSecret",
                    i, pull_secret_ref.name, sa.name
                ));
            }
        }

        Ok(())
    }

    /// Check container for secret references.
    fn check_container_secrets(
        &self,
        mountable_secrets: &HashSet<String>,
        container: &Container,
        container_type: &str,
        sa_name: &str,
    ) -> Result<(), String> {
        for env in &container.env {
            if let Some(ref value_from) = env.value_from {
                if let Some(ref secret_key_ref) = value_from.secret_key_ref {
                    if !mountable_secrets.contains(&secret_key_ref.name) {
                        return Err(format!(
                            "{} {} with envVar {} referencing secret.secretName=\"{}\" is not allowed because service account {} does not reference that secret",
                            container_type, container.name, env.name, secret_key_ref.name, sa_name
                        ));
                    }
                }
            }
        }

        for env_from in &container.env_from {
            if let Some(ref secret_ref) = env_from.secret_ref {
                if !mountable_secrets.contains(&secret_ref.name) {
                    return Err(format!(
                        "{} {} with envFrom referencing secret.secretName=\"{}\" is not allowed because service account {} does not reference that secret",
                        container_type, container.name, secret_ref.name, sa_name
                    ));
                }
            }
        }

        Ok(())
    }

    /// Limit ephemeral container secret references.
    fn limit_ephemeral_container_secret_references(
        &self,
        sa: &ServiceAccount,
        pod: &Pod,
    ) -> Result<(), String> {
        let mountable_secrets: HashSet<String> =
            sa.secrets.iter().map(|s| s.name.clone()).collect();

        for container in &pod.spec.ephemeral_containers {
            for env in &container.env {
                if let Some(ref value_from) = env.value_from {
                    if let Some(ref secret_key_ref) = value_from.secret_key_ref {
                        if !mountable_secrets.contains(&secret_key_ref.name) {
                            return Err(format!(
                                "ephemeral container {} with envVar {} referencing secret.secretName=\"{}\" is not allowed because service account {} does not reference that secret",
                                container.name, env.name, secret_key_ref.name, sa.name
                            ));
                        }
                    }
                }
            }

            for env_from in &container.env_from {
                if let Some(ref secret_ref) = env_from.secret_ref {
                    if !mountable_secrets.contains(&secret_ref.name) {
                        return Err(format!(
                            "ephemeral container {} with envFrom referencing secret.secretName=\"{}\" is not allowed because service account {} does not reference that secret",
                            container.name, secret_ref.name, sa.name
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a pod has any secret references.
    fn pod_has_secrets(&self, pod: &Pod) -> bool {
        // Check volumes
        for volume in &pod.spec.volumes {
            if volume.source.secret.is_some() {
                return true;
            }
        }

        // Check containers
        for container in &pod.spec.containers {
            if self.container_has_secrets(container) {
                return true;
            }
        }

        // Check init containers
        for container in &pod.spec.init_containers {
            if self.container_has_secrets(container) {
                return true;
            }
        }

        false
    }

    fn container_has_secrets(&self, container: &Container) -> bool {
        for env in &container.env {
            if let Some(ref value_from) = env.value_from {
                if value_from.secret_key_ref.is_some() {
                    return true;
                }
            }
        }

        for env_from in &container.env_from {
            if env_from.secret_ref.is_some() {
                return true;
            }
        }

        false
    }

    /// Check if pod volumes contain service account token projections.
    fn pod_has_service_account_token_projection(&self, pod: &Pod) -> bool {
        for volume in &pod.spec.volumes {
            if let Some(ref projected) = volume.source.projected {
                for source in &projected.sources {
                    if source.service_account_token.is_some() {
                        return true;
                    }
                }
            }
        }
        false
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

impl MutationInterface for Plugin {
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Only handle pods
        let resource = attributes.get_resource();
        if resource.resource != "pods" {
            return Ok(());
        }

        // Skip non-empty subresources (except ephemeralcontainers which we handle in validate)
        let subresource = attributes.get_subresource();
        if !subresource.is_empty() && subresource != "ephemeralcontainers" {
            return Ok(());
        }

        // Only mutate on create
        if attributes.get_operation() != Operation::Create {
            return Ok(());
        }

        let namespace = attributes.get_namespace().to_string();

        // Get the pod
        let pod = match attributes
            .get_object_mut()
            .and_then(|obj| obj.as_any_mut().downcast_mut::<Pod>())
        {
            Some(pod) => pod,
            None => return Ok(()),
        };

        // Don't modify mirror pods - but still validate them
        if pod.is_mirror_pod() {
            return self.validate_mirror_pod(pod);
        }

        // Set default service account if needed
        if pod.spec.service_account_name.is_empty() {
            pod.spec.service_account_name = DEFAULT_SERVICE_ACCOUNT_NAME.to_string();
        }

        // Get the service account
        let sa = match self.get_service_account(&namespace, &pod.spec.service_account_name) {
            Some(sa) => sa,
            None => {
                return Err(AdmissionError::bad_request(format!(
                    "error looking up service account {}/{}: not found",
                    namespace, pod.spec.service_account_name
                )));
            }
        };

        // Mount service account token if enabled and should automount
        if self.mount_service_account_token && self.should_automount(&sa, pod) {
            self.mount_service_account_token_volume(&sa, pod);
        }

        // Add image pull secrets if pod doesn't have any
        if pod.spec.image_pull_secrets.is_empty() {
            pod.spec.image_pull_secrets = sa
                .image_pull_secrets
                .iter()
                .map(|s| LocalObjectReference {
                    name: s.name.clone(),
                })
                .collect();
        }

        // Validate (limit secret references if needed)
        self.validate_pod(&sa, pod)
    }
}

impl ValidationInterface for Plugin {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // Only handle pods
        let resource = attributes.get_resource();
        if resource.resource != "pods" {
            return Ok(());
        }

        let subresource = attributes.get_subresource();
        let operation = attributes.get_operation();

        // Handle ephemeralcontainers subresource update
        if operation == Operation::Update && subresource == "ephemeralcontainers" {
            return self.validate_ephemeral_containers(attributes);
        }

        // Only validate pod specs during create requests
        if operation != Operation::Create {
            return Ok(());
        }

        // Skip other subresources
        if !subresource.is_empty() {
            return Ok(());
        }

        let namespace = attributes.get_namespace();

        // Get the pod
        let pod = match attributes
            .get_object()
            .and_then(|obj| obj.as_any().downcast_ref::<Pod>())
        {
            Some(pod) => pod,
            None => return Ok(()),
        };

        // Mirror pods have restrictions
        if pod.is_mirror_pod() {
            return self.validate_mirror_pod(pod);
        }

        // Require service account name
        if pod.spec.service_account_name.is_empty() {
            return Err(AdmissionError::bad_request(format!(
                "no service account specified for pod {}/{}",
                namespace, pod.name
            )));
        }

        // Ensure the service account exists
        let sa = match self.get_service_account(namespace, &pod.spec.service_account_name) {
            Some(sa) => sa,
            None => {
                return Err(AdmissionError::bad_request(format!(
                    "error looking up service account {}/{}: not found",
                    namespace, pod.spec.service_account_name
                )));
            }
        };

        // Validate secret references if enforced
        if self.enforce_mountable_secrets(&sa) {
            self.validate_pod(&sa, pod)?;
        }

        Ok(())
    }
}

impl Plugin {
    /// Validate a mirror pod.
    fn validate_mirror_pod(&self, pod: &Pod) -> AdmissionResult<()> {
        if !pod.spec.service_account_name.is_empty() {
            return Err(AdmissionError::bad_request(
                "a mirror pod may not reference service accounts",
            ));
        }

        if self.pod_has_secrets(pod) {
            return Err(AdmissionError::bad_request(
                "a mirror pod may not reference secrets",
            ));
        }

        if self.pod_has_service_account_token_projection(pod) {
            return Err(AdmissionError::bad_request(
                "a mirror pod may not use ServiceAccountToken volume projections",
            ));
        }

        Ok(())
    }

    /// Validate a pod against service account restrictions.
    fn validate_pod(&self, sa: &ServiceAccount, pod: &Pod) -> AdmissionResult<()> {
        if self.enforce_mountable_secrets(sa) {
            if let Err(msg) = self.limit_secret_references_for_pod(sa, pod) {
                return Err(AdmissionError::bad_request(msg));
            }
        }
        Ok(())
    }

    /// Validate ephemeral containers update.
    fn validate_ephemeral_containers(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        let namespace = attributes.get_namespace();

        let pod = match attributes
            .get_object()
            .and_then(|obj| obj.as_any().downcast_ref::<Pod>())
        {
            Some(pod) => pod,
            None => return Ok(()),
        };

        // Require service account name
        if pod.spec.service_account_name.is_empty() {
            return Err(AdmissionError::bad_request(format!(
                "no service account specified for pod {}/{}",
                namespace, pod.name
            )));
        }

        // Get the service account
        let sa = match self.get_service_account(namespace, &pod.spec.service_account_name) {
            Some(sa) => sa,
            None => {
                return Err(AdmissionError::bad_request(format!(
                    "error looking up service account {}/{}: not found",
                    namespace, pod.spec.service_account_name
                )));
            }
        };

        // Check ephemeral container secret references if enforced
        if self.enforce_mountable_secrets(&sa) {
            if let Err(msg) = self.limit_ephemeral_container_secret_references(&sa, pod) {
                return Err(AdmissionError::bad_request(msg));
            }
        }

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Default name generator.
fn default_generate_name(prefix: &str) -> String {
    format!("{}abc123", prefix)
}

/// Generate the projected volume source for service account token.
pub fn token_volume_source() -> ProjectedVolumeSource {
    ProjectedVolumeSource {
        default_mode: Some(PROJECTED_VOLUME_DEFAULT_MODE),
        sources: vec![
            VolumeProjection {
                service_account_token: Some(ServiceAccountTokenProjection {
                    path: "token".to_string(),
                    expiration_seconds: DEFAULT_TOKEN_EXPIRATION_SECONDS,
                }),
                ..Default::default()
            },
            VolumeProjection {
                config_map: Some(ConfigMapProjection {
                    name: "kube-root-ca.crt".to_string(),
                    items: vec![KeyToPath {
                        key: "ca.crt".to_string(),
                        path: "ca.crt".to_string(),
                    }],
                }),
                ..Default::default()
            },
            VolumeProjection {
                downward_api: Some(DownwardAPIProjection {
                    items: vec![DownwardAPIVolumeFile {
                        path: "namespace".to_string(),
                        field_ref: Some(ObjectFieldSelector {
                            api_version: "v1".to_string(),
                            field_path: "metadata.namespace".to_string(),
                        }),
                    }],
                }),
                ..Default::default()
            },
        ],
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    fn test_generate_name(prefix: &str) -> String {
        format!("{}abc123", prefix)
    }

    fn create_test_plugin() -> Plugin {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));
        Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name)
    }

    fn create_pod_attributes(pod: Pod, operation: Operation) -> AttributesRecord {
        let name = pod.name.clone();
        let namespace = pod.namespace.clone();
        AttributesRecord::new(
            &name,
            &namespace,
            GroupVersionResource::new("", "v1", "pods"),
            "",
            operation,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        )
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
    fn test_ignores_non_pod_resource() {
        let plugin = create_test_plugin();
        let mut attrs = AttributesRecord::new(
            "test",
            "myns",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Create,
            None,
            None,
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );
        assert!(plugin.admit(&mut attrs).is_ok());
    }

    #[test]
    fn test_ignores_nil_object() {
        let plugin = create_test_plugin();
        let mut attrs = AttributesRecord::new(
            "test",
            "myns",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            None,
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );
        assert!(plugin.admit(&mut attrs).is_ok());
    }

    #[test]
    fn test_ignores_mirror_pod_without_sa() {
        let plugin = create_test_plugin();
        let mut pod = Pod::new("test", "myns");
        pod.annotations
            .insert(MIRROR_POD_ANNOTATION_KEY.to_string(), "true".to_string());

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        assert!(plugin.admit(&mut attrs).is_ok());
    }

    #[test]
    fn test_rejects_mirror_pod_with_service_account() {
        let plugin = create_test_plugin();
        let mut pod = Pod::new("test", "myns");
        pod.annotations
            .insert(MIRROR_POD_ANNOTATION_KEY.to_string(), "true".to_string());
        pod.spec.service_account_name = DEFAULT_SERVICE_ACCOUNT_NAME.to_string();

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("may not reference service accounts"));
    }

    #[test]
    fn test_rejects_mirror_pod_with_secret_volumes() {
        let plugin = create_test_plugin();
        let mut pod = Pod::new("test", "myns");
        pod.annotations
            .insert(MIRROR_POD_ANNOTATION_KEY.to_string(), "true".to_string());
        pod.spec.volumes.push(ServiceAccountVolume {
            name: "secret-vol".to_string(),
            source: ServiceAccountVolumeSource {
                secret: Some(SecretVolumeSource {
                    secret_name: "mysecret".to_string(),
                }),
                ..Default::default()
            },
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("may not reference secrets"));
    }

    #[test]
    fn test_rejects_mirror_pod_with_token_projection() {
        let plugin = create_test_plugin();
        let mut pod = Pod::new("test", "myns");
        pod.annotations
            .insert(MIRROR_POD_ANNOTATION_KEY.to_string(), "true".to_string());
        pod.spec.volumes.push(ServiceAccountVolume {
            name: "token-vol".to_string(),
            source: ServiceAccountVolumeSource {
                projected: Some(ProjectedVolumeSource {
                    default_mode: None,
                    sources: vec![VolumeProjection {
                        service_account_token: Some(ServiceAccountTokenProjection {
                            path: "token".to_string(),
                            expiration_seconds: 3600,
                        }),
                        ..Default::default()
                    }],
                }),
                ..Default::default()
            },
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ServiceAccountToken volume projections"));
    }

    #[test]
    fn test_assigns_default_service_account() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        let mut pod = Pod::new("test", "myns");
        pod.spec.containers.push(Container::default());

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let pod = attrs
            .get_object()
            .unwrap()
            .as_any()
            .downcast_ref::<Pod>()
            .unwrap();
        assert_eq!(pod.spec.service_account_name, DEFAULT_SERVICE_ACCOUNT_NAME);
    }

    #[test]
    fn test_denies_invalid_service_account() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        // Don't add any service account

        let plugin = Plugin::new().with_service_account_store(store);

        let mut pod = Pod::new("test", "myns");
        pod.spec.service_account_name = "nonexistent".to_string();

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_automounts_api_token() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        let mut pod = Pod::new("test", "myns");
        pod.spec.containers.push(Container::default());

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let pod = attrs
            .get_object()
            .unwrap()
            .as_any()
            .downcast_ref::<Pod>()
            .unwrap();

        // Should have one volume
        assert_eq!(pod.spec.volumes.len(), 1);
        assert!(pod.spec.volumes[0]
            .name
            .starts_with(SERVICE_ACCOUNT_VOLUME_NAME));

        // Should have volume mount in container
        assert_eq!(pod.spec.containers[0].volume_mounts.len(), 1);
        assert_eq!(
            pod.spec.containers[0].volume_mounts[0].mount_path,
            DEFAULT_API_TOKEN_MOUNT_PATH
        );
    }

    #[test]
    fn test_automounts_api_token_init_containers() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        let mut pod = Pod::new("test", "myns");
        pod.spec.init_containers.push(Container::default());

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let pod = attrs
            .get_object()
            .unwrap()
            .as_any()
            .downcast_ref::<Pod>()
            .unwrap();

        // Should have volume mount in init container
        assert_eq!(pod.spec.init_containers[0].volume_mounts.len(), 1);
        assert_eq!(
            pod.spec.init_containers[0].volume_mounts[0].mount_path,
            DEFAULT_API_TOKEN_MOUNT_PATH
        );
    }

    #[test]
    fn test_respects_existing_mount() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        let mut pod = Pod::new("test", "myns");
        pod.spec.containers.push(Container {
            name: "test".to_string(),
            volume_mounts: vec![VolumeMount {
                name: "my-custom-mount".to_string(),
                mount_path: DEFAULT_API_TOKEN_MOUNT_PATH.to_string(),
                read_only: false,
            }],
            ..Default::default()
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let pod = attrs
            .get_object()
            .unwrap()
            .as_any()
            .downcast_ref::<Pod>()
            .unwrap();

        // Should not create a volume since no container needs it
        assert_eq!(pod.spec.volumes.len(), 0);
        // Should keep the existing mount
        assert_eq!(pod.spec.containers[0].volume_mounts.len(), 1);
        assert_eq!(pod.spec.containers[0].volume_mounts[0].name, "my-custom-mount");
    }

    #[test]
    fn test_allows_referenced_secret() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        let mut sa = ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns");
        sa.secrets.push(ObjectReference {
            name: "foo".to_string(),
            namespace: "myns".to_string(),
        });
        store.add(sa);

        let mut plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);
        plugin.limit_secret_references = true;

        let mut pod = Pod::new("test", "myns");
        pod.spec.volumes.push(ServiceAccountVolume {
            name: "secret-vol".to_string(),
            source: ServiceAccountVolumeSource {
                secret: Some(SecretVolumeSource {
                    secret_name: "foo".to_string(),
                }),
                ..Default::default()
            },
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        assert!(plugin.admit(&mut attrs).is_ok());
    }

    #[test]
    fn test_rejects_unreferenced_secret_volumes() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let mut plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);
        plugin.limit_secret_references = true;

        let mut pod = Pod::new("test", "myns");
        pod.spec.volumes.push(ServiceAccountVolume {
            name: "secret-vol".to_string(),
            source: ServiceAccountVolumeSource {
                secret: Some(SecretVolumeSource {
                    secret_name: "foo".to_string(),
                }),
                ..Default::default()
            },
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("secret.secretName"));
    }

    #[test]
    fn test_rejects_unreferenced_secret_env_var() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let mut plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);
        plugin.limit_secret_references = true;

        let mut pod = Pod::new("test", "myns");
        pod.spec.containers.push(Container {
            name: "container-1".to_string(),
            env: vec![EnvVar {
                name: "env-1".to_string(),
                value: String::new(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: "foo".to_string(),
                        key: "key".to_string(),
                    }),
                }),
            }],
            ..Default::default()
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("with envVar"));
    }

    #[test]
    fn test_rejects_unreferenced_secret_env_from() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let mut plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);
        plugin.limit_secret_references = true;

        let mut pod = Pod::new("test", "myns");
        pod.spec.containers.push(Container {
            name: "container-1".to_string(),
            env_from: vec![EnvFromSource {
                secret_ref: Some(SecretEnvSource {
                    name: "foo".to_string(),
                }),
            }],
            ..Default::default()
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("with envFrom"));
    }

    #[test]
    fn test_allows_referenced_image_pull_secrets() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        let mut sa = ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns");
        sa.image_pull_secrets.push(LocalObjectReference {
            name: "foo".to_string(),
        });
        store.add(sa);

        let mut plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);
        plugin.limit_secret_references = true;

        let mut pod = Pod::new("test", "myns");
        pod.spec.image_pull_secrets.push(LocalObjectReference {
            name: "foo".to_string(),
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        assert!(plugin.admit(&mut attrs).is_ok());
    }

    #[test]
    fn test_rejects_unreferenced_image_pull_secrets() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let mut plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);
        plugin.limit_secret_references = true;

        let mut pod = Pod::new("test", "myns");
        pod.spec.image_pull_secrets.push(LocalObjectReference {
            name: "foo".to_string(),
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("imagePullSecrets"));
    }

    #[test]
    fn test_add_image_pull_secrets() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        let mut sa = ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns");
        sa.image_pull_secrets.push(LocalObjectReference {
            name: "foo".to_string(),
        });
        sa.image_pull_secrets.push(LocalObjectReference {
            name: "bar".to_string(),
        });
        store.add(sa);

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        let pod = Pod::new("test", "myns");

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let pod = attrs
            .get_object()
            .unwrap()
            .as_any()
            .downcast_ref::<Pod>()
            .unwrap();

        assert_eq!(pod.spec.image_pull_secrets.len(), 2);
        assert_eq!(pod.spec.image_pull_secrets[0].name, "foo");
        assert_eq!(pod.spec.image_pull_secrets[1].name, "bar");
    }

    #[test]
    fn test_do_not_add_image_pull_secrets_if_pod_has_them() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        let mut sa = ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns");
        sa.image_pull_secrets.push(LocalObjectReference {
            name: "foo".to_string(),
        });
        sa.image_pull_secrets.push(LocalObjectReference {
            name: "bar".to_string(),
        });
        store.add(sa);

        let mut plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);
        plugin.limit_secret_references = true;

        let mut pod = Pod::new("test", "myns");
        pod.spec.image_pull_secrets.push(LocalObjectReference {
            name: "foo".to_string(),
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let pod = attrs
            .get_object()
            .unwrap()
            .as_any()
            .downcast_ref::<Pod>()
            .unwrap();

        // Should not have added the SA's image pull secrets
        assert_eq!(pod.spec.image_pull_secrets.len(), 1);
        assert_eq!(pod.spec.image_pull_secrets[0].name, "foo");
    }

    #[test]
    fn test_enforce_mountable_secrets_annotation() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        let mut sa = ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns");
        sa.annotations.insert(
            ENFORCE_MOUNTABLE_SECRETS_ANNOTATION.to_string(),
            "true".to_string(),
        );
        store.add(sa);

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        let mut pod = Pod::new("test", "myns");
        pod.spec.volumes.push(ServiceAccountVolume {
            name: "secret-vol".to_string(),
            source: ServiceAccountVolumeSource {
                secret: Some(SecretVolumeSource {
                    secret_name: "foo".to_string(),
                }),
                ..Default::default()
            },
        });

        let mut attrs = create_pod_attributes(pod, Operation::Create);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_err());
    }

    #[test]
    fn test_should_automount_pod_preference() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        let mut sa = ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns");
        sa.automount_service_account_token = Some(true);
        store.add(sa.clone());

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        // Pod says no automount - should win
        let mut pod = Pod::new("test", "myns");
        pod.spec.automount_service_account_token = Some(false);

        assert!(!plugin.should_automount(&sa, &pod));
    }

    #[test]
    fn test_should_automount_sa_preference() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        let mut sa = ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns");
        sa.automount_service_account_token = Some(false);
        store.add(sa.clone());

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        let pod = Pod::new("test", "myns");
        // Pod has no preference, SA says no

        assert!(!plugin.should_automount(&sa, &pod));
    }

    #[test]
    fn test_should_automount_default() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        let sa = ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns");
        store.add(sa.clone());

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        let pod = Pod::new("test", "myns");

        // Both have no preference - default to true
        assert!(plugin.should_automount(&sa, &pod));
    }

    #[test]
    fn test_validate_ephemeral_containers_with_unreferenced_secret() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let mut plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);
        plugin.limit_secret_references = true;

        let mut pod = Pod::new("test", "myns");
        pod.spec.service_account_name = DEFAULT_SERVICE_ACCOUNT_NAME.to_string();
        pod.spec.ephemeral_containers.push(EphemeralContainer {
            name: "debug".to_string(),
            env: vec![EnvVar {
                name: "env-1".to_string(),
                value: String::new(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: "foo".to_string(),
                        key: "key".to_string(),
                    }),
                }),
            }],
            ..Default::default()
        });

        let attrs = AttributesRecord::new(
            "test",
            "myns",
            GroupVersionResource::new("", "v1", "pods"),
            "ephemeralcontainers",
            Operation::Update,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ephemeral container"));
    }

    #[test]
    fn test_validate_allows_referenced_ephemeral_container_secret() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        let mut sa = ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns");
        sa.secrets.push(ObjectReference {
            name: "foo".to_string(),
            namespace: "myns".to_string(),
        });
        store.add(sa);

        let mut plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);
        plugin.limit_secret_references = true;

        let mut pod = Pod::new("test", "myns");
        pod.spec.service_account_name = DEFAULT_SERVICE_ACCOUNT_NAME.to_string();
        pod.spec.ephemeral_containers.push(EphemeralContainer {
            name: "debug".to_string(),
            env: vec![EnvVar {
                name: "env-1".to_string(),
                value: String::new(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: "foo".to_string(),
                        key: "key".to_string(),
                    }),
                }),
            }],
            ..Default::default()
        });

        let attrs = AttributesRecord::new(
            "test",
            "myns",
            GroupVersionResource::new("", "v1", "pods"),
            "ephemeralcontainers",
            Operation::Update,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_token_volume_source() {
        let source = token_volume_source();

        assert_eq!(source.default_mode, Some(PROJECTED_VOLUME_DEFAULT_MODE));
        assert_eq!(source.sources.len(), 3);

        // Check service account token projection
        let token = source.sources[0].service_account_token.as_ref().unwrap();
        assert_eq!(token.path, "token");
        assert_eq!(token.expiration_seconds, DEFAULT_TOKEN_EXPIRATION_SECONDS);

        // Check configmap projection
        let cm = source.sources[1].config_map.as_ref().unwrap();
        assert_eq!(cm.name, "kube-root-ca.crt");
        assert_eq!(cm.items.len(), 1);
        assert_eq!(cm.items[0].key, "ca.crt");

        // Check downward API projection
        let da = source.sources[2].downward_api.as_ref().unwrap();
        assert_eq!(da.items.len(), 1);
        assert_eq!(da.items[0].path, "namespace");
    }

    #[test]
    fn test_default_trait() {
        let plugin = Plugin::default();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.mount_service_account_token);
        assert!(!plugin.limit_secret_references);
    }

    #[test]
    fn test_ignores_update_operation_for_mutation() {
        let store = Arc::new(InMemoryServiceAccountStore::new());
        store.add(ServiceAccount::new(DEFAULT_SERVICE_ACCOUNT_NAME, "myns"));

        let plugin = Plugin::new()
            .with_service_account_store(store)
            .with_generate_name(test_generate_name);

        let mut pod = Pod::new("test", "myns");
        pod.spec.containers.push(Container::default());

        let mut attrs = create_pod_attributes(pod, Operation::Update);
        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        // Pod should not have been modified (no volumes added)
        let pod = attrs
            .get_object()
            .unwrap()
            .as_any()
            .downcast_ref::<Pod>()
            .unwrap();
        assert!(pod.spec.volumes.is_empty());
    }
}
