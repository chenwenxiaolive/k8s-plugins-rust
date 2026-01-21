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

//! ImagePolicyWebhook admission controller.
//!
//! This admission controller validates container images against an external webhook.
//! It intercepts pod creation and update requests, extracts container images,
//! and sends them to a configured webhook backend for policy decisions.
//!
//! Key features:
//! - Validates container images against external webhook
//! - Supports image review requests and responses
//! - Caches review results with configurable TTLs
//! - Supports fail-open or fail-closed behavior on webhook errors
//! - Filters annotations by image-policy.k8s.io domain

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use crate::api::core::{resource, Pod};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Plugin name for the ImagePolicyWebhook admission controller.
pub const PLUGIN_NAME: &str = "ImagePolicyWebhook";

/// Subresource name for ephemeral containers.
const EPHEMERAL_CONTAINERS: &str = "ephemeralcontainers";

/// Audit key prefix for all audit keys handled by this plugin.
pub const AUDIT_KEY_PREFIX: &str = "imagepolicywebhook.image-policy.k8s.io/";

/// Annotation key suffix indicating the image review failed open.
pub const IMAGE_POLICY_FAILED_OPEN_KEY_SUFFIX: &str = "failed-open";

/// Annotation key suffix indicating the pod should be audited.
pub const IMAGE_POLICY_AUDIT_REQUIRED_KEY_SUFFIX: &str = "audit-required";

/// Pod annotation key for failed open indication (legacy).
pub const IMAGE_POLICY_FAILED_OPEN_KEY: &str = "alpha.image-policy.k8s.io/failed-open";

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default retry backoff duration.
#[allow(dead_code)]
const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_millis(500);
/// Minimum retry backoff duration.
#[allow(dead_code)]
const MIN_RETRY_BACKOFF: Duration = Duration::from_nanos(1);
/// Maximum retry backoff duration.
#[allow(dead_code)]
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(300); // 5 minutes

/// Default TTL for allowed responses.
const DEFAULT_ALLOW_TTL: Duration = Duration::from_secs(300); // 5 minutes
/// Default TTL for denied responses.
const DEFAULT_DENY_TTL: Duration = Duration::from_secs(30);

/// Minimum TTL for allowed responses.
const MIN_ALLOW_TTL: Duration = Duration::from_secs(1);
/// Maximum TTL for allowed responses.
const MAX_ALLOW_TTL: Duration = Duration::from_secs(1800); // 30 minutes

/// Minimum TTL for denied responses.
const MIN_DENY_TTL: Duration = Duration::from_secs(1);
/// Maximum TTL for denied responses.
const MAX_DENY_TTL: Duration = Duration::from_secs(1800); // 30 minutes

// ============================================================================
// ImageReview Types (matching k8s.io/api/imagepolicy/v1alpha1)
// ============================================================================

/// ImageReviewContainerSpec is a description of a container within the pod creation request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageReviewContainerSpec {
    /// The image being reviewed.
    pub image: String,
}

impl ImageReviewContainerSpec {
    /// Create a new container spec with the given image.
    pub fn new(image: &str) -> Self {
        Self {
            image: image.to_string(),
        }
    }
}

/// ImageReviewSpec holds information about the pod being evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReviewSpec {
    /// Containers is a list of containers being created.
    pub containers: Vec<ImageReviewContainerSpec>,
    /// Annotations contains filtered pod annotations.
    pub annotations: HashMap<String, String>,
    /// Namespace is the namespace the pod is being created in.
    pub namespace: String,
}

impl ImageReviewSpec {
    /// Create a new review spec.
    pub fn new(containers: Vec<ImageReviewContainerSpec>, namespace: &str) -> Self {
        Self {
            containers,
            annotations: HashMap::new(),
            namespace: namespace.to_string(),
        }
    }

    /// Create a cache key from this spec.
    pub fn cache_key(&self) -> String {
        // Create a deterministic cache key from the spec
        let mut key = format!("ns:{}|", self.namespace);

        // Sort containers for deterministic ordering
        let mut images: Vec<_> = self.containers.iter().map(|c| &c.image).collect();
        images.sort();
        for img in images {
            key.push_str(&format!("img:{}|", img));
        }

        // Sort annotations for deterministic ordering
        let mut ann_keys: Vec<_> = self.annotations.keys().collect();
        ann_keys.sort();
        for k in ann_keys {
            if let Some(v) = self.annotations.get(k) {
                key.push_str(&format!("ann:{}={}|", k, v));
            }
        }

        key
    }
}

/// ImageReviewStatus is the result of the review for the pod creation request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageReviewStatus {
    /// Allowed indicates whether all images are allowed.
    pub allowed: bool,
    /// Reason is a brief description of why the images were allowed or denied.
    pub reason: String,
    /// AuditAnnotations are audit annotations to add to the admission response.
    pub audit_annotations: HashMap<String, String>,
}

impl ImageReviewStatus {
    /// Create a new allowed status.
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            reason: String::new(),
            audit_annotations: HashMap::new(),
        }
    }

    /// Create a new denied status with a reason.
    pub fn denied(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.to_string(),
            audit_annotations: HashMap::new(),
        }
    }
}

/// ImageReview checks if the set of images in a pod are allowed.
#[derive(Debug, Clone)]
pub struct ImageReview {
    /// APIVersion of the image review.
    pub api_version: String,
    /// Kind of the image review.
    pub kind: String,
    /// Spec holds information about the pod being evaluated.
    pub spec: ImageReviewSpec,
    /// Status is the result of the review.
    pub status: ImageReviewStatus,
}

fn default_api_version() -> String {
    "imagepolicy.k8s.io/v1alpha1".to_string()
}

fn default_kind() -> String {
    "ImageReview".to_string()
}

impl ImageReview {
    /// Create a new image review.
    pub fn new(spec: ImageReviewSpec) -> Self {
        Self {
            api_version: default_api_version(),
            kind: default_kind(),
            spec,
            status: ImageReviewStatus::default(),
        }
    }
}

// ============================================================================
// Configuration Types
// ============================================================================

/// ImagePolicyWebhookConfig holds configuration for the webhook.
#[derive(Debug, Clone)]
pub struct ImagePolicyWebhookConfig {
    /// Path to the kubeconfig file for the webhook backend.
    pub kube_config_file: String,
    /// TTL for allowed responses (in seconds, 0 = use default, -1 = disable).
    pub allow_ttl: i64,
    /// TTL for denied responses (in seconds, 0 = use default, -1 = disable).
    pub deny_ttl: i64,
    /// Retry backoff duration (in milliseconds, 0 = use default).
    pub retry_backoff: i64,
    /// Whether to allow requests when the webhook backend fails.
    pub default_allow: bool,
}

impl ImagePolicyWebhookConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder method to set kube_config_file.
    pub fn with_kube_config_file(mut self, path: &str) -> Self {
        self.kube_config_file = path.to_string();
        self
    }

    /// Builder method to set allow_ttl.
    pub fn with_allow_ttl(mut self, ttl: i64) -> Self {
        self.allow_ttl = ttl;
        self
    }

    /// Builder method to set deny_ttl.
    pub fn with_deny_ttl(mut self, ttl: i64) -> Self {
        self.deny_ttl = ttl;
        self
    }

    /// Builder method to set retry_backoff.
    pub fn with_retry_backoff(mut self, backoff: i64) -> Self {
        self.retry_backoff = backoff;
        self
    }

    /// Builder method to set default_allow.
    pub fn with_default_allow(mut self, allow: bool) -> Self {
        self.default_allow = allow;
        self
    }
}

impl Default for ImagePolicyWebhookConfig {
    fn default() -> Self {
        Self {
            kube_config_file: String::new(),
            allow_ttl: 0,
            deny_ttl: 0,
            retry_backoff: 0,
            default_allow: false,
        }
    }
}

/// AdmissionConfig holds the top-level admission configuration.
#[derive(Debug, Clone, Default)]
pub struct AdmissionConfig {
    /// ImagePolicyWebhook configuration.
    pub image_policy: ImagePolicyWebhookConfig,
}

impl AdmissionConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder method to set image_policy.
    pub fn with_image_policy(mut self, config: ImagePolicyWebhookConfig) -> Self {
        self.image_policy = config;
        self
    }

    /// Parse configuration from a reader containing key=value pairs or simple config format.
    pub fn from_reader(reader: &mut dyn Read) -> Result<Self, AdmissionError> {
        let buf_reader = BufReader::new(reader);
        let mut config = ImagePolicyWebhookConfig::default();

        for line in buf_reader.lines() {
            let line = line.map_err(|e| {
                AdmissionError::internal_error(format!("failed to read config line: {}", e))
            })?;

            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse key=value or key: value format
            let (key, value) = if let Some(pos) = line.find('=') {
                let (k, v) = line.split_at(pos);
                (k.trim(), v[1..].trim())
            } else if let Some(pos) = line.find(':') {
                let (k, v) = line.split_at(pos);
                (k.trim(), v[1..].trim())
            } else {
                continue;
            };

            // Remove quotes if present
            let value = value.trim_matches('"').trim_matches('\'');

            // Match camelCase or snake_case keys
            match key {
                "kubeConfigFile" | "kube_config_file" => {
                    config.kube_config_file = value.to_string();
                }
                "allowTTL" | "allow_ttl" => {
                    config.allow_ttl = value.parse().unwrap_or(0);
                }
                "denyTTL" | "deny_ttl" => {
                    config.deny_ttl = value.parse().unwrap_or(0);
                }
                "retryBackoff" | "retry_backoff" => {
                    config.retry_backoff = value.parse().unwrap_or(0);
                }
                "defaultAllow" | "default_allow" => {
                    config.default_allow = value == "true" || value == "1";
                }
                _ => {
                    // Ignore unknown keys
                }
            }
        }

        Ok(Self { image_policy: config })
    }
}

// ============================================================================
// Cache Types
// ============================================================================

/// CacheEntry holds a cached response with its expiration time.
#[derive(Debug, Clone)]
struct CacheEntry {
    status: ImageReviewStatus,
    expires_at: Instant,
}

impl CacheEntry {
    fn new(status: ImageReviewStatus, ttl: Duration) -> Self {
        Self {
            status,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// LRUExpireCache is a simple LRU cache with expiration.
#[derive(Debug)]
struct LRUExpireCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    max_size: usize,
}

impl LRUExpireCache {
    fn new(max_size: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_size,
        }
    }

    fn get(&self, key: &str) -> Option<ImageReviewStatus> {
        let entries = self.entries.read().ok()?;
        if let Some(entry) = entries.get(key) {
            if !entry.is_expired() {
                return Some(entry.status.clone());
            }
        }
        None
    }

    fn add(&self, key: String, status: ImageReviewStatus, ttl: Duration) {
        if ttl.is_zero() {
            return; // Don't cache if TTL is zero
        }

        if let Ok(mut entries) = self.entries.write() {
            // Evict expired entries if we're at capacity
            if entries.len() >= self.max_size {
                entries.retain(|_, v| !v.is_expired());
            }

            // If still at capacity, remove oldest (simple approach)
            if entries.len() >= self.max_size {
                if let Some(oldest_key) = entries.keys().next().cloned() {
                    entries.remove(&oldest_key);
                }
            }

            entries.insert(key, CacheEntry::new(status, ttl));
        }
    }

    /// Clear all entries from the cache.
    #[cfg(test)]
    #[allow(dead_code)]
    fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }
}

// ============================================================================
// Webhook Client Trait
// ============================================================================

/// WebhookClient is a trait for making webhook requests.
/// This allows for mocking in tests.
pub trait WebhookClient: Send + Sync {
    /// Send an image review request to the webhook backend.
    fn review(&self, review: &ImageReview) -> Result<ImageReviewStatus, WebhookError>;
}

/// WebhookError represents an error from the webhook backend.
#[derive(Debug, Clone)]
pub struct WebhookError {
    pub message: String,
    pub status_code: Option<u16>,
}

impl WebhookError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            status_code: None,
        }
    }

    pub fn with_status(message: &str, status_code: u16) -> Self {
        Self {
            message: message.to_string(),
            status_code: Some(status_code),
        }
    }
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = self.status_code {
            write!(f, "{} (status: {})", self.message, code)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for WebhookError {}

/// A mock webhook client that allows all images by default.
/// In a real implementation, this would make HTTP requests to the webhook backend.
#[derive(Debug, Default)]
pub struct DefaultWebhookClient;

impl WebhookClient for DefaultWebhookClient {
    fn review(&self, _review: &ImageReview) -> Result<ImageReviewStatus, WebhookError> {
        // Default implementation allows all images
        // In production, this would make an HTTP POST to the webhook backend
        Ok(ImageReviewStatus::allowed())
    }
}

/// A configurable mock webhook client for testing.
pub struct MockWebhookClient {
    /// Function to determine if an image is allowed.
    review_fn: Box<dyn Fn(&ImageReview) -> Result<ImageReviewStatus, WebhookError> + Send + Sync>,
}

impl MockWebhookClient {
    /// Create a new mock client that allows all images.
    pub fn allow_all() -> Self {
        Self {
            review_fn: Box::new(|_| Ok(ImageReviewStatus::allowed())),
        }
    }

    /// Create a new mock client that denies all images.
    pub fn deny_all() -> Self {
        Self {
            review_fn: Box::new(|_| Ok(ImageReviewStatus::denied("not allowed"))),
        }
    }

    /// Create a new mock client with custom review logic.
    pub fn with_review_fn<F>(f: F) -> Self
    where
        F: Fn(&ImageReview) -> Result<ImageReviewStatus, WebhookError> + Send + Sync + 'static,
    {
        Self {
            review_fn: Box::new(f),
        }
    }

    /// Create a mock client that simulates backend failure.
    pub fn failing(status_code: u16) -> Self {
        Self {
            review_fn: Box::new(move |_| {
                Err(WebhookError::with_status("webhook backend failure", status_code))
            }),
        }
    }
}

impl WebhookClient for MockWebhookClient {
    fn review(&self, review: &ImageReview) -> Result<ImageReviewStatus, WebhookError> {
        (self.review_fn)(review)
    }
}

// ============================================================================
// Plugin Registration
// ============================================================================

/// Register the ImagePolicyWebhook plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |config: Option<&mut dyn Read>| {
        let plugin = if let Some(reader) = config {
            Plugin::from_config(reader)?
        } else {
            Plugin::new()
        };
        Ok(Arc::new(plugin) as Arc<dyn Interface>)
    });
}

// ============================================================================
// Plugin Implementation
// ============================================================================

/// ImagePolicyWebhook is an implementation of admission.Interface.
/// It validates container images against an external webhook backend.
pub struct Plugin {
    handler: Handler,
    webhook: Arc<dyn WebhookClient>,
    response_cache: Arc<LRUExpireCache>,
    allow_ttl: Duration,
    deny_ttl: Duration,
    default_allow: bool,
}

impl Plugin {
    /// Create a new ImagePolicyWebhook plugin with default settings.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            webhook: Arc::new(DefaultWebhookClient),
            response_cache: Arc::new(LRUExpireCache::new(1024)),
            allow_ttl: DEFAULT_ALLOW_TTL,
            deny_ttl: DEFAULT_DENY_TTL,
            default_allow: false,
        }
    }

    /// Create a new plugin from configuration.
    pub fn from_config(reader: &mut dyn Read) -> Result<Self, AdmissionError> {
        let config = AdmissionConfig::from_reader(reader)?;
        let wh_config = config.image_policy;

        let allow_ttl = normalize_duration(
            "allow cache",
            wh_config.allow_ttl,
            MIN_ALLOW_TTL,
            MAX_ALLOW_TTL,
            DEFAULT_ALLOW_TTL,
        )?;

        let deny_ttl = normalize_duration(
            "deny cache",
            wh_config.deny_ttl,
            MIN_DENY_TTL,
            MAX_DENY_TTL,
            DEFAULT_DENY_TTL,
        )?;

        Ok(Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            webhook: Arc::new(DefaultWebhookClient),
            response_cache: Arc::new(LRUExpireCache::new(1024)),
            allow_ttl,
            deny_ttl,
            default_allow: wh_config.default_allow,
        })
    }

    /// Create a new plugin with a custom webhook client (for testing).
    pub fn with_webhook<W: WebhookClient + 'static>(
        webhook: W,
        allow_ttl: Duration,
        deny_ttl: Duration,
        default_allow: bool,
    ) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            webhook: Arc::new(webhook),
            response_cache: Arc::new(LRUExpireCache::new(1024)),
            allow_ttl,
            deny_ttl,
            default_allow,
        }
    }

    /// Get the TTL for a given status.
    fn status_ttl(&self, status: &ImageReviewStatus) -> Duration {
        if status.allowed {
            self.allow_ttl
        } else {
            self.deny_ttl
        }
    }

    /// Filter annotations to only include those matching *.image-policy.k8s.io/*
    fn filter_annotations(&self, all_annotations: &HashMap<String, String>) -> HashMap<String, String> {
        all_annotations
            .iter()
            .filter(|(k, _)| k.contains(".image-policy.k8s.io/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Handle webhook errors based on defaultAllow setting.
    fn webhook_error(
        &self,
        pod: &mut Pod,
        error: WebhookError,
    ) -> Result<(), AdmissionError> {
        if self.default_allow {
            // Add failed-open annotation to the pod
            pod.annotations.insert(
                IMAGE_POLICY_FAILED_OPEN_KEY.to_string(),
                "true".to_string(),
            );
            Ok(())
        } else {
            Err(AdmissionError::forbidden_msg(format!(
                "pod {} in namespace {} denied: {}",
                &pod.name,
                &pod.namespace,
                &error.to_string(),
            )))
        }
    }

    /// Admit a pod by checking its images against the webhook.
    fn admit_pod(
        &self,
        pod: &mut Pod,
        namespace: &str,
        review: &mut ImageReview,
    ) -> Result<(), AdmissionError> {
        let cache_key = review.spec.cache_key();

        // Check cache first
        if let Some(cached_status) = self.response_cache.get(&cache_key) {
            review.status = cached_status;
        } else {
            // Call webhook
            match self.webhook.review(review) {
                Ok(status) => {
                    let ttl = self.status_ttl(&status);
                    self.response_cache.add(cache_key, status.clone(), ttl);
                    review.status = status;
                }
                Err(e) => {
                    return self.webhook_error(pod, e);
                }
            }
        }

        // Check if allowed
        if !review.status.allowed {
            let reason = if !review.status.reason.is_empty() {
                format!(
                    "image policy webhook backend denied one or more images: {}",
                    review.status.reason
                )
            } else {
                "one or more images rejected by webhook backend".to_string()
            };
            return Err(AdmissionError::forbidden_msg(format!(
                "pod {} in namespace {} denied: {}",
                &pod.name,
                namespace,
                &reason,
            )));
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
        let subresource = attributes.get_subresource();

        // Ignore all calls to subresources other than ephemeralcontainers
        // or calls to resources other than pods
        if (!subresource.is_empty() && subresource != EPHEMERAL_CONTAINERS)
            || attributes.get_resource().group_resource() != resource("pods")
        {
            return Ok(());
        }

        // Get the pod object
        let pod = match attributes.get_object() {
            Some(obj) => match obj.as_any().downcast_ref::<Pod>() {
                Some(p) => p.clone(),
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

        // Build list of ImageReviewContainerSpec
        let container_specs: Vec<ImageReviewContainerSpec> = if subresource.is_empty() {
            // For regular pod create/update, check init containers and regular containers
            pod.spec
                .init_containers
                .iter()
                .chain(pod.spec.containers.iter())
                .map(|c| ImageReviewContainerSpec::new(&c.image))
                .collect()
        } else if subresource == EPHEMERAL_CONTAINERS {
            // For ephemeral containers subresource, only check ephemeral containers
            pod.spec
                .ephemeral_containers
                .iter()
                .map(|c| ImageReviewContainerSpec::new(&c.image))
                .collect()
        } else {
            return Ok(());
        };

        // If no containers to check, allow
        if container_specs.is_empty() {
            return Ok(());
        }

        // Create the image review
        let mut review = ImageReview::new(ImageReviewSpec {
            containers: container_specs,
            annotations: self.filter_annotations(&pod.annotations),
            namespace: attributes.get_namespace().to_string(),
        });

        // Create a mutable copy for potential annotation updates
        let mut pod_copy = pod;

        // Perform the review
        self.admit_pod(&mut pod_copy, attributes.get_namespace(), &mut review)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Normalize a duration configuration value.
fn normalize_duration(
    name: &str,
    value: i64,
    min: Duration,
    max: Duration,
    default: Duration,
) -> Result<Duration, AdmissionError> {
    // -1 means disable (return zero duration)
    if value == -1 {
        return Ok(Duration::ZERO);
    }

    // 0 means use default
    if value == 0 {
        return Ok(default);
    }

    // Convert from seconds to Duration
    let duration = Duration::from_secs(value as u64);

    // Check bounds
    if duration < min || duration > max {
        return Err(AdmissionError::internal_error(format!(
            "image policy webhook {}: valid value is between {:?} and {:?}, got {:?}",
            name, min, max, duration
        )));
    }

    Ok(duration)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{GroupVersionKind, GroupVersionResource};
    use crate::admission::AttributesRecord;
    use crate::api::core::{Container, PodSpec, Service, ServiceSpec};

    /// Helper to create a pod with a single container.
    fn good_pod(image: &str) -> Pod {
        Pod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            node_name: None,
            spec: PodSpec {
                init_containers: vec![],
                containers: vec![Container::new("main", image)],
                ephemeral_containers: vec![],
                volumes: vec![],
                affinity: None,
                tolerations: vec![],
                node_selector: HashMap::new(),
                priority_class_name: String::new(),
                priority: None,
                preemption_policy: None,
                ..Default::default()
            },
        }
    }

    /// Helper to create pod attributes.
    fn new_pod_attributes(
        name: &str,
        namespace: &str,
        operation: Operation,
        pod: Pod,
        subresource: &str,
    ) -> AttributesRecord {
        AttributesRecord::new(
            name,
            namespace,
            GroupVersionResource::new("", "v1", "pods"),
            subresource,
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
    fn test_ignores_non_pod_resources() {
        let plugin = Plugin::new();
        let service = Service {
            name: "test".to_string(),
            namespace: "default".to_string(),
            spec: ServiceSpec::default(),
        };
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "services"),
            "",
            Operation::Create,
            Some(Box::new(service)),
            None,
            GroupVersionKind::new("", "v1", "Service"),
            false,
        );
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ignores_other_subresources() {
        let plugin = Plugin::new();
        let pod = good_pod("nginx");
        let attrs = new_pod_attributes("test", "default", Operation::Update, pod, "status");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_container_allowed() {
        let mock_client = MockWebhookClient::with_review_fn(|review| {
            // Allow "good" images
            if review.spec.containers.iter().all(|c| c.image == "good") {
                Ok(ImageReviewStatus::allowed())
            } else {
                Ok(ImageReviewStatus::denied("not allowed"))
            }
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);
        let pod = good_pod("good");
        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");

        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_container_denied() {
        let mock_client = MockWebhookClient::with_review_fn(|review| {
            // Deny "bad" images
            if review.spec.containers.iter().any(|c| c.image == "bad") {
                Ok(ImageReviewStatus::denied("bad image not allowed"))
            } else {
                Ok(ImageReviewStatus::allowed())
            }
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);
        let pod = good_pod("bad");
        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("bad image not allowed"));
    }

    #[test]
    fn test_multiple_containers_one_bad() {
        let mock_client = MockWebhookClient::with_review_fn(|review| {
            if review.spec.containers.iter().any(|c| c.image == "bad") {
                Ok(ImageReviewStatus::denied("not allowed"))
            } else {
                Ok(ImageReviewStatus::allowed())
            }
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);

        let pod = Pod {
            name: "test".to_string(),
            namespace: "default".to_string(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            node_name: None,
            spec: PodSpec {
                init_containers: vec![],
                containers: vec![
                    Container::new("good-container", "good"),
                    Container::new("bad-container", "bad"),
                ],
                ephemeral_containers: vec![],
                volumes: vec![],
                affinity: None,
                tolerations: vec![],
                node_selector: HashMap::new(),
                priority_class_name: String::new(),
                priority: None,
                preemption_policy: None,
                ..Default::default()
            },
        };

        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");
        let result = plugin.validate(&attrs);
        assert!(result.is_err());
    }

    #[test]
    fn test_init_container_bad() {
        let mock_client = MockWebhookClient::with_review_fn(|review| {
            if review.spec.containers.iter().any(|c| c.image == "bad") {
                Ok(ImageReviewStatus::denied("not allowed"))
            } else {
                Ok(ImageReviewStatus::allowed())
            }
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);

        let pod = Pod {
            name: "test".to_string(),
            namespace: "default".to_string(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            node_name: None,
            spec: PodSpec {
                init_containers: vec![Container::new("init", "bad")],
                containers: vec![Container::new("main", "good")],
                ephemeral_containers: vec![],
                volumes: vec![],
                affinity: None,
                tolerations: vec![],
                node_selector: HashMap::new(),
                priority_class_name: String::new(),
                priority: None,
                preemption_policy: None,
                ..Default::default()
            },
        };

        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");
        let result = plugin.validate(&attrs);
        assert!(result.is_err());
    }

    #[test]
    fn test_ephemeral_containers_subresource() {
        let mock_client = MockWebhookClient::with_review_fn(|review| {
            // When checking ephemeral containers, the spec should only contain ephemeral ones
            if review.spec.containers.iter().any(|c| c.image == "bad-ephemeral") {
                Ok(ImageReviewStatus::denied("not allowed"))
            } else {
                Ok(ImageReviewStatus::allowed())
            }
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);

        let pod = Pod {
            name: "test".to_string(),
            namespace: "default".to_string(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            node_name: None,
            spec: PodSpec {
                init_containers: vec![],
                containers: vec![Container::new("main", "good")],
                ephemeral_containers: vec![Container::new("debug", "bad-ephemeral")],
                volumes: vec![],
                affinity: None,
                tolerations: vec![],
                node_selector: HashMap::new(),
                priority_class_name: String::new(),
                priority: None,
                preemption_policy: None,
                ..Default::default()
            },
        };

        let attrs = new_pod_attributes("test", "default", Operation::Update, pod, "ephemeralcontainers");
        let result = plugin.validate(&attrs);
        assert!(result.is_err());
    }

    #[test]
    fn test_ephemeral_containers_not_checked_on_regular_update() {
        let mock_client = MockWebhookClient::with_review_fn(|review| {
            // When doing regular update (not ephemeralcontainers subresource),
            // ephemeral containers should NOT be in the review
            if review.spec.containers.iter().any(|c| c.image == "bad-ephemeral") {
                Ok(ImageReviewStatus::denied("not allowed"))
            } else {
                Ok(ImageReviewStatus::allowed())
            }
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);

        let pod = Pod {
            name: "test".to_string(),
            namespace: "default".to_string(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            node_name: None,
            spec: PodSpec {
                init_containers: vec![],
                containers: vec![Container::new("main", "good")],
                ephemeral_containers: vec![Container::new("debug", "bad-ephemeral")],
                volumes: vec![],
                affinity: None,
                tolerations: vec![],
                node_selector: HashMap::new(),
                priority_class_name: String::new(),
                priority: None,
                preemption_policy: None,
                ..Default::default()
            },
        };

        // Regular update (subresource = ""), should only check init + regular containers
        let attrs = new_pod_attributes("test", "default", Operation::Update, pod, "");
        let result = plugin.validate(&attrs);
        // Should be allowed because we only check init and regular containers
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_allow_on_webhook_failure() {
        let mock_client = MockWebhookClient::failing(500);

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, true);
        let pod = good_pod("any-image");
        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");

        let result = plugin.validate(&attrs);
        // Should be allowed because defaultAllow = true
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_deny_on_webhook_failure() {
        let mock_client = MockWebhookClient::failing(500);

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);
        let pod = good_pod("any-image");
        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");

        let result = plugin.validate(&attrs);
        // Should be denied because defaultAllow = false
        assert!(result.is_err());
    }

    #[test]
    fn test_annotation_filtering() {
        let plugin = Plugin::new();

        let mut annotations = HashMap::new();
        annotations.insert("test".to_string(), "test".to_string());
        annotations.insert("another".to_string(), "annotation".to_string());
        annotations.insert("my.image-policy.k8s.io/test".to_string(), "value1".to_string());
        annotations.insert("other.image-policy.k8s.io/test2".to_string(), "value2".to_string());

        let filtered = plugin.filter_annotations(&annotations);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains_key("my.image-policy.k8s.io/test"));
        assert!(filtered.contains_key("other.image-policy.k8s.io/test2"));
        assert!(!filtered.contains_key("test"));
        assert!(!filtered.contains_key("another"));
    }

    #[test]
    fn test_annotations_passed_to_webhook() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let received_annotations = Arc::new(RwLock::new(HashMap::new()));
        let annotations_checked = Arc::new(AtomicBool::new(false));

        let received_clone = received_annotations.clone();
        let checked_clone = annotations_checked.clone();

        let mock_client = MockWebhookClient::with_review_fn(move |review| {
            if let Ok(mut received) = received_clone.write() {
                *received = review.spec.annotations.clone();
            }
            checked_clone.store(true, Ordering::SeqCst);
            Ok(ImageReviewStatus::allowed())
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);

        let mut pod = good_pod("test-image");
        pod.annotations.insert("my.image-policy.k8s.io/allow".to_string(), "true".to_string());
        pod.annotations.insert("unrelated-annotation".to_string(), "value".to_string());

        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());

        // Verify annotations were received
        assert!(annotations_checked.load(Ordering::SeqCst));
        let received = received_annotations.read().unwrap();
        assert_eq!(received.len(), 1);
        assert!(received.contains_key("my.image-policy.k8s.io/allow"));
    }

    #[test]
    fn test_cache_hit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let mock_client = MockWebhookClient::with_review_fn(move |_| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(ImageReviewStatus::allowed())
        });

        let plugin = Plugin::with_webhook(
            mock_client,
            Duration::from_secs(60),
            Duration::from_secs(60),
            false,
        );

        let pod = good_pod("cached-image");

        // First call
        let attrs = new_pod_attributes("test1", "default", Operation::Create, pod.clone(), "");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second call with same image - should hit cache
        let attrs = new_pod_attributes("test2", "default", Operation::Create, pod.clone(), "");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 1); // Still 1, cache hit
    }

    #[test]
    fn test_cache_miss_different_image() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let mock_client = MockWebhookClient::with_review_fn(move |_| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(ImageReviewStatus::allowed())
        });

        let plugin = Plugin::with_webhook(
            mock_client,
            Duration::from_secs(60),
            Duration::from_secs(60),
            false,
        );

        // First call with image1
        let pod1 = good_pod("image1");
        let attrs = new_pod_attributes("test1", "default", Operation::Create, pod1, "");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second call with different image - should miss cache
        let pod2 = good_pod("image2");
        let attrs = new_pod_attributes("test2", "default", Operation::Create, pod2, "");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 2); // Now 2, cache miss
    }

    #[test]
    fn test_webhook_error_not_cached() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let mock_client = MockWebhookClient::with_review_fn(move |_| {
            let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                Err(WebhookError::with_status("error", 500))
            } else {
                Ok(ImageReviewStatus::allowed())
            }
        });

        let plugin = Plugin::with_webhook(
            mock_client,
            Duration::from_secs(60),
            Duration::from_secs(60),
            true, // default allow to let first call through
        );

        let pod = good_pod("test-image");

        // First call - error (but allowed due to defaultAllow)
        let attrs = new_pod_attributes("test1", "default", Operation::Create, pod.clone(), "");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second call - should NOT be cached since first was an error
        let attrs = new_pod_attributes("test2", "default", Operation::Create, pod.clone(), "");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 2); // Called again
    }

    #[test]
    fn test_normalize_duration() {
        // Default value (0)
        let result = normalize_duration("test", 0, MIN_ALLOW_TTL, MAX_ALLOW_TTL, DEFAULT_ALLOW_TTL);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DEFAULT_ALLOW_TTL);

        // Disabled (-1)
        let result = normalize_duration("test", -1, MIN_ALLOW_TTL, MAX_ALLOW_TTL, DEFAULT_ALLOW_TTL);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::ZERO);

        // Valid value
        let result = normalize_duration("test", 60, MIN_ALLOW_TTL, MAX_ALLOW_TTL, DEFAULT_ALLOW_TTL);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Duration::from_secs(60));

        // Value too large
        let result = normalize_duration("test", 99999, MIN_ALLOW_TTL, MAX_ALLOW_TTL, DEFAULT_ALLOW_TTL);
        assert!(result.is_err());
    }

    #[test]
    fn test_image_review_spec_cache_key() {
        let spec1 = ImageReviewSpec {
            containers: vec![
                ImageReviewContainerSpec::new("nginx"),
                ImageReviewContainerSpec::new("redis"),
            ],
            annotations: HashMap::new(),
            namespace: "default".to_string(),
        };

        let spec2 = ImageReviewSpec {
            containers: vec![
                ImageReviewContainerSpec::new("redis"),
                ImageReviewContainerSpec::new("nginx"),
            ],
            annotations: HashMap::new(),
            namespace: "default".to_string(),
        };

        // Same containers in different order should have same cache key
        assert_eq!(spec1.cache_key(), spec2.cache_key());

        // Different namespace should have different cache key
        let spec3 = ImageReviewSpec {
            containers: vec![ImageReviewContainerSpec::new("nginx")],
            annotations: HashMap::new(),
            namespace: "other".to_string(),
        };

        let spec4 = ImageReviewSpec {
            containers: vec![ImageReviewContainerSpec::new("nginx")],
            annotations: HashMap::new(),
            namespace: "default".to_string(),
        };

        assert_ne!(spec3.cache_key(), spec4.cache_key());
    }

    #[test]
    fn test_image_review_status() {
        let allowed = ImageReviewStatus::allowed();
        assert!(allowed.allowed);
        assert!(allowed.reason.is_empty());

        let denied = ImageReviewStatus::denied("not allowed");
        assert!(!denied.allowed);
        assert_eq!(denied.reason, "not allowed");
    }

    #[test]
    fn test_webhook_error_display() {
        let err = WebhookError::new("connection failed");
        assert_eq!(err.to_string(), "connection failed");

        let err = WebhookError::with_status("server error", 500);
        assert_eq!(err.to_string(), "server error (status: 500)");
    }

    #[test]
    fn test_lru_cache_basic() {
        let cache = LRUExpireCache::new(10);

        // Add an entry
        cache.add(
            "key1".to_string(),
            ImageReviewStatus::allowed(),
            Duration::from_secs(60),
        );

        // Should find it
        let result = cache.get("key1");
        assert!(result.is_some());
        assert!(result.unwrap().allowed);

        // Should not find non-existent key
        let result = cache.get("key2");
        assert!(result.is_none());
    }

    #[test]
    fn test_lru_cache_expiration() {
        let cache = LRUExpireCache::new(10);

        // Add an entry with very short TTL
        cache.add(
            "key1".to_string(),
            ImageReviewStatus::allowed(),
            Duration::from_nanos(1),
        );

        // Wait a tiny bit
        std::thread::sleep(Duration::from_millis(1));

        // Should be expired
        let result = cache.get("key1");
        assert!(result.is_none());
    }

    #[test]
    fn test_lru_cache_zero_ttl_not_cached() {
        let cache = LRUExpireCache::new(10);

        // Add an entry with zero TTL
        cache.add(
            "key1".to_string(),
            ImageReviewStatus::allowed(),
            Duration::ZERO,
        );

        // Should not be cached
        let result = cache.get("key1");
        assert!(result.is_none());
    }

    #[test]
    fn test_config_parsing_from_reader() {
        let config_str = r#"
kubeConfigFile: /path/to/kubeconfig
allowTTL: 60
denyTTL: 30
retryBackoff: 500
defaultAllow: true
"#;

        let mut reader = std::io::Cursor::new(config_str);
        let config = AdmissionConfig::from_reader(&mut reader).unwrap();
        assert_eq!(config.image_policy.kube_config_file, "/path/to/kubeconfig");
        assert_eq!(config.image_policy.allow_ttl, 60);
        assert_eq!(config.image_policy.deny_ttl, 30);
        assert!(config.image_policy.default_allow);
    }

    #[test]
    fn test_config_builder_pattern() {
        let image_policy_config = ImagePolicyWebhookConfig::new()
            .with_kube_config_file("/path/to/kubeconfig")
            .with_allow_ttl(60)
            .with_deny_ttl(30)
            .with_retry_backoff(500)
            .with_default_allow(true);

        let config = AdmissionConfig::new()
            .with_image_policy(image_policy_config);

        assert_eq!(config.image_policy.kube_config_file, "/path/to/kubeconfig");
        assert_eq!(config.image_policy.allow_ttl, 60);
        assert_eq!(config.image_policy.deny_ttl, 30);
        assert_eq!(config.image_policy.retry_backoff, 500);
        assert!(config.image_policy.default_allow);
    }

    #[test]
    fn test_empty_containers() {
        let mock_client = MockWebhookClient::allow_all();
        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);

        let pod = Pod {
            name: "test".to_string(),
            namespace: "default".to_string(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            node_name: None,
            spec: PodSpec {
                init_containers: vec![],
                containers: vec![],
                ephemeral_containers: vec![],
                volumes: vec![],
                affinity: None,
                tolerations: vec![],
                node_selector: HashMap::new(),
                priority_class_name: String::new(),
                priority: None,
                preemption_policy: None,
                ..Default::default()
            },
        };

        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");
        let result = plugin.validate(&attrs);
        // Should be allowed with no containers
        assert!(result.is_ok());
    }

    #[test]
    fn test_namespace_passed_to_webhook() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let namespace_checked = Arc::new(AtomicBool::new(false));
        let received_namespace = Arc::new(RwLock::new(String::new()));

        let checked_clone = namespace_checked.clone();
        let ns_clone = received_namespace.clone();

        let mock_client = MockWebhookClient::with_review_fn(move |review| {
            if let Ok(mut ns) = ns_clone.write() {
                *ns = review.spec.namespace.clone();
            }
            checked_clone.store(true, Ordering::SeqCst);
            Ok(ImageReviewStatus::allowed())
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);

        let pod = good_pod("test-image");
        let attrs = new_pod_attributes("test", "my-namespace", Operation::Create, pod, "");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());

        assert!(namespace_checked.load(Ordering::SeqCst));
        let ns = received_namespace.read().unwrap();
        assert_eq!(*ns, "my-namespace");
    }

    #[test]
    fn test_default_trait() {
        let plugin = Plugin::default();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
    }

    #[test]
    fn test_all_container_types_checked_on_create() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let container_count = Arc::new(AtomicUsize::new(0));
        let count_clone = container_count.clone();

        let mock_client = MockWebhookClient::with_review_fn(move |review| {
            count_clone.store(review.spec.containers.len(), Ordering::SeqCst);
            Ok(ImageReviewStatus::allowed())
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);

        let pod = Pod {
            name: "test".to_string(),
            namespace: "default".to_string(),
            annotations: HashMap::new(),
            labels: HashMap::new(),
            node_name: None,
            spec: PodSpec {
                init_containers: vec![Container::new("init", "init-image")],
                containers: vec![
                    Container::new("main1", "main-image-1"),
                    Container::new("main2", "main-image-2"),
                ],
                ephemeral_containers: vec![Container::new("debug", "debug-image")],
                volumes: vec![],
                affinity: None,
                tolerations: vec![],
                node_selector: HashMap::new(),
                priority_class_name: String::new(),
                priority: None,
                preemption_policy: None,
                ..Default::default()
            },
        };

        // Regular create should check init + regular containers (not ephemeral)
        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());

        // Should be 3: 1 init + 2 regular (not ephemeral)
        assert_eq!(container_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_denied_with_reason() {
        let mock_client = MockWebhookClient::with_review_fn(|_| {
            Ok(ImageReviewStatus::denied("image contains vulnerabilities"))
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);
        let pod = good_pod("vulnerable-image");
        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("image contains vulnerabilities"));
    }

    #[test]
    fn test_denied_without_reason() {
        let mock_client = MockWebhookClient::with_review_fn(|_| {
            Ok(ImageReviewStatus {
                allowed: false,
                reason: String::new(),
                audit_annotations: HashMap::new(),
            })
        });

        let plugin = Plugin::with_webhook(mock_client, DEFAULT_ALLOW_TTL, DEFAULT_DENY_TTL, false);
        let pod = good_pod("any-image");
        let attrs = new_pod_attributes("test", "default", Operation::Create, pod, "");

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("one or more images rejected by webhook backend"));
    }
}
