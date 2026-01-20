// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! ValidatingAdmissionWebhook admission controller.
//!
//! This admission controller calls external validating webhooks to validate
//! admission requests. It aggregates results from multiple webhooks and
//! supports failure policies (Fail, Ignore).

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use crate::admission::attributes::{GroupVersionKind, GroupVersionResource};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub const PLUGIN_NAME: &str = "ValidatingAdmissionWebhook";

/// Audit annotation prefix for validating webhooks.
pub const VALIDATING_AUDIT_ANNOTATION_PREFIX: &str = "validating.webhook.admission.k8s.io/";

/// Audit annotation prefix for webhooks that failed open.
pub const VALIDATING_AUDIT_ANNOTATION_FAILED_OPEN_KEY_PREFIX: &str =
    "failed-open.validating.webhook.admission.k8s.io/";

// ============================================================================
// Webhook Types
// ============================================================================

/// FailurePolicy defines how to handle webhook failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailurePolicy {
    /// Fail means the admission request should be rejected if the webhook fails.
    #[default]
    Fail,
    /// Ignore means the admission request should be allowed if the webhook fails.
    Ignore,
}

impl FailurePolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            FailurePolicy::Fail => "Fail",
            FailurePolicy::Ignore => "Ignore",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "Ignore" => FailurePolicy::Ignore,
            _ => FailurePolicy::Fail,
        }
    }
}

/// SideEffectClass describes the side effects of a webhook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SideEffectClass {
    /// Unknown means the webhook has unknown side effects.
    Unknown,
    /// None means the webhook has no side effects.
    #[default]
    None,
    /// Some means the webhook has some side effects.
    Some,
    /// NoneOnDryRun means the webhook has no side effects on dry run.
    NoneOnDryRun,
}

impl SideEffectClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            SideEffectClass::Unknown => "Unknown",
            SideEffectClass::None => "None",
            SideEffectClass::Some => "Some",
            SideEffectClass::NoneOnDryRun => "NoneOnDryRun",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "None" => SideEffectClass::None,
            "Some" => SideEffectClass::Some,
            "NoneOnDryRun" => SideEffectClass::NoneOnDryRun,
            _ => SideEffectClass::Unknown,
        }
    }

    /// Check if dry run is supported.
    pub fn supports_dry_run(&self) -> bool {
        matches!(self, SideEffectClass::None | SideEffectClass::NoneOnDryRun)
    }
}

/// MatchPolicy defines how to match resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchPolicy {
    /// Exact means the resource must match exactly.
    #[default]
    Exact,
    /// Equivalent means equivalent resources should match.
    Equivalent,
}

impl MatchPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchPolicy::Exact => "Exact",
            MatchPolicy::Equivalent => "Equivalent",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "Equivalent" => MatchPolicy::Equivalent,
            _ => MatchPolicy::Exact,
        }
    }
}

/// OperationType describes what operations the webhook cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationType {
    All,
    Create,
    Update,
    Delete,
    Connect,
}

impl OperationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationType::All => "*",
            OperationType::Create => "CREATE",
            OperationType::Update => "UPDATE",
            OperationType::Delete => "DELETE",
            OperationType::Connect => "CONNECT",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "*" => OperationType::All,
            "CREATE" => OperationType::Create,
            "UPDATE" => OperationType::Update,
            "DELETE" => OperationType::Delete,
            "CONNECT" => OperationType::Connect,
            _ => OperationType::All,
        }
    }

    /// Check if this operation type matches the given operation.
    pub fn matches(&self, op: Operation) -> bool {
        match self {
            OperationType::All => true,
            OperationType::Create => op == Operation::Create,
            OperationType::Update => op == Operation::Update,
            OperationType::Delete => op == Operation::Delete,
            OperationType::Connect => op == Operation::Connect,
        }
    }
}

/// RuleWithOperations describes what operations on what resources/subresources
/// the webhook cares about.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RuleWithOperations {
    /// Operations is the list of operations this rule applies to.
    pub operations: Vec<OperationType>,
    /// APIGroups is the API groups the resources belong to.
    pub api_groups: Vec<String>,
    /// APIVersions is the API versions the resources belong to.
    pub api_versions: Vec<String>,
    /// Resources is the list of resources this rule applies to.
    pub resources: Vec<String>,
    /// Scope specifies the scope of this rule.
    pub scope: Option<String>,
}

impl RuleWithOperations {
    /// Create a new rule with operations.
    pub fn new(
        operations: Vec<OperationType>,
        api_groups: Vec<String>,
        api_versions: Vec<String>,
        resources: Vec<String>,
    ) -> Self {
        Self {
            operations,
            api_groups,
            api_versions,
            resources,
            scope: None,
        }
    }

    /// Check if this rule matches the given attributes.
    pub fn matches(&self, attr: &dyn Attributes) -> bool {
        let resource = attr.get_resource();
        let operation = attr.get_operation();

        // Check operation
        if !self.operations.iter().any(|op| op.matches(operation)) {
            return false;
        }

        // Check API group
        if !self.api_groups.is_empty()
            && !self.api_groups.iter().any(|g| g == "*" || g == &resource.group)
        {
            return false;
        }

        // Check API version
        if !self.api_versions.is_empty()
            && !self
                .api_versions
                .iter()
                .any(|v| v == "*" || v == &resource.version)
        {
            return false;
        }

        // Check resource
        if !self.resources.is_empty() {
            let subresource = attr.get_subresource();
            let resource_match = self.resources.iter().any(|r| {
                if r == "*" {
                    return true;
                }
                if r.contains('/') {
                    // Rule specifies resource/subresource
                    let full_resource = if subresource.is_empty() {
                        resource.resource.clone()
                    } else {
                        format!("{}/{}", resource.resource, subresource)
                    };
                    r == &full_resource || r == &format!("{}/*", resource.resource)
                } else {
                    // Rule specifies just the resource
                    r == &resource.resource
                }
            });
            if !resource_match {
                return false;
            }
        }

        true
    }
}

/// LabelSelectorRequirement is a selector that contains values, a key, and an operator.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

/// LabelSelector is a label query over a set of resources.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LabelSelector {
    pub match_labels: HashMap<String, String>,
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

impl LabelSelector {
    /// Check if the selector matches the given labels.
    pub fn matches(&self, labels: &HashMap<String, String>) -> bool {
        // Check match_labels
        for (key, value) in &self.match_labels {
            match labels.get(key) {
                Some(v) if v == value => continue,
                _ => return false,
            }
        }

        // Check match_expressions
        for expr in &self.match_expressions {
            let label_value = labels.get(&expr.key);
            let matches = match expr.operator.as_str() {
                "In" => label_value.map_or(false, |v| expr.values.contains(v)),
                "NotIn" => label_value.map_or(true, |v| !expr.values.contains(v)),
                "Exists" => label_value.is_some(),
                "DoesNotExist" => label_value.is_none(),
                _ => true,
            };
            if !matches {
                return false;
            }
        }

        true
    }

    /// Check if the selector is empty (matches everything).
    pub fn is_empty(&self) -> bool {
        self.match_labels.is_empty() && self.match_expressions.is_empty()
    }
}

/// WebhookClientConfig contains the information to make a TLS connection with the webhook.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WebhookClientConfig {
    /// URL gives the location of the webhook.
    pub url: Option<String>,
    /// Service is a reference to the service for this webhook.
    pub service: Option<ServiceReference>,
    /// CABundle is a PEM encoded CA bundle for validating the webhook's server certificate.
    pub ca_bundle: Vec<u8>,
}

/// ServiceReference holds a reference to a Service.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceReference {
    /// Namespace is the namespace of the service.
    pub namespace: String,
    /// Name is the name of the service.
    pub name: String,
    /// Path is an optional URL path.
    pub path: Option<String>,
    /// Port is the port on the service.
    pub port: Option<i32>,
}

impl ServiceReference {
    /// Get the full URL for the service.
    pub fn get_url(&self) -> String {
        let port = self.port.unwrap_or(443);
        let path = self.path.as_deref().unwrap_or("");
        format!(
            "https://{}.{}.svc:{}{}",
            self.name, self.namespace, port, path
        )
    }
}

/// MatchCondition represents a condition which must be fulfilled for a request to be sent to a webhook.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchCondition {
    /// Name is an identifier for this match condition.
    pub name: String,
    /// Expression is a CEL expression that must evaluate to true.
    pub expression: String,
}

/// ValidatingWebhook describes an admission webhook and the resources and operations it applies to.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatingWebhook {
    /// Name is the name of the admission webhook.
    pub name: String,
    /// ClientConfig defines how to communicate with the webhook.
    pub client_config: WebhookClientConfig,
    /// Rules describe what operations on what resources/subresources the webhook cares about.
    pub rules: Vec<RuleWithOperations>,
    /// FailurePolicy defines how to handle webhook failures.
    pub failure_policy: FailurePolicy,
    /// MatchPolicy defines how the "rules" list is used to match incoming requests.
    pub match_policy: MatchPolicy,
    /// NamespaceSelector decides whether to run the webhook on objects in namespaces that match.
    pub namespace_selector: Option<LabelSelector>,
    /// ObjectSelector decides whether to run the webhook based on the object labels.
    pub object_selector: Option<LabelSelector>,
    /// SideEffects states whether this webhook has side effects.
    pub side_effects: SideEffectClass,
    /// TimeoutSeconds specifies the timeout for this webhook.
    pub timeout_seconds: i32,
    /// AdmissionReviewVersions is an ordered list of preferred AdmissionReview versions.
    pub admission_review_versions: Vec<String>,
    /// MatchConditions is a list of conditions that must be met for a request to be sent to this webhook.
    pub match_conditions: Vec<MatchCondition>,
}

impl Default for ValidatingWebhook {
    fn default() -> Self {
        Self {
            name: String::new(),
            client_config: WebhookClientConfig::default(),
            rules: Vec::new(),
            failure_policy: FailurePolicy::Fail,
            match_policy: MatchPolicy::Exact,
            namespace_selector: None,
            object_selector: None,
            side_effects: SideEffectClass::Unknown,
            timeout_seconds: 10,
            admission_review_versions: vec!["v1".to_string()],
            match_conditions: Vec::new(),
        }
    }
}

impl ValidatingWebhook {
    /// Create a new validating webhook.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Create a webhook with rules.
    pub fn with_rules(name: &str, rules: Vec<RuleWithOperations>) -> Self {
        Self {
            name: name.to_string(),
            rules,
            ..Default::default()
        }
    }

    /// Check if this webhook should be called for the given attributes.
    pub fn should_call(&self, attr: &dyn Attributes, namespace_labels: Option<&HashMap<String, String>>) -> bool {
        // Check rules
        if !self.rules.iter().any(|r| r.matches(attr)) {
            return false;
        }

        // Check namespace selector
        if let Some(ref selector) = self.namespace_selector {
            if let Some(ns_labels) = namespace_labels {
                if !selector.matches(ns_labels) {
                    return false;
                }
            }
        }

        // Check object selector (simplified - would need object labels in real impl)
        // For now, we skip this check if no object selector is defined

        true
    }

    /// Check if dry run is supported.
    pub fn supports_dry_run(&self) -> bool {
        self.side_effects.supports_dry_run()
    }

    /// Get the timeout duration.
    pub fn get_timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds as u64)
    }
}

/// ValidatingWebhookConfiguration describes the configuration of validating admission webhooks.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ValidatingWebhookConfiguration {
    /// Name is the name of this configuration.
    pub name: String,
    /// Webhooks is a list of webhooks and the affected resources and operations.
    pub webhooks: Vec<ValidatingWebhook>,
}

impl ValidatingWebhookConfiguration {
    /// Create a new configuration.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            webhooks: Vec::new(),
        }
    }

    /// Create a configuration with webhooks.
    pub fn with_webhooks(name: &str, webhooks: Vec<ValidatingWebhook>) -> Self {
        Self {
            name: name.to_string(),
            webhooks,
        }
    }
}

// ============================================================================
// Admission Review Types
// ============================================================================

/// AdmissionRequest describes the admission.Attributes for the admission request.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionRequest {
    /// UID is an identifier for the individual request/response.
    pub uid: String,
    /// Kind is the fully-qualified type of object being submitted.
    pub kind: GroupVersionKind,
    /// Resource is the fully-qualified resource being requested.
    pub resource: GroupVersionResource,
    /// SubResource is the subresource being requested.
    pub sub_resource: String,
    /// Name is the name of the object as presented in the request.
    pub name: String,
    /// Namespace is the namespace associated with the request.
    pub namespace: String,
    /// Operation is the operation being performed.
    pub operation: String,
    /// DryRun indicates that modifications will definitely not be persisted.
    pub dry_run: bool,
}

impl AdmissionRequest {
    /// Create an admission request from attributes.
    pub fn from_attributes(uid: &str, attr: &dyn Attributes) -> Self {
        let operation = match attr.get_operation() {
            Operation::Create => "CREATE",
            Operation::Update => "UPDATE",
            Operation::Delete => "DELETE",
            Operation::Connect => "CONNECT",
        };

        Self {
            uid: uid.to_string(),
            kind: attr.get_kind().clone(),
            resource: attr.get_resource().clone(),
            sub_resource: attr.get_subresource().to_string(),
            name: attr.get_name().to_string(),
            namespace: attr.get_namespace().to_string(),
            operation: operation.to_string(),
            dry_run: attr.is_dry_run(),
        }
    }
}

/// AdmissionResponse describes an admission response.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionResponse {
    /// UID is an identifier for the individual request/response.
    pub uid: String,
    /// Allowed indicates whether or not the admission request was permitted.
    pub allowed: bool,
    /// Status contains extra details into why an admission request was denied.
    pub status: Option<ResponseStatus>,
    /// Warnings is a list of warning messages to return to the requesting API client.
    pub warnings: Vec<String>,
    /// AuditAnnotations is a map of audit annotations for the admission response.
    pub audit_annotations: HashMap<String, String>,
}

impl Default for AdmissionResponse {
    fn default() -> Self {
        Self {
            uid: String::new(),
            allowed: true,
            status: None,
            warnings: Vec::new(),
            audit_annotations: HashMap::new(),
        }
    }
}

impl AdmissionResponse {
    /// Create an allowed response.
    pub fn allowed(uid: &str) -> Self {
        Self {
            uid: uid.to_string(),
            allowed: true,
            status: None,
            warnings: Vec::new(),
            audit_annotations: HashMap::new(),
        }
    }

    /// Create a denied response.
    pub fn denied(uid: &str, message: &str) -> Self {
        Self {
            uid: uid.to_string(),
            allowed: false,
            status: Some(ResponseStatus {
                code: 403,
                message: message.to_string(),
                reason: "Forbidden".to_string(),
            }),
            warnings: Vec::new(),
            audit_annotations: HashMap::new(),
        }
    }

    /// Create a denied response with a custom status code.
    pub fn denied_with_code(uid: &str, code: i32, message: &str, reason: &str) -> Self {
        Self {
            uid: uid.to_string(),
            allowed: false,
            status: Some(ResponseStatus {
                code,
                message: message.to_string(),
                reason: reason.to_string(),
            }),
            warnings: Vec::new(),
            audit_annotations: HashMap::new(),
        }
    }
}

/// ResponseStatus contains details about the result of the admission request.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseStatus {
    /// Code is the HTTP status code.
    pub code: i32,
    /// Message is a human-readable description.
    pub message: String,
    /// Reason is a machine-readable description.
    pub reason: String,
}

// ============================================================================
// Webhook Client
// ============================================================================

/// WebhookError represents an error from calling a webhook.
#[derive(Debug, Clone, PartialEq)]
pub enum WebhookError {
    /// Error calling the webhook.
    CallingWebhook {
        webhook_name: String,
        reason: String,
        status_code: i32,
    },
    /// Webhook rejected the request.
    Rejection {
        webhook_name: String,
        status: ResponseStatus,
    },
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookError::CallingWebhook {
                webhook_name,
                reason,
                status_code,
            } => write!(
                f,
                "failed to call webhook {}: {} (status: {})",
                webhook_name, reason, status_code
            ),
            WebhookError::Rejection { webhook_name, status } => write!(
                f,
                "admission webhook \"{}\" denied the request: {}",
                webhook_name, status.message
            ),
        }
    }
}

impl std::error::Error for WebhookError {}

/// Trait for calling webhooks.
pub trait WebhookCaller: Send + Sync {
    /// Call a validating webhook.
    fn call(
        &self,
        webhook: &ValidatingWebhook,
        request: &AdmissionRequest,
    ) -> Result<AdmissionResponse, WebhookError>;
}

/// Mock webhook caller for testing.
#[derive(Debug, Default)]
pub struct MockWebhookCaller {
    responses: RwLock<HashMap<String, Result<AdmissionResponse, WebhookError>>>,
}

impl MockWebhookCaller {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the response for a webhook.
    pub fn set_response(&self, webhook_name: &str, response: Result<AdmissionResponse, WebhookError>) {
        self.responses
            .write()
            .unwrap()
            .insert(webhook_name.to_string(), response);
    }

    /// Set an allowed response for a webhook.
    pub fn set_allowed(&self, webhook_name: &str) {
        self.set_response(
            webhook_name,
            Ok(AdmissionResponse::allowed("test-uid")),
        );
    }

    /// Set a denied response for a webhook.
    pub fn set_denied(&self, webhook_name: &str, message: &str) {
        self.set_response(
            webhook_name,
            Ok(AdmissionResponse::denied("test-uid", message)),
        );
    }

    /// Set a call error for a webhook.
    pub fn set_call_error(&self, webhook_name: &str, reason: &str) {
        self.set_response(
            webhook_name,
            Err(WebhookError::CallingWebhook {
                webhook_name: webhook_name.to_string(),
                reason: reason.to_string(),
                status_code: 500,
            }),
        );
    }
}

impl WebhookCaller for MockWebhookCaller {
    fn call(
        &self,
        webhook: &ValidatingWebhook,
        _request: &AdmissionRequest,
    ) -> Result<AdmissionResponse, WebhookError> {
        let responses = self.responses.read().unwrap();
        match responses.get(&webhook.name) {
            Some(response) => response.clone(),
            None => Ok(AdmissionResponse::allowed("default-uid")),
        }
    }
}

// ============================================================================
// Dispatcher
// ============================================================================

/// ValidatingDispatcher dispatches admission requests to validating webhooks.
pub struct ValidatingDispatcher {
    caller: Arc<dyn WebhookCaller>,
}

impl ValidatingDispatcher {
    /// Create a new dispatcher.
    pub fn new(caller: Arc<dyn WebhookCaller>) -> Self {
        Self { caller }
    }

    /// Dispatch the request to all matching webhooks.
    pub fn dispatch(
        &self,
        attr: &dyn Attributes,
        webhooks: &[ValidatingWebhook],
        namespace_labels: Option<&HashMap<String, String>>,
    ) -> AdmissionResult<()> {
        // Find relevant webhooks
        let relevant_hooks: Vec<_> = webhooks
            .iter()
            .filter(|h| h.should_call(attr, namespace_labels))
            .collect();

        if relevant_hooks.is_empty() {
            return Ok(());
        }

        // Check dry run support
        if attr.is_dry_run() {
            for hook in &relevant_hooks {
                if !hook.supports_dry_run() {
                    return Err(AdmissionError::bad_request(format!(
                        "webhook {} does not support dry run",
                        hook.name
                    )));
                }
            }
        }

        // Create admission request
        let uid = uuid_v4();
        let request = AdmissionRequest::from_attributes(&uid, attr);

        // Call all webhooks and collect errors
        let mut errors: Vec<AdmissionError> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        for hook in relevant_hooks {
            match self.call_hook(hook, &request) {
                Ok(response) => {
                    // Collect warnings
                    warnings.extend(response.warnings);

                    if !response.allowed {
                        let msg = response
                            .status
                            .map(|s| s.message)
                            .unwrap_or_else(|| "request denied".to_string());
                        errors.push(AdmissionError::bad_request(format!(
                            "admission webhook \"{}\" denied the request: {}",
                            hook.name, msg
                        )));
                    }
                }
                Err(e) => {
                    match e {
                        WebhookError::CallingWebhook { ref webhook_name, .. } => {
                            if hook.failure_policy == FailurePolicy::Ignore {
                                // Log and continue (failed open)
                                eprintln!(
                                    "Failed calling webhook {}, failing open: {}",
                                    webhook_name, e
                                );
                            } else {
                                // Fail closed
                                errors.push(AdmissionError::internal_error(format!(
                                    "failed to call webhook {}: {}",
                                    webhook_name, e
                                )));
                            }
                        }
                        WebhookError::Rejection { ref webhook_name, ref status } => {
                            errors.push(AdmissionError::bad_request(format!(
                                "admission webhook \"{}\" denied the request: {}",
                                webhook_name, status.message
                            )));
                        }
                    }
                }
            }
        }

        // Return errors if any
        if errors.is_empty() {
            Ok(())
        } else if errors.len() == 1 {
            Err(errors.remove(0))
        } else {
            Err(AdmissionError::aggregate(errors))
        }
    }

    /// Call a single webhook.
    fn call_hook(
        &self,
        hook: &ValidatingWebhook,
        request: &AdmissionRequest,
    ) -> Result<AdmissionResponse, WebhookError> {
        self.caller.call(hook, request)
    }
}

// ============================================================================
// Plugin
// ============================================================================

/// Register the ValidatingAdmissionWebhook plugin.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Trait for providing webhook configurations.
pub trait WebhookConfigurationSource: Send + Sync {
    /// Get all validating webhook configurations.
    fn get_webhooks(&self) -> Vec<ValidatingWebhook>;
}

/// In-memory webhook configuration source.
#[derive(Debug, Default)]
pub struct InMemoryWebhookSource {
    configurations: RwLock<Vec<ValidatingWebhookConfiguration>>,
}

impl InMemoryWebhookSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a configuration.
    pub fn add_configuration(&self, config: ValidatingWebhookConfiguration) {
        self.configurations.write().unwrap().push(config);
    }

    /// Clear all configurations.
    pub fn clear(&self) {
        self.configurations.write().unwrap().clear();
    }
}

impl WebhookConfigurationSource for InMemoryWebhookSource {
    fn get_webhooks(&self) -> Vec<ValidatingWebhook> {
        self.configurations
            .read()
            .unwrap()
            .iter()
            .flat_map(|c| c.webhooks.clone())
            .collect()
    }
}

/// Trait for providing namespace labels.
pub trait NamespaceLabelSource: Send + Sync {
    /// Get labels for a namespace.
    fn get_namespace_labels(&self, namespace: &str) -> Option<HashMap<String, String>>;
}

/// In-memory namespace label source.
#[derive(Debug, Default)]
pub struct InMemoryNamespaceLabelSource {
    labels: RwLock<HashMap<String, HashMap<String, String>>>,
}

impl InMemoryNamespaceLabelSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set labels for a namespace.
    pub fn set_labels(&self, namespace: &str, labels: HashMap<String, String>) {
        self.labels
            .write()
            .unwrap()
            .insert(namespace.to_string(), labels);
    }
}

impl NamespaceLabelSource for InMemoryNamespaceLabelSource {
    fn get_namespace_labels(&self, namespace: &str) -> Option<HashMap<String, String>> {
        self.labels.read().unwrap().get(namespace).cloned()
    }
}

/// Plugin is the ValidatingAdmissionWebhook admission controller.
pub struct Plugin {
    handler: Handler,
    dispatcher: Option<ValidatingDispatcher>,
    webhook_source: Option<Arc<dyn WebhookConfigurationSource>>,
    namespace_label_source: Option<Arc<dyn NamespaceLabelSource>>,
}

impl Plugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[
                Operation::Create,
                Operation::Update,
                Operation::Delete,
                Operation::Connect,
            ]),
            dispatcher: None,
            webhook_source: None,
            namespace_label_source: None,
        }
    }

    /// Create a plugin with a webhook caller.
    pub fn with_caller(caller: Arc<dyn WebhookCaller>) -> Self {
        Self {
            handler: Handler::new(&[
                Operation::Create,
                Operation::Update,
                Operation::Delete,
                Operation::Connect,
            ]),
            dispatcher: Some(ValidatingDispatcher::new(caller)),
            webhook_source: None,
            namespace_label_source: None,
        }
    }

    /// Create a fully configured plugin.
    pub fn with_config(
        caller: Arc<dyn WebhookCaller>,
        webhook_source: Arc<dyn WebhookConfigurationSource>,
        namespace_label_source: Arc<dyn NamespaceLabelSource>,
    ) -> Self {
        Self {
            handler: Handler::new(&[
                Operation::Create,
                Operation::Update,
                Operation::Delete,
                Operation::Connect,
            ]),
            dispatcher: Some(ValidatingDispatcher::new(caller)),
            webhook_source: Some(webhook_source),
            namespace_label_source: Some(namespace_label_source),
        }
    }

    /// Set the webhook caller.
    pub fn set_caller(&mut self, caller: Arc<dyn WebhookCaller>) {
        self.dispatcher = Some(ValidatingDispatcher::new(caller));
    }

    /// Set the webhook configuration source.
    pub fn set_webhook_source(&mut self, source: Arc<dyn WebhookConfigurationSource>) {
        self.webhook_source = Some(source);
    }

    /// Set the namespace label source.
    pub fn set_namespace_label_source(&mut self, source: Arc<dyn NamespaceLabelSource>) {
        self.namespace_label_source = Some(source);
    }

    /// Check if this is an exempt resource (webhook configurations themselves).
    fn is_exempt_resource(&self, attr: &dyn Attributes) -> bool {
        let resource = attr.get_resource();
        // ValidatingWebhookConfiguration and MutatingWebhookConfiguration are exempt
        resource.group == "admissionregistration.k8s.io"
            && (resource.resource == "validatingwebhookconfigurations"
                || resource.resource == "mutatingwebhookconfigurations")
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
        // Skip exempt resources
        if self.is_exempt_resource(attributes) {
            return Ok(());
        }

        // Get dispatcher
        let dispatcher = match &self.dispatcher {
            Some(d) => d,
            None => return Ok(()), // No dispatcher configured
        };

        // Get webhooks
        let webhooks = match &self.webhook_source {
            Some(source) => source.get_webhooks(),
            None => return Ok(()), // No webhook source configured
        };

        if webhooks.is_empty() {
            return Ok(());
        }

        // Get namespace labels
        let namespace_labels = self
            .namespace_label_source
            .as_ref()
            .and_then(|s| s.get_namespace_labels(attributes.get_namespace()));

        // Dispatch to webhooks
        dispatcher.dispatch(attributes, &webhooks, namespace_labels.as_ref())
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Generate a simple UUID v4 (for testing purposes).
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (duration.as_nanos() & 0xFFFFFFFF) as u32,
        ((duration.as_nanos() >> 32) & 0xFFFF) as u16,
        ((duration.as_nanos() >> 48) & 0x0FFF) as u16,
        (0x8000 | ((duration.as_nanos() >> 60) & 0x3FFF)) as u16,
        (duration.as_nanos() >> 76) as u64 | (std::process::id() as u64) << 32,
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use crate::api::core::Pod;

    fn create_pod_attributes(name: &str, namespace: &str, operation: Operation) -> AttributesRecord {
        let pod = Pod::new(name, namespace);
        AttributesRecord::new(
            name,
            namespace,
            GroupVersionResource::new("", "v1", "pods"),
            "",
            operation,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        )
    }

    fn create_dry_run_attributes(name: &str, namespace: &str) -> AttributesRecord {
        let pod = Pod::new(name, namespace);
        AttributesRecord::new(
            name,
            namespace,
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            true,
        )
    }

    #[test]
    fn test_plugin_handles_operations() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(plugin.handles(Operation::Delete));
        assert!(plugin.handles(Operation::Connect));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_failure_policy() {
        assert_eq!(FailurePolicy::Fail.as_str(), "Fail");
        assert_eq!(FailurePolicy::Ignore.as_str(), "Ignore");
        assert_eq!(FailurePolicy::from_str("Fail"), FailurePolicy::Fail);
        assert_eq!(FailurePolicy::from_str("Ignore"), FailurePolicy::Ignore);
        assert_eq!(FailurePolicy::from_str("unknown"), FailurePolicy::Fail);
    }

    #[test]
    fn test_side_effect_class() {
        assert!(SideEffectClass::None.supports_dry_run());
        assert!(SideEffectClass::NoneOnDryRun.supports_dry_run());
        assert!(!SideEffectClass::Some.supports_dry_run());
        assert!(!SideEffectClass::Unknown.supports_dry_run());
    }

    #[test]
    fn test_rule_with_operations_matches() {
        let rule = RuleWithOperations::new(
            vec![OperationType::Create, OperationType::Update],
            vec!["".to_string()],
            vec!["v1".to_string()],
            vec!["pods".to_string()],
        );

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        assert!(rule.matches(&attrs));

        let attrs = create_pod_attributes("test", "default", Operation::Update);
        assert!(rule.matches(&attrs));

        let attrs = create_pod_attributes("test", "default", Operation::Delete);
        assert!(!rule.matches(&attrs));
    }

    #[test]
    fn test_rule_with_wildcard_operations() {
        let rule = RuleWithOperations::new(
            vec![OperationType::All],
            vec!["*".to_string()],
            vec!["*".to_string()],
            vec!["*".to_string()],
        );

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        assert!(rule.matches(&attrs));

        let attrs = create_pod_attributes("test", "default", Operation::Delete);
        assert!(rule.matches(&attrs));
    }

    #[test]
    fn test_label_selector_matches() {
        let mut match_labels = HashMap::new();
        match_labels.insert("env".to_string(), "prod".to_string());

        let selector = LabelSelector {
            match_labels,
            match_expressions: vec![],
        };

        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        assert!(selector.matches(&labels));

        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "dev".to_string());
        assert!(!selector.matches(&labels));

        let labels = HashMap::new();
        assert!(!selector.matches(&labels));
    }

    #[test]
    fn test_label_selector_expressions() {
        let selector = LabelSelector {
            match_labels: HashMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "tier".to_string(),
                operator: "In".to_string(),
                values: vec!["frontend".to_string(), "backend".to_string()],
            }],
        };

        let mut labels = HashMap::new();
        labels.insert("tier".to_string(), "frontend".to_string());
        assert!(selector.matches(&labels));

        let mut labels = HashMap::new();
        labels.insert("tier".to_string(), "database".to_string());
        assert!(!selector.matches(&labels));
    }

    #[test]
    fn test_validating_webhook_should_call() {
        let webhook = ValidatingWebhook::with_rules(
            "test-webhook",
            vec![RuleWithOperations::new(
                vec![OperationType::Create],
                vec!["".to_string()],
                vec!["v1".to_string()],
                vec!["pods".to_string()],
            )],
        );

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        assert!(webhook.should_call(&attrs, None));

        let attrs = create_pod_attributes("test", "default", Operation::Delete);
        assert!(!webhook.should_call(&attrs, None));
    }

    #[test]
    fn test_validating_webhook_namespace_selector() {
        let mut ns_selector_labels = HashMap::new();
        ns_selector_labels.insert("env".to_string(), "prod".to_string());

        let mut webhook = ValidatingWebhook::with_rules(
            "test-webhook",
            vec![RuleWithOperations::new(
                vec![OperationType::Create],
                vec!["".to_string()],
                vec!["v1".to_string()],
                vec!["pods".to_string()],
            )],
        );
        webhook.namespace_selector = Some(LabelSelector {
            match_labels: ns_selector_labels,
            match_expressions: vec![],
        });

        let attrs = create_pod_attributes("test", "default", Operation::Create);

        // Without namespace labels - webhook should still be called if namespace_selector exists
        // but no labels are provided (the selector check passes when labels are None)
        assert!(webhook.should_call(&attrs, None));

        // With matching namespace labels
        let mut ns_labels = HashMap::new();
        ns_labels.insert("env".to_string(), "prod".to_string());
        assert!(webhook.should_call(&attrs, Some(&ns_labels)));

        // With non-matching namespace labels
        let mut ns_labels = HashMap::new();
        ns_labels.insert("env".to_string(), "dev".to_string());
        assert!(!webhook.should_call(&attrs, Some(&ns_labels)));
    }

    #[test]
    fn test_admission_request_from_attributes() {
        let attrs = create_pod_attributes("test-pod", "default", Operation::Create);
        let request = AdmissionRequest::from_attributes("test-uid", &attrs);

        assert_eq!(request.uid, "test-uid");
        assert_eq!(request.name, "test-pod");
        assert_eq!(request.namespace, "default");
        assert_eq!(request.operation, "CREATE");
        assert!(!request.dry_run);
    }

    #[test]
    fn test_admission_response() {
        let allowed = AdmissionResponse::allowed("test-uid");
        assert!(allowed.allowed);
        assert!(allowed.status.is_none());

        let denied = AdmissionResponse::denied("test-uid", "not allowed");
        assert!(!denied.allowed);
        assert_eq!(denied.status.as_ref().unwrap().code, 403);
        assert_eq!(denied.status.as_ref().unwrap().message, "not allowed");
    }

    #[test]
    fn test_mock_webhook_caller() {
        let caller = MockWebhookCaller::new();
        caller.set_allowed("webhook1");
        caller.set_denied("webhook2", "denied");

        let webhook1 = ValidatingWebhook::new("webhook1");
        let request = AdmissionRequest {
            uid: "test".to_string(),
            kind: GroupVersionKind::new("", "v1", "Pod"),
            resource: GroupVersionResource::new("", "v1", "pods"),
            sub_resource: String::new(),
            name: "test".to_string(),
            namespace: "default".to_string(),
            operation: "CREATE".to_string(),
            dry_run: false,
        };

        let response = caller.call(&webhook1, &request).unwrap();
        assert!(response.allowed);

        let webhook2 = ValidatingWebhook::new("webhook2");
        let response = caller.call(&webhook2, &request).unwrap();
        assert!(!response.allowed);
    }

    #[test]
    fn test_dispatcher_no_matching_webhooks() {
        let caller = Arc::new(MockWebhookCaller::new());
        let dispatcher = ValidatingDispatcher::new(caller);

        let webhooks = vec![ValidatingWebhook::with_rules(
            "test-webhook",
            vec![RuleWithOperations::new(
                vec![OperationType::Delete],
                vec!["".to_string()],
                vec!["v1".to_string()],
                vec!["pods".to_string()],
            )],
        )];

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        let result = dispatcher.dispatch(&attrs, &webhooks, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dispatcher_webhook_allows() {
        let caller = Arc::new(MockWebhookCaller::new());
        caller.set_allowed("test-webhook");

        let dispatcher = ValidatingDispatcher::new(caller);

        let webhooks = vec![ValidatingWebhook::with_rules(
            "test-webhook",
            vec![RuleWithOperations::new(
                vec![OperationType::Create],
                vec!["".to_string()],
                vec!["v1".to_string()],
                vec!["pods".to_string()],
            )],
        )];

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        let result = dispatcher.dispatch(&attrs, &webhooks, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dispatcher_webhook_denies() {
        let caller = Arc::new(MockWebhookCaller::new());
        caller.set_denied("test-webhook", "pod not allowed");

        let dispatcher = ValidatingDispatcher::new(caller);

        let webhooks = vec![ValidatingWebhook::with_rules(
            "test-webhook",
            vec![RuleWithOperations::new(
                vec![OperationType::Create],
                vec!["".to_string()],
                vec!["v1".to_string()],
                vec!["pods".to_string()],
            )],
        )];

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        let result = dispatcher.dispatch(&attrs, &webhooks, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("pod not allowed"));
    }

    #[test]
    fn test_dispatcher_failure_policy_fail() {
        let caller = Arc::new(MockWebhookCaller::new());
        caller.set_call_error("test-webhook", "connection refused");

        let dispatcher = ValidatingDispatcher::new(caller);

        let mut webhook = ValidatingWebhook::with_rules(
            "test-webhook",
            vec![RuleWithOperations::new(
                vec![OperationType::Create],
                vec!["".to_string()],
                vec!["v1".to_string()],
                vec!["pods".to_string()],
            )],
        );
        webhook.failure_policy = FailurePolicy::Fail;

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        let result = dispatcher.dispatch(&attrs, &[webhook], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_dispatcher_failure_policy_ignore() {
        let caller = Arc::new(MockWebhookCaller::new());
        caller.set_call_error("test-webhook", "connection refused");

        let dispatcher = ValidatingDispatcher::new(caller);

        let mut webhook = ValidatingWebhook::with_rules(
            "test-webhook",
            vec![RuleWithOperations::new(
                vec![OperationType::Create],
                vec!["".to_string()],
                vec!["v1".to_string()],
                vec!["pods".to_string()],
            )],
        );
        webhook.failure_policy = FailurePolicy::Ignore;

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        let result = dispatcher.dispatch(&attrs, &[webhook], None);
        assert!(result.is_ok()); // Failed open
    }

    #[test]
    fn test_dispatcher_dry_run_not_supported() {
        let caller = Arc::new(MockWebhookCaller::new());
        caller.set_allowed("test-webhook");

        let dispatcher = ValidatingDispatcher::new(caller);

        let mut webhook = ValidatingWebhook::with_rules(
            "test-webhook",
            vec![RuleWithOperations::new(
                vec![OperationType::Create],
                vec!["".to_string()],
                vec!["v1".to_string()],
                vec!["pods".to_string()],
            )],
        );
        webhook.side_effects = SideEffectClass::Some;

        let attrs = create_dry_run_attributes("test", "default");
        let result = dispatcher.dispatch(&attrs, &[webhook], None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("dry run"));
    }

    #[test]
    fn test_dispatcher_dry_run_supported() {
        let caller = Arc::new(MockWebhookCaller::new());
        caller.set_allowed("test-webhook");

        let dispatcher = ValidatingDispatcher::new(caller);

        let mut webhook = ValidatingWebhook::with_rules(
            "test-webhook",
            vec![RuleWithOperations::new(
                vec![OperationType::Create],
                vec!["".to_string()],
                vec!["v1".to_string()],
                vec!["pods".to_string()],
            )],
        );
        webhook.side_effects = SideEffectClass::None;

        let attrs = create_dry_run_attributes("test", "default");
        let result = dispatcher.dispatch(&attrs, &[webhook], None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dispatcher_multiple_webhooks() {
        let caller = Arc::new(MockWebhookCaller::new());
        caller.set_allowed("webhook1");
        caller.set_allowed("webhook2");
        caller.set_denied("webhook3", "denied by webhook3");

        let dispatcher = ValidatingDispatcher::new(caller);

        let webhooks = vec![
            ValidatingWebhook::with_rules(
                "webhook1",
                vec![RuleWithOperations::new(
                    vec![OperationType::Create],
                    vec!["".to_string()],
                    vec!["v1".to_string()],
                    vec!["pods".to_string()],
                )],
            ),
            ValidatingWebhook::with_rules(
                "webhook2",
                vec![RuleWithOperations::new(
                    vec![OperationType::Create],
                    vec!["".to_string()],
                    vec!["v1".to_string()],
                    vec!["pods".to_string()],
                )],
            ),
            ValidatingWebhook::with_rules(
                "webhook3",
                vec![RuleWithOperations::new(
                    vec![OperationType::Create],
                    vec!["".to_string()],
                    vec!["v1".to_string()],
                    vec!["pods".to_string()],
                )],
            ),
        ];

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        let result = dispatcher.dispatch(&attrs, &webhooks, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("webhook3"));
    }

    #[test]
    fn test_in_memory_webhook_source() {
        let source = InMemoryWebhookSource::new();

        let config = ValidatingWebhookConfiguration::with_webhooks(
            "test-config",
            vec![
                ValidatingWebhook::new("webhook1"),
                ValidatingWebhook::new("webhook2"),
            ],
        );
        source.add_configuration(config);

        let webhooks = source.get_webhooks();
        assert_eq!(webhooks.len(), 2);
        assert_eq!(webhooks[0].name, "webhook1");
        assert_eq!(webhooks[1].name, "webhook2");
    }

    #[test]
    fn test_in_memory_namespace_label_source() {
        let source = InMemoryNamespaceLabelSource::new();

        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        source.set_labels("default", labels);

        let retrieved = source.get_namespace_labels("default");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().get("env"), Some(&"prod".to_string()));

        let not_found = source.get_namespace_labels("other");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_plugin_validate_no_config() {
        let plugin = Plugin::new();
        let attrs = create_pod_attributes("test", "default", Operation::Create);
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_validate_with_config() {
        let caller = Arc::new(MockWebhookCaller::new());
        caller.set_allowed("test-webhook");

        let webhook_source = Arc::new(InMemoryWebhookSource::new());
        webhook_source.add_configuration(ValidatingWebhookConfiguration::with_webhooks(
            "test-config",
            vec![ValidatingWebhook::with_rules(
                "test-webhook",
                vec![RuleWithOperations::new(
                    vec![OperationType::Create],
                    vec!["".to_string()],
                    vec!["v1".to_string()],
                    vec!["pods".to_string()],
                )],
            )],
        ));

        let ns_source = Arc::new(InMemoryNamespaceLabelSource::new());

        let plugin = Plugin::with_config(caller, webhook_source, ns_source);

        let attrs = create_pod_attributes("test", "default", Operation::Create);
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_exempt_resources() {
        let caller = Arc::new(MockWebhookCaller::new());
        caller.set_denied("test-webhook", "should not be called");

        let webhook_source = Arc::new(InMemoryWebhookSource::new());
        webhook_source.add_configuration(ValidatingWebhookConfiguration::with_webhooks(
            "test-config",
            vec![ValidatingWebhook::with_rules(
                "test-webhook",
                vec![RuleWithOperations::new(
                    vec![OperationType::All],
                    vec!["*".to_string()],
                    vec!["*".to_string()],
                    vec!["*".to_string()],
                )],
            )],
        ));

        let ns_source = Arc::new(InMemoryNamespaceLabelSource::new());
        let plugin = Plugin::with_config(caller, webhook_source, ns_source);

        // Create attributes for ValidatingWebhookConfiguration
        let attrs = AttributesRecord::new(
            "test-config",
            "",
            GroupVersionResource::new("admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations"),
            "",
            Operation::Create,
            None,
            None,
            GroupVersionKind::new("admissionregistration.k8s.io", "v1", "ValidatingWebhookConfiguration"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok()); // Exempt, so allowed even with deny webhook
    }

    #[test]
    fn test_service_reference_get_url() {
        let service = ServiceReference {
            namespace: "kube-system".to_string(),
            name: "my-webhook".to_string(),
            path: Some("/validate".to_string()),
            port: Some(8443),
        };

        assert_eq!(
            service.get_url(),
            "https://my-webhook.kube-system.svc:8443/validate"
        );

        let service_default_port = ServiceReference {
            namespace: "default".to_string(),
            name: "webhook".to_string(),
            path: None,
            port: None,
        };

        assert_eq!(
            service_default_port.get_url(),
            "https://webhook.default.svc:443"
        );
    }

    #[test]
    fn test_webhook_timeout() {
        let mut webhook = ValidatingWebhook::new("test");
        webhook.timeout_seconds = 30;

        assert_eq!(webhook.get_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn test_match_policy() {
        assert_eq!(MatchPolicy::Exact.as_str(), "Exact");
        assert_eq!(MatchPolicy::Equivalent.as_str(), "Equivalent");
        assert_eq!(MatchPolicy::from_str("Exact"), MatchPolicy::Exact);
        assert_eq!(MatchPolicy::from_str("Equivalent"), MatchPolicy::Equivalent);
    }

    #[test]
    fn test_operation_type_matches() {
        assert!(OperationType::All.matches(Operation::Create));
        assert!(OperationType::All.matches(Operation::Delete));
        assert!(OperationType::Create.matches(Operation::Create));
        assert!(!OperationType::Create.matches(Operation::Delete));
    }

    #[test]
    fn test_webhook_error_display() {
        let call_err = WebhookError::CallingWebhook {
            webhook_name: "my-webhook".to_string(),
            reason: "timeout".to_string(),
            status_code: 500,
        };
        assert!(call_err.to_string().contains("my-webhook"));
        assert!(call_err.to_string().contains("timeout"));

        let rejection_err = WebhookError::Rejection {
            webhook_name: "my-webhook".to_string(),
            status: ResponseStatus {
                code: 403,
                message: "not allowed".to_string(),
                reason: "Forbidden".to_string(),
            },
        };
        assert!(rejection_err.to_string().contains("my-webhook"));
        assert!(rejection_err.to_string().contains("not allowed"));
    }

    #[test]
    fn test_label_selector_empty() {
        let selector = LabelSelector::default();
        assert!(selector.is_empty());

        let labels = HashMap::new();
        assert!(selector.matches(&labels));

        let mut labels = HashMap::new();
        labels.insert("any".to_string(), "value".to_string());
        assert!(selector.matches(&labels));
    }

    #[test]
    fn test_rule_subresource_matching() {
        let rule = RuleWithOperations::new(
            vec![OperationType::Update],
            vec!["".to_string()],
            vec!["v1".to_string()],
            vec!["pods/status".to_string()],
        );

        // Create attributes for pods/status subresource
        let pod = Pod::new("test", "default");
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "status",
            Operation::Update,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        assert!(rule.matches(&attrs));

        // Should not match main resource
        let attrs_main = create_pod_attributes("test", "default", Operation::Update);
        assert!(!rule.matches(&attrs_main));
    }
}
