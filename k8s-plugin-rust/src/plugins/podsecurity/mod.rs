// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! PodSecurity admission controller.
//!
//! This admission controller enforces Pod Security Standards (PSS) at the namespace level.
//! It supports three security levels: Privileged, Baseline, and Restricted.
//! Policies are configured via namespace labels.

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use crate::api::core::Pod;
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

pub const PLUGIN_NAME: &str = "PodSecurity";

// Namespace label keys for pod security
pub const LABEL_ENFORCE: &str = "pod-security.kubernetes.io/enforce";
pub const LABEL_ENFORCE_VERSION: &str = "pod-security.kubernetes.io/enforce-version";
pub const LABEL_AUDIT: &str = "pod-security.kubernetes.io/audit";
pub const LABEL_AUDIT_VERSION: &str = "pod-security.kubernetes.io/audit-version";
pub const LABEL_WARN: &str = "pod-security.kubernetes.io/warn";
pub const LABEL_WARN_VERSION: &str = "pod-security.kubernetes.io/warn-version";

pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Pod Security Level defines the degree of isolation required for pods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Level {
    /// Privileged - Unrestricted policy, providing the widest possible level of permissions.
    #[default]
    Privileged,
    /// Baseline - Minimally restrictive policy which prevents known privilege escalations.
    Baseline,
    /// Restricted - Heavily restricted policy, following current Pod hardening best practices.
    Restricted,
}

impl Level {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "privileged" => Some(Level::Privileged),
            "baseline" => Some(Level::Baseline),
            "restricted" => Some(Level::Restricted),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Privileged => "privileged",
            Level::Baseline => "baseline",
            Level::Restricted => "restricted",
        }
    }
}

/// Policy mode determines how violations are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Enforce - Violations will cause the pod to be rejected.
    Enforce,
    /// Audit - Violations are recorded in audit logs but allowed.
    Audit,
    /// Warn - Violations trigger a user-facing warning but are allowed.
    Warn,
}

/// Namespace policy configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct NamespacePolicy {
    pub enforce: Level,
    pub enforce_version: String,
    pub audit: Level,
    pub audit_version: String,
    pub warn: Level,
    pub warn_version: String,
}

impl Default for NamespacePolicy {
    fn default() -> Self {
        Self {
            enforce: Level::Privileged,
            enforce_version: "latest".to_string(),
            audit: Level::Privileged,
            audit_version: "latest".to_string(),
            warn: Level::Privileged,
            warn_version: "latest".to_string(),
        }
    }
}

impl NamespacePolicy {
    /// Parse policy from namespace labels.
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
        let mut policy = Self::default();

        if let Some(level) = labels.get(LABEL_ENFORCE).and_then(|s| Level::from_str(s)) {
            policy.enforce = level;
        }
        if let Some(version) = labels.get(LABEL_ENFORCE_VERSION) {
            policy.enforce_version = version.clone();
        }
        if let Some(level) = labels.get(LABEL_AUDIT).and_then(|s| Level::from_str(s)) {
            policy.audit = level;
        }
        if let Some(version) = labels.get(LABEL_AUDIT_VERSION) {
            policy.audit_version = version.clone();
        }
        if let Some(level) = labels.get(LABEL_WARN).and_then(|s| Level::from_str(s)) {
            policy.warn = level;
        }
        if let Some(version) = labels.get(LABEL_WARN_VERSION) {
            policy.warn_version = version.clone();
        }

        policy
    }
}

/// Check result for a single security check.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub allowed: bool,
    pub reason: String,
}

impl CheckResult {
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            reason: String::new(),
        }
    }

    pub fn forbidden(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.to_string(),
        }
    }
}

/// Security checks for different levels.
pub struct SecurityChecker;

impl SecurityChecker {
    /// Check if a pod meets the requirements for a given security level.
    pub fn check_pod(pod: &Pod, level: Level) -> Vec<CheckResult> {
        match level {
            Level::Privileged => vec![CheckResult::allowed()],
            Level::Baseline => Self::check_baseline(pod),
            Level::Restricted => Self::check_restricted(pod),
        }
    }

    /// Baseline level checks.
    fn check_baseline(pod: &Pod) -> Vec<CheckResult> {
        let mut results = Vec::new();

        // Check hostNetwork
        if pod.spec.host_network.unwrap_or(false) {
            results.push(CheckResult::forbidden("hostNetwork is not allowed"));
        }

        // Check hostPID
        if pod.spec.host_pid.unwrap_or(false) {
            results.push(CheckResult::forbidden("hostPID is not allowed"));
        }

        // Check hostIPC
        if pod.spec.host_ipc.unwrap_or(false) {
            results.push(CheckResult::forbidden("hostIPC is not allowed"));
        }

        // Check privileged containers
        for container in &pod.spec.containers {
            if container.security_context.as_ref()
                .map(|sc| sc.privileged.unwrap_or(false))
                .unwrap_or(false)
            {
                results.push(CheckResult::forbidden(&format!(
                    "container {} must not set securityContext.privileged=true",
                    container.name
                )));
            }
        }

        if results.is_empty() {
            results.push(CheckResult::allowed());
        }

        results
    }

    /// Restricted level checks (includes baseline + additional restrictions).
    fn check_restricted(pod: &Pod) -> Vec<CheckResult> {
        let mut results = Self::check_baseline(pod);

        // Remove the "allowed" result if present, we'll add it at the end if no violations
        results.retain(|r| !r.allowed);

        // Check runAsNonRoot
        let pod_run_as_non_root = pod.spec.security_context.as_ref()
            .and_then(|sc| sc.run_as_non_root);

        for container in &pod.spec.containers {
            let container_run_as_non_root = container.security_context.as_ref()
                .and_then(|sc| sc.run_as_non_root);

            if container_run_as_non_root != Some(true) && pod_run_as_non_root != Some(true) {
                results.push(CheckResult::forbidden(&format!(
                    "container {} must set securityContext.runAsNonRoot=true",
                    container.name
                )));
            }

            // Check allowPrivilegeEscalation
            let allow_priv_esc = container.security_context.as_ref()
                .and_then(|sc| sc.allow_privilege_escalation);
            if allow_priv_esc != Some(false) {
                results.push(CheckResult::forbidden(&format!(
                    "container {} must set securityContext.allowPrivilegeEscalation=false",
                    container.name
                )));
            }

            // Check capabilities - must drop ALL
            let drops_all = container.security_context.as_ref()
                .and_then(|sc| sc.capabilities.as_ref())
                .map(|caps| caps.drop.iter().any(|c| c.to_uppercase() == "ALL"))
                .unwrap_or(false);
            if !drops_all {
                results.push(CheckResult::forbidden(&format!(
                    "container {} must set securityContext.capabilities.drop=[\"ALL\"]",
                    container.name
                )));
            }
        }

        if results.is_empty() {
            results.push(CheckResult::allowed());
        }

        results
    }
}

/// Trait for looking up namespace labels.
pub trait NamespaceLabelSource: Send + Sync {
    fn get_labels(&self, namespace: &str) -> Option<HashMap<String, String>>;
}

/// In-memory implementation for testing.
pub struct InMemoryNamespaceLabelSource {
    namespaces: RwLock<HashMap<String, HashMap<String, String>>>,
}

impl InMemoryNamespaceLabelSource {
    pub fn new() -> Self {
        Self {
            namespaces: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_namespace(&self, name: &str, labels: HashMap<String, String>) {
        let mut ns = self.namespaces.write().unwrap();
        ns.insert(name.to_string(), labels);
    }
}

impl Default for InMemoryNamespaceLabelSource {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceLabelSource for InMemoryNamespaceLabelSource {
    fn get_labels(&self, namespace: &str) -> Option<HashMap<String, String>> {
        let ns = self.namespaces.read().unwrap();
        ns.get(namespace).cloned()
    }
}

pub struct Plugin {
    handler: Handler,
    namespace_source: Option<Arc<dyn NamespaceLabelSource>>,
    #[allow(dead_code)]
    ready: bool,
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            namespace_source: None,
            ready: false,
        }
    }

    pub fn with_namespace_source(source: Arc<dyn NamespaceLabelSource>) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            namespace_source: Some(source),
            ready: true,
        }
    }

    fn get_namespace_policy(&self, namespace: &str) -> NamespacePolicy {
        if let Some(ref source) = self.namespace_source {
            if let Some(labels) = source.get_labels(namespace) {
                return NamespacePolicy::from_labels(&labels);
            }
        }
        NamespacePolicy::default()
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
        let resource = attributes.get_resource();
        if resource.resource != "pods" {
            return Ok(());
        }

        // Ignore subresources
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        // Get the pod
        let pod = match attributes.get_object().and_then(|obj| obj.as_any().downcast_ref::<Pod>()) {
            Some(p) => p,
            None => return Ok(()),
        };

        // Get namespace policy
        let namespace = attributes.get_namespace();
        let policy = self.get_namespace_policy(&namespace);

        // Check against enforce level
        let results = SecurityChecker::check_pod(pod, policy.enforce);
        let violations: Vec<_> = results.iter().filter(|r| !r.allowed).collect();

        if !violations.is_empty() {
            let reasons: Vec<_> = violations.iter().map(|v| v.reason.as_str()).collect();
            return Err(AdmissionError::forbidden_msg(format!(
                "violates PodSecurity \"{}\": {}",
                policy.enforce.as_str(),
                reasons.join("; ")
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::core::{Container, PullPolicy, SecurityContext, Capabilities, PodSecurityContext};

    fn create_pod(name: &str) -> Pod {
        let mut pod = Pod::new(name, "default");
        pod.spec.containers = vec![Container::new("test", "nginx")];
        pod
    }

    fn create_privileged_pod(name: &str) -> Pod {
        let mut pod = create_pod(name);
        pod.spec.containers = vec![Container {
            name: "test".to_string(),
            image: "nginx".to_string(),
            image_pull_policy: PullPolicy::IfNotPresent,
            resources: Default::default(),
            security_context: Some(SecurityContext {
                privileged: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }];
        pod
    }

    fn create_restricted_pod(name: &str) -> Pod {
        let mut pod = create_pod(name);
        pod.spec.security_context = Some(PodSecurityContext {
            run_as_non_root: Some(true),
            ..Default::default()
        });
        pod.spec.containers = vec![Container {
            name: "test".to_string(),
            image: "nginx".to_string(),
            image_pull_policy: PullPolicy::IfNotPresent,
            resources: Default::default(),
            security_context: Some(SecurityContext {
                run_as_non_root: Some(true),
                allow_privilege_escalation: Some(false),
                capabilities: Some(Capabilities {
                    add: vec![],
                    drop: vec!["ALL".to_string()],
                }),
                ..Default::default()
            }),
            ..Default::default()
        }];
        pod
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_level_from_str() {
        assert_eq!(Level::from_str("privileged"), Some(Level::Privileged));
        assert_eq!(Level::from_str("baseline"), Some(Level::Baseline));
        assert_eq!(Level::from_str("restricted"), Some(Level::Restricted));
        assert_eq!(Level::from_str("PRIVILEGED"), Some(Level::Privileged));
        assert_eq!(Level::from_str("invalid"), None);
    }

    #[test]
    fn test_level_as_str() {
        assert_eq!(Level::Privileged.as_str(), "privileged");
        assert_eq!(Level::Baseline.as_str(), "baseline");
        assert_eq!(Level::Restricted.as_str(), "restricted");
    }

    #[test]
    fn test_namespace_policy_default() {
        let policy = NamespacePolicy::default();
        assert_eq!(policy.enforce, Level::Privileged);
        assert_eq!(policy.audit, Level::Privileged);
        assert_eq!(policy.warn, Level::Privileged);
    }

    #[test]
    fn test_namespace_policy_from_labels() {
        let mut labels = HashMap::new();
        labels.insert(LABEL_ENFORCE.to_string(), "restricted".to_string());
        labels.insert(LABEL_ENFORCE_VERSION.to_string(), "v1.25".to_string());
        labels.insert(LABEL_AUDIT.to_string(), "baseline".to_string());
        labels.insert(LABEL_WARN.to_string(), "baseline".to_string());

        let policy = NamespacePolicy::from_labels(&labels);
        assert_eq!(policy.enforce, Level::Restricted);
        assert_eq!(policy.enforce_version, "v1.25");
        assert_eq!(policy.audit, Level::Baseline);
        assert_eq!(policy.warn, Level::Baseline);
    }

    #[test]
    fn test_check_privileged_level_allows_all() {
        let pod = create_privileged_pod("test");
        let results = SecurityChecker::check_pod(&pod, Level::Privileged);
        assert!(results.iter().all(|r| r.allowed));
    }

    #[test]
    fn test_check_baseline_rejects_privileged_container() {
        let pod = create_privileged_pod("test");
        let results = SecurityChecker::check_pod(&pod, Level::Baseline);
        assert!(results.iter().any(|r| !r.allowed));
        assert!(results.iter().any(|r| r.reason.contains("privileged")));
    }

    #[test]
    fn test_check_baseline_rejects_host_network() {
        let mut pod = create_pod("test");
        pod.spec.host_network = Some(true);
        let results = SecurityChecker::check_pod(&pod, Level::Baseline);
        assert!(results.iter().any(|r| !r.allowed));
        assert!(results.iter().any(|r| r.reason.contains("hostNetwork")));
    }

    #[test]
    fn test_check_baseline_rejects_host_pid() {
        let mut pod = create_pod("test");
        pod.spec.host_pid = Some(true);
        let results = SecurityChecker::check_pod(&pod, Level::Baseline);
        assert!(results.iter().any(|r| !r.allowed));
        assert!(results.iter().any(|r| r.reason.contains("hostPID")));
    }

    #[test]
    fn test_check_baseline_rejects_host_ipc() {
        let mut pod = create_pod("test");
        pod.spec.host_ipc = Some(true);
        let results = SecurityChecker::check_pod(&pod, Level::Baseline);
        assert!(results.iter().any(|r| !r.allowed));
        assert!(results.iter().any(|r| r.reason.contains("hostIPC")));
    }

    #[test]
    fn test_check_baseline_allows_unprivileged_pod() {
        let pod = create_pod("test");
        let results = SecurityChecker::check_pod(&pod, Level::Baseline);
        assert!(results.iter().all(|r| r.allowed));
    }

    #[test]
    fn test_check_restricted_requires_run_as_non_root() {
        let pod = create_pod("test");
        let results = SecurityChecker::check_pod(&pod, Level::Restricted);
        assert!(results.iter().any(|r| r.reason.contains("runAsNonRoot")));
    }

    #[test]
    fn test_check_restricted_requires_drop_all_capabilities() {
        let mut pod = create_pod("test");
        pod.spec.security_context = Some(PodSecurityContext {
            run_as_non_root: Some(true),
            ..Default::default()
        });
        pod.spec.containers = vec![Container {
            name: "test".to_string(),
            image: "nginx".to_string(),
            image_pull_policy: PullPolicy::IfNotPresent,
            resources: Default::default(),
            security_context: Some(SecurityContext {
                run_as_non_root: Some(true),
                allow_privilege_escalation: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        }];
        let results = SecurityChecker::check_pod(&pod, Level::Restricted);
        assert!(results.iter().any(|r| r.reason.contains("capabilities.drop")));
    }

    #[test]
    fn test_check_restricted_allows_compliant_pod() {
        let pod = create_restricted_pod("test");
        let results = SecurityChecker::check_pod(&pod, Level::Restricted);
        assert!(results.iter().all(|r| r.allowed));
    }

    #[test]
    fn test_in_memory_namespace_source() {
        let source = InMemoryNamespaceLabelSource::new();
        let mut labels = HashMap::new();
        labels.insert(LABEL_ENFORCE.to_string(), "restricted".to_string());
        source.add_namespace("secure-ns", labels);

        let retrieved = source.get_labels("secure-ns");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().get(LABEL_ENFORCE), Some(&"restricted".to_string()));

        assert!(source.get_labels("nonexistent").is_none());
    }

    #[test]
    fn test_plugin_with_namespace_source() {
        let source = Arc::new(InMemoryNamespaceLabelSource::new());
        let mut labels = HashMap::new();
        labels.insert(LABEL_ENFORCE.to_string(), "baseline".to_string());
        source.add_namespace("test-ns", labels);

        let plugin = Plugin::with_namespace_source(source);
        let policy = plugin.get_namespace_policy("test-ns");
        assert_eq!(policy.enforce, Level::Baseline);
    }

    #[test]
    fn test_plugin_default_policy_for_unknown_namespace() {
        let source = Arc::new(InMemoryNamespaceLabelSource::new());
        let plugin = Plugin::with_namespace_source(source);
        let policy = plugin.get_namespace_policy("unknown");
        assert_eq!(policy.enforce, Level::Privileged);
    }
}
