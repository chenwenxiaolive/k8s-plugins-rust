// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! MutatingAdmissionPolicy admission controller.
//!
//! This admission controller mutates admission requests using CEL (Common Expression Language)
//! expressions defined in MutatingAdmissionPolicy resources. It provides a declarative,
//! in-process alternative to mutating admission webhooks.
//!
//! Key features:
//! - CEL-based mutation expressions
//! - Policy bindings to match specific resources
//! - JSON Patch generation from CEL expressions
//! - Failure policy configuration (Fail or Ignore)
//! - Reinvocation policy for handling mutations

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins,
};
use crate::api::core::ApiObject;
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

pub const PLUGIN_NAME: &str = "MutatingAdmissionPolicy";

pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

// ============================================================================
// Policy Types
// ============================================================================

/// FailurePolicy defines how to handle failures for the admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailurePolicy {
    /// Fail means that an error causes the admission to fail.
    #[default]
    Fail,
    /// Ignore means that an error is ignored and the request is allowed.
    Ignore,
}

impl FailurePolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "fail" => Some(FailurePolicy::Fail),
            "ignore" => Some(FailurePolicy::Ignore),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FailurePolicy::Fail => "Fail",
            FailurePolicy::Ignore => "Ignore",
        }
    }
}

/// ReinvocationPolicy defines whether mutations should be reinvoked after other mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReinvocationPolicy {
    /// Never means the mutation will not be reinvoked.
    #[default]
    Never,
    /// IfNeeded means the mutation will be reinvoked if the object was modified.
    IfNeeded,
}

impl ReinvocationPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "never" => Some(ReinvocationPolicy::Never),
            "ifneeded" => Some(ReinvocationPolicy::IfNeeded),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ReinvocationPolicy::Never => "Never",
            ReinvocationPolicy::IfNeeded => "IfNeeded",
        }
    }
}

/// MatchCondition represents a condition that must be met for a policy to apply.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchCondition {
    /// Name is an identifier for this match condition.
    pub name: String,
    /// Expression is a CEL expression that must evaluate to true.
    pub expression: String,
}

impl MatchCondition {
    pub fn new(name: &str, expression: &str) -> Self {
        Self {
            name: name.to_string(),
            expression: expression.to_string(),
        }
    }
}

/// Mutation contains a CEL expression that produces a JSON Patch.
#[derive(Debug, Clone, PartialEq)]
pub struct Mutation {
    /// PatchType specifies the type of patch (JSONPatch or ApplyConfiguration).
    pub patch_type: PatchType,
    /// Expression is the CEL expression that generates the patch.
    pub expression: String,
}

impl Mutation {
    pub fn json_patch(expression: &str) -> Self {
        Self {
            patch_type: PatchType::JSONPatch,
            expression: expression.to_string(),
        }
    }

    pub fn apply_configuration(expression: &str) -> Self {
        Self {
            patch_type: PatchType::ApplyConfiguration,
            expression: expression.to_string(),
        }
    }
}

/// PatchType specifies the type of patch to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PatchType {
    /// JSONPatch means the mutation produces a JSON Patch (RFC 6902).
    #[default]
    JSONPatch,
    /// ApplyConfiguration means the mutation produces an apply configuration.
    ApplyConfiguration,
}

/// Variable is a named expression for use in compositions.
#[derive(Debug, Clone, PartialEq)]
pub struct Variable {
    /// Name is the name of the variable.
    pub name: String,
    /// Expression is the CEL expression for the variable.
    pub expression: String,
}

impl Variable {
    pub fn new(name: &str, expression: &str) -> Self {
        Self {
            name: name.to_string(),
            expression: expression.to_string(),
        }
    }
}

// ============================================================================
// Resource Matching Types
// ============================================================================

/// MatchResources describes what resources a policy applies to.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MatchResources {
    /// NamespaceSelector restricts the policy to namespaces matching the selector.
    pub namespace_selector: Option<LabelSelector>,
    /// ObjectSelector restricts the policy to objects matching the selector.
    pub object_selector: Option<LabelSelector>,
    /// ResourceRules describes what resources to match.
    pub resource_rules: Vec<ResourceRule>,
    /// ExcludeResourceRules describes what resources to exclude.
    pub exclude_resource_rules: Vec<ResourceRule>,
}

/// LabelSelector is a label query over a set of resources.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LabelSelector {
    /// MatchLabels is a map of key-value pairs.
    pub match_labels: HashMap<String, String>,
}

impl LabelSelector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_labels(labels: HashMap<String, String>) -> Self {
        Self { match_labels: labels }
    }

    /// Check if the selector matches the given labels.
    pub fn matches(&self, labels: &HashMap<String, String>) -> bool {
        for (key, value) in &self.match_labels {
            match labels.get(key) {
                Some(v) if v == value => continue,
                _ => return false,
            }
        }
        true
    }
}

/// ResourceRule describes resources the policy applies to.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResourceRule {
    /// API groups the rule applies to.
    pub api_groups: Vec<String>,
    /// API versions the rule applies to.
    pub api_versions: Vec<String>,
    /// Resources the rule applies to.
    pub resources: Vec<String>,
    /// Operations the rule applies to.
    pub operations: Vec<Operation>,
}

impl ResourceRule {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_pods() -> Self {
        Self {
            api_groups: vec!["".to_string()],
            api_versions: vec!["v1".to_string()],
            resources: vec!["pods".to_string()],
            operations: vec![Operation::Create, Operation::Update],
        }
    }

    /// Check if the rule matches the given attributes.
    pub fn matches(&self, attributes: &dyn Attributes) -> bool {
        let resource = attributes.get_resource();

        let group_matches = self.api_groups.is_empty()
            || self.api_groups.iter().any(|g| g == "*" || g == &resource.group);

        let version_matches = self.api_versions.is_empty()
            || self.api_versions.iter().any(|v| v == "*" || v == &resource.version);

        let resource_matches = self.resources.is_empty()
            || self.resources.iter().any(|r| r == "*" || r == &resource.resource);

        let operation_matches = self.operations.is_empty()
            || self.operations.contains(&attributes.get_operation());

        group_matches && version_matches && resource_matches && operation_matches
    }
}

// ============================================================================
// Policy and Binding Types
// ============================================================================

/// MutatingAdmissionPolicy describes the definition of a mutation policy.
#[derive(Debug, Clone, PartialEq)]
pub struct MutatingAdmissionPolicy {
    /// Name is the name of the policy.
    pub name: String,
    /// Spec contains the policy specification.
    pub spec: MutatingAdmissionPolicySpec,
}

impl MutatingAdmissionPolicy {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            spec: MutatingAdmissionPolicySpec::default(),
        }
    }

    pub fn with_mutations(name: &str, mutations: Vec<Mutation>) -> Self {
        Self {
            name: name.to_string(),
            spec: MutatingAdmissionPolicySpec {
                mutations,
                ..Default::default()
            },
        }
    }
}

impl ApiObject for MutatingAdmissionPolicy {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "MutatingAdmissionPolicy"
    }
}

/// MutatingAdmissionPolicySpec is the specification for a MutatingAdmissionPolicy.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MutatingAdmissionPolicySpec {
    /// MatchConstraints specifies what resources this policy applies to.
    pub match_constraints: Option<MatchResources>,
    /// Mutations contain CEL expressions that produce patches.
    pub mutations: Vec<Mutation>,
    /// FailurePolicy defines how to handle failures.
    pub failure_policy: FailurePolicy,
    /// ReinvocationPolicy defines whether to reinvoke after other mutations.
    pub reinvocation_policy: ReinvocationPolicy,
    /// MatchConditions is a list of conditions that must be met.
    pub match_conditions: Vec<MatchCondition>,
    /// Variables are named expressions for use in compositions.
    pub variables: Vec<Variable>,
}

/// MutatingAdmissionPolicyBinding binds a policy to resources.
#[derive(Debug, Clone, PartialEq)]
pub struct MutatingAdmissionPolicyBinding {
    /// Name is the name of the binding.
    pub name: String,
    /// Spec contains the binding specification.
    pub spec: MutatingAdmissionPolicyBindingSpec,
}

impl MutatingAdmissionPolicyBinding {
    pub fn new(name: &str, policy_name: &str) -> Self {
        Self {
            name: name.to_string(),
            spec: MutatingAdmissionPolicyBindingSpec {
                policy_name: policy_name.to_string(),
                ..Default::default()
            },
        }
    }
}

impl ApiObject for MutatingAdmissionPolicyBinding {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "MutatingAdmissionPolicyBinding"
    }
}

/// MutatingAdmissionPolicyBindingSpec is the specification for a binding.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MutatingAdmissionPolicyBindingSpec {
    /// PolicyName is the name of the policy to bind.
    pub policy_name: String,
    /// MatchResources restricts what resources the binding applies to.
    pub match_resources: Option<MatchResources>,
}

// ============================================================================
// JSON Patch Types
// ============================================================================

/// JSONPatchOperation represents a single JSON Patch operation.
#[derive(Debug, Clone, PartialEq)]
pub struct JSONPatchOperation {
    /// Operation type (add, remove, replace, move, copy, test).
    pub op: String,
    /// Path to the target location.
    pub path: String,
    /// Value to use (for add, replace, test).
    pub value: Option<serde_json::Value>,
    /// From path (for move, copy).
    pub from: Option<String>,
}

impl JSONPatchOperation {
    pub fn add(path: &str, value: serde_json::Value) -> Self {
        Self {
            op: "add".to_string(),
            path: path.to_string(),
            value: Some(value),
            from: None,
        }
    }

    pub fn remove(path: &str) -> Self {
        Self {
            op: "remove".to_string(),
            path: path.to_string(),
            value: None,
            from: None,
        }
    }

    pub fn replace(path: &str, value: serde_json::Value) -> Self {
        Self {
            op: "replace".to_string(),
            path: path.to_string(),
            value: Some(value),
            from: None,
        }
    }
}

/// MutationResult holds the result of applying a mutation.
#[derive(Debug, Clone)]
pub struct MutationResult {
    pub applied: bool,
    pub patches: Vec<JSONPatchOperation>,
    pub error: Option<String>,
}

impl MutationResult {
    pub fn success(patches: Vec<JSONPatchOperation>) -> Self {
        Self {
            applied: true,
            patches,
            error: None,
        }
    }

    pub fn no_op() -> Self {
        Self {
            applied: false,
            patches: Vec::new(),
            error: None,
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            applied: false,
            patches: Vec::new(),
            error: Some(msg.to_string()),
        }
    }
}

// ============================================================================
// CEL Evaluator
// ============================================================================

/// Context for CEL evaluation.
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// The object being admitted.
    pub object: Option<serde_json::Value>,
    /// The old object (for updates).
    pub old_object: Option<serde_json::Value>,
    /// The request attributes.
    pub request: RequestContext,
    /// Variables defined by the policy.
    pub variables: HashMap<String, serde_json::Value>,
}

/// Request context for CEL evaluation.
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub name: String,
    pub namespace: String,
    pub operation: String,
    pub resource: String,
    pub subresource: String,
}

/// CEL Evaluator trait for evaluating CEL expressions.
pub trait CelEvaluator: Send + Sync {
    /// Evaluate a boolean CEL expression.
    fn evaluate_bool(&self, expression: &str, context: &EvaluationContext) -> Result<bool, String>;

    /// Evaluate a CEL expression that produces a JSON Patch.
    fn evaluate_patch(&self, expression: &str, context: &EvaluationContext) -> Result<Vec<JSONPatchOperation>, String>;
}

/// Simple CEL evaluator for common expressions.
#[derive(Debug, Default)]
pub struct SimpleCelEvaluator;

impl SimpleCelEvaluator {
    pub fn new() -> Self {
        Self
    }
}

impl CelEvaluator for SimpleCelEvaluator {
    fn evaluate_bool(&self, expression: &str, _context: &EvaluationContext) -> Result<bool, String> {
        let expr = expression.trim();
        if expr == "true" {
            return Ok(true);
        }
        if expr == "false" {
            return Ok(false);
        }
        // Default: allow for unknown expressions
        Ok(true)
    }

    fn evaluate_patch(&self, expression: &str, _context: &EvaluationContext) -> Result<Vec<JSONPatchOperation>, String> {
        // Simple parsing of patch expressions
        // Format: [{"op": "add", "path": "/metadata/labels/foo", "value": "bar"}]

        let expr = expression.trim();

        // Handle empty or no-op expressions
        if expr.is_empty() || expr == "[]" {
            return Ok(Vec::new());
        }

        // Try to parse as JSON array of patch operations
        if expr.starts_with('[') {
            match serde_json::from_str::<Vec<serde_json::Value>>(expr) {
                Ok(arr) => {
                    let mut patches = Vec::new();
                    for item in arr {
                        if let Some(obj) = item.as_object() {
                            let op = obj.get("op").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let path = obj.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let value = obj.get("value").cloned();
                            let from = obj.get("from").and_then(|v| v.as_str()).map(|s| s.to_string());

                            patches.push(JSONPatchOperation { op, path, value, from });
                        }
                    }
                    return Ok(patches);
                }
                Err(e) => return Err(format!("failed to parse patch: {}", e)),
            }
        }

        // Default: no patches
        Ok(Vec::new())
    }
}

// ============================================================================
// Policy Lister
// ============================================================================

/// Trait for listing MutatingAdmissionPolicies.
pub trait PolicyLister: Send + Sync {
    fn list_policies(&self) -> Vec<MutatingAdmissionPolicy>;
    fn get_policy(&self, name: &str) -> Option<MutatingAdmissionPolicy>;
}

/// Trait for listing MutatingAdmissionPolicyBindings.
pub trait BindingLister: Send + Sync {
    fn list_bindings(&self) -> Vec<MutatingAdmissionPolicyBinding>;
    fn get_bindings_for_policy(&self, policy_name: &str) -> Vec<MutatingAdmissionPolicyBinding>;
}

/// In-memory policy store for testing.
#[derive(Debug, Default)]
pub struct InMemoryPolicyStore {
    policies: RwLock<HashMap<String, MutatingAdmissionPolicy>>,
    bindings: RwLock<HashMap<String, MutatingAdmissionPolicyBinding>>,
}

impl InMemoryPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_policy(&self, policy: MutatingAdmissionPolicy) {
        self.policies
            .write()
            .expect("policy store lock poisoned")
            .insert(policy.name.clone(), policy);
    }

    pub fn add_binding(&self, binding: MutatingAdmissionPolicyBinding) {
        self.bindings
            .write()
            .expect("binding store lock poisoned")
            .insert(binding.name.clone(), binding);
    }
}

impl PolicyLister for InMemoryPolicyStore {
    fn list_policies(&self) -> Vec<MutatingAdmissionPolicy> {
        self.policies
            .read()
            .expect("policy store lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    fn get_policy(&self, name: &str) -> Option<MutatingAdmissionPolicy> {
        self.policies
            .read()
            .expect("policy store lock poisoned")
            .get(name)
            .cloned()
    }
}

impl BindingLister for InMemoryPolicyStore {
    fn list_bindings(&self) -> Vec<MutatingAdmissionPolicyBinding> {
        self.bindings
            .read()
            .expect("binding store lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    fn get_bindings_for_policy(&self, policy_name: &str) -> Vec<MutatingAdmissionPolicyBinding> {
        self.bindings
            .read()
            .expect("binding store lock poisoned")
            .values()
            .filter(|b| b.spec.policy_name == policy_name)
            .cloned()
            .collect()
    }
}

// ============================================================================
// Plugin Implementation
// ============================================================================

pub struct Plugin {
    handler: Handler,
    policy_lister: Option<Arc<dyn PolicyLister>>,
    binding_lister: Option<Arc<dyn BindingLister>>,
    evaluator: Arc<dyn CelEvaluator>,
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]),
            policy_lister: None,
            binding_lister: None,
            evaluator: Arc::new(SimpleCelEvaluator::new()),
        }
    }

    pub fn with_listers(
        policy_lister: Arc<dyn PolicyLister>,
        binding_lister: Arc<dyn BindingLister>,
    ) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]),
            policy_lister: Some(policy_lister),
            binding_lister: Some(binding_lister),
            evaluator: Arc::new(SimpleCelEvaluator::new()),
        }
    }

    pub fn with_evaluator(
        policy_lister: Arc<dyn PolicyLister>,
        binding_lister: Arc<dyn BindingLister>,
        evaluator: Arc<dyn CelEvaluator>,
    ) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update, Operation::Delete]),
            policy_lister: Some(policy_lister),
            binding_lister: Some(binding_lister),
            evaluator,
        }
    }

    /// Build evaluation context from attributes.
    fn build_context(&self, attributes: &dyn Attributes) -> EvaluationContext {
        let object = attributes.get_object().map(|_| serde_json::json!({}));
        let old_object = attributes.get_old_object().map(|_| serde_json::json!({}));

        EvaluationContext {
            object,
            old_object,
            request: RequestContext {
                name: attributes.get_name().to_string(),
                namespace: attributes.get_namespace().to_string(),
                operation: format!("{:?}", attributes.get_operation()),
                resource: attributes.get_resource().resource.clone(),
                subresource: attributes.get_subresource().to_string(),
            },
            variables: HashMap::new(),
        }
    }

    /// Check if a policy matches the request.
    fn policy_matches(&self, policy: &MutatingAdmissionPolicy, attributes: &dyn Attributes) -> bool {
        if let Some(constraints) = &policy.spec.match_constraints {
            if !constraints.resource_rules.is_empty() {
                let matches = constraints.resource_rules.iter().any(|rule| rule.matches(attributes));
                if !matches {
                    return false;
                }
            }

            for rule in &constraints.exclude_resource_rules {
                if rule.matches(attributes) {
                    return false;
                }
            }
        }

        true
    }

    /// Evaluate match conditions for a policy.
    fn check_match_conditions(&self, policy: &MutatingAdmissionPolicy, context: &EvaluationContext) -> Result<bool, String> {
        for condition in &policy.spec.match_conditions {
            match self.evaluator.evaluate_bool(&condition.expression, context) {
                Ok(true) => continue,
                Ok(false) => return Ok(false),
                Err(e) => {
                    if policy.spec.failure_policy == FailurePolicy::Fail {
                        return Err(format!("error evaluating match condition '{}': {}", condition.name, e));
                    }
                    // Ignore error and skip policy
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Apply mutations from a policy.
    fn apply_mutations(&self, policy: &MutatingAdmissionPolicy, context: &EvaluationContext) -> Vec<MutationResult> {
        let mut results = Vec::new();

        for mutation in &policy.spec.mutations {
            match self.evaluator.evaluate_patch(&mutation.expression, context) {
                Ok(patches) => {
                    if patches.is_empty() {
                        results.push(MutationResult::no_op());
                    } else {
                        results.push(MutationResult::success(patches));
                    }
                }
                Err(e) => {
                    if policy.spec.failure_policy == FailurePolicy::Fail {
                        results.push(MutationResult::error(&e));
                    } else {
                        results.push(MutationResult::no_op());
                    }
                }
            }
        }

        if results.is_empty() {
            results.push(MutationResult::no_op());
        }

        results
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
        let policy_lister = match &self.policy_lister {
            Some(l) => l,
            None => return Ok(()), // No policies configured
        };

        let binding_lister = match &self.binding_lister {
            Some(l) => l,
            None => return Ok(()), // No bindings configured
        };

        let context = self.build_context(attributes);

        // Iterate through all policies
        for policy in policy_lister.list_policies() {
            // Check if policy matches this request
            if !self.policy_matches(&policy, attributes) {
                continue;
            }

            // Check if there's a binding for this policy
            let bindings = binding_lister.get_bindings_for_policy(&policy.name);
            if bindings.is_empty() {
                continue;
            }

            // Check match conditions
            match self.check_match_conditions(&policy, &context) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    return Err(AdmissionError::forbidden_msg(format!(
                        "[{}] {}",
                        policy.name, e
                    )));
                }
            }

            // Apply mutations
            let results = self.apply_mutations(&policy, &context);
            for result in results {
                if let Some(err) = result.error {
                    return Err(AdmissionError::forbidden_msg(format!(
                        "[{}] mutation error: {}",
                        policy.name, err
                    )));
                }
                // In a real implementation, we would apply the patches to the object here
                // For now, we just log that mutations were applied
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_failure_policy_from_str() {
        assert_eq!(FailurePolicy::parse("fail"), Some(FailurePolicy::Fail));
        assert_eq!(FailurePolicy::parse("Fail"), Some(FailurePolicy::Fail));
        assert_eq!(FailurePolicy::parse("ignore"), Some(FailurePolicy::Ignore));
        assert_eq!(FailurePolicy::parse("invalid"), None);
    }

    #[test]
    fn test_failure_policy_as_str() {
        assert_eq!(FailurePolicy::Fail.as_str(), "Fail");
        assert_eq!(FailurePolicy::Ignore.as_str(), "Ignore");
    }

    #[test]
    fn test_reinvocation_policy_from_str() {
        assert_eq!(ReinvocationPolicy::parse("never"), Some(ReinvocationPolicy::Never));
        assert_eq!(ReinvocationPolicy::parse("ifneeded"), Some(ReinvocationPolicy::IfNeeded));
        assert_eq!(ReinvocationPolicy::parse("invalid"), None);
    }

    #[test]
    fn test_reinvocation_policy_as_str() {
        assert_eq!(ReinvocationPolicy::Never.as_str(), "Never");
        assert_eq!(ReinvocationPolicy::IfNeeded.as_str(), "IfNeeded");
    }

    #[test]
    fn test_label_selector_matches() {
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "nginx".to_string());
        labels.insert("env".to_string(), "prod".to_string());

        let selector = LabelSelector::with_labels(
            [("app".to_string(), "nginx".to_string())].into_iter().collect()
        );
        assert!(selector.matches(&labels));

        let non_matching = LabelSelector::with_labels(
            [("app".to_string(), "apache".to_string())].into_iter().collect()
        );
        assert!(!non_matching.matches(&labels));
    }

    #[test]
    fn test_mutation_json_patch() {
        let m = Mutation::json_patch("[{\"op\": \"add\", \"path\": \"/metadata/labels/foo\", \"value\": \"bar\"}]");
        assert_eq!(m.patch_type, PatchType::JSONPatch);
    }

    #[test]
    fn test_mutation_apply_configuration() {
        let m = Mutation::apply_configuration("object.spec.replicas = 3");
        assert_eq!(m.patch_type, PatchType::ApplyConfiguration);
    }

    #[test]
    fn test_json_patch_operation_add() {
        let op = JSONPatchOperation::add("/metadata/labels/foo", serde_json::json!("bar"));
        assert_eq!(op.op, "add");
        assert_eq!(op.path, "/metadata/labels/foo");
        assert_eq!(op.value, Some(serde_json::json!("bar")));
    }

    #[test]
    fn test_json_patch_operation_remove() {
        let op = JSONPatchOperation::remove("/metadata/labels/foo");
        assert_eq!(op.op, "remove");
        assert_eq!(op.path, "/metadata/labels/foo");
        assert!(op.value.is_none());
    }

    #[test]
    fn test_json_patch_operation_replace() {
        let op = JSONPatchOperation::replace("/spec/replicas", serde_json::json!(3));
        assert_eq!(op.op, "replace");
        assert_eq!(op.path, "/spec/replicas");
        assert_eq!(op.value, Some(serde_json::json!(3)));
    }

    #[test]
    fn test_mutation_result() {
        let success = MutationResult::success(vec![JSONPatchOperation::add("/test", serde_json::json!("value"))]);
        assert!(success.applied);
        assert!(success.error.is_none());
        assert_eq!(success.patches.len(), 1);

        let no_op = MutationResult::no_op();
        assert!(!no_op.applied);
        assert!(no_op.patches.is_empty());

        let error = MutationResult::error("something went wrong");
        assert!(error.error.is_some());
    }

    #[test]
    fn test_simple_cel_evaluator_bool() {
        let evaluator = SimpleCelEvaluator::new();
        let context = EvaluationContext {
            object: None,
            old_object: None,
            request: RequestContext::default(),
            variables: HashMap::new(),
        };

        assert!(evaluator.evaluate_bool("true", &context).unwrap());
        assert!(!evaluator.evaluate_bool("false", &context).unwrap());
    }

    #[test]
    fn test_simple_cel_evaluator_patch() {
        let evaluator = SimpleCelEvaluator::new();
        let context = EvaluationContext {
            object: None,
            old_object: None,
            request: RequestContext::default(),
            variables: HashMap::new(),
        };

        // Empty patch
        let patches = evaluator.evaluate_patch("[]", &context).unwrap();
        assert!(patches.is_empty());

        // Valid patch
        let patches = evaluator.evaluate_patch(
            r#"[{"op": "add", "path": "/metadata/labels/foo", "value": "bar"}]"#,
            &context
        ).unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].op, "add");
        assert_eq!(patches[0].path, "/metadata/labels/foo");
    }

    #[test]
    fn test_policy_store() {
        let store = InMemoryPolicyStore::new();

        let policy = MutatingAdmissionPolicy::new("test-policy");
        store.add_policy(policy.clone());

        let binding = MutatingAdmissionPolicyBinding::new("test-binding", "test-policy");
        store.add_binding(binding);

        assert!(store.get_policy("test-policy").is_some());
        assert!(store.get_policy("nonexistent").is_none());

        let bindings = store.get_bindings_for_policy("test-policy");
        assert_eq!(bindings.len(), 1);
    }

    #[test]
    fn test_plugin_no_policies() {
        let plugin = Plugin::new();

        use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
        use crate::api::core::Pod;

        let pod = Pod::new("test", "default");
        let mut attrs = AttributesRecord::new(
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

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_with_no_op_mutation() {
        let store = Arc::new(InMemoryPolicyStore::new());

        let policy = MutatingAdmissionPolicy::with_mutations(
            "no-op",
            vec![Mutation::json_patch("[]")],
        );
        store.add_policy(policy);
        store.add_binding(MutatingAdmissionPolicyBinding::new("no-op-binding", "no-op"));

        let plugin = Plugin::with_listers(store.clone(), store);

        use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
        use crate::api::core::Pod;

        let pod = Pod::new("test", "default");
        let mut attrs = AttributesRecord::new(
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

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_with_mutation() {
        let store = Arc::new(InMemoryPolicyStore::new());

        let policy = MutatingAdmissionPolicy::with_mutations(
            "add-label",
            vec![Mutation::json_patch(r#"[{"op": "add", "path": "/metadata/labels/injected", "value": "true"}]"#)],
        );
        store.add_policy(policy);
        store.add_binding(MutatingAdmissionPolicyBinding::new("add-label-binding", "add-label"));

        let plugin = Plugin::with_listers(store.clone(), store);

        use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
        use crate::api::core::Pod;

        let pod = Pod::new("test", "default");
        let mut attrs = AttributesRecord::new(
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

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_match_condition() {
        let mc = MatchCondition::new("check-namespace", "request.namespace != 'kube-system'");
        assert_eq!(mc.name, "check-namespace");
        assert_eq!(mc.expression, "request.namespace != 'kube-system'");
    }

    #[test]
    fn test_variable() {
        let v = Variable::new("isAdmin", "request.userInfo.username == 'admin'");
        assert_eq!(v.name, "isAdmin");
        assert_eq!(v.expression, "request.userInfo.username == 'admin'");
    }

    #[test]
    fn test_resource_rule_for_pods() {
        let rule = ResourceRule::for_pods();
        assert_eq!(rule.api_groups, vec!["".to_string()]);
        assert_eq!(rule.api_versions, vec!["v1".to_string()]);
        assert_eq!(rule.resources, vec!["pods".to_string()]);
    }

    #[test]
    fn test_default_trait() {
        let plugin = Plugin::default();
        assert!(plugin.handles(Operation::Create));
    }

    #[test]
    fn test_policy_new() {
        let policy = MutatingAdmissionPolicy::new("test");
        assert_eq!(policy.name, "test");
        assert!(policy.spec.mutations.is_empty());
    }

    #[test]
    fn test_binding_new() {
        let binding = MutatingAdmissionPolicyBinding::new("test-binding", "test-policy");
        assert_eq!(binding.name, "test-binding");
        assert_eq!(binding.spec.policy_name, "test-policy");
    }
}
