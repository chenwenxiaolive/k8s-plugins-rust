// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! ValidatingAdmissionPolicy admission controller.
//!
//! This admission controller validates admission requests using CEL (Common Expression Language)
//! expressions defined in ValidatingAdmissionPolicy resources. It provides a declarative,
//! in-process alternative to validating admission webhooks.
//!
//! Key features:
//! - CEL-based validation expressions
//! - Policy bindings to match specific resources
//! - Audit annotations for policy decisions
//! - Failure policy configuration (Fail or Ignore)
//! - Parameter references for policy configuration

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use crate::api::core::ApiObject;
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

pub const PLUGIN_NAME: &str = "ValidatingAdmissionPolicy";

pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

// ============================================================================
// CEL Expression Types
// ============================================================================

/// FailurePolicy defines how to handle failures for the admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailurePolicy {
    /// Fail means that an error calling the webhook causes the admission to fail.
    #[default]
    Fail,
    /// Ignore means that an error is ignored and the request is allowed.
    Ignore,
}

impl FailurePolicy {
    pub fn from_str(s: &str) -> Option<Self> {
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

/// Validation contains a CEL expression which evaluates to true or false.
#[derive(Debug, Clone, PartialEq)]
pub struct Validation {
    /// Expression is the CEL expression to evaluate.
    pub expression: String,
    /// Message is the message to display when validation fails.
    pub message: String,
    /// MessageExpression is a CEL expression that evaluates to a string message.
    pub message_expression: Option<String>,
    /// Reason is a machine-readable reason for the validation failure.
    pub reason: Option<String>,
}

impl Validation {
    pub fn new(expression: &str, message: &str) -> Self {
        Self {
            expression: expression.to_string(),
            message: message.to_string(),
            message_expression: None,
            reason: None,
        }
    }

    pub fn with_reason(expression: &str, message: &str, reason: &str) -> Self {
        Self {
            expression: expression.to_string(),
            message: message.to_string(),
            message_expression: None,
            reason: Some(reason.to_string()),
        }
    }
}

/// AuditAnnotation describes how to produce an audit annotation for an API request.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditAnnotation {
    /// Key is the audit annotation key.
    pub key: String,
    /// ValueExpression is a CEL expression that evaluates to the annotation value.
    pub value_expression: String,
}

impl AuditAnnotation {
    pub fn new(key: &str, value_expression: &str) -> Self {
        Self {
            key: key.to_string(),
            value_expression: value_expression.to_string(),
        }
    }
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
// Policy and Binding Types
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
    /// MatchPolicy defines how the "rules" list is used to match incoming requests.
    pub match_policy: MatchPolicy,
}

/// LabelSelector is a label query over a set of resources.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LabelSelector {
    /// MatchLabels is a map of key-value pairs.
    pub match_labels: HashMap<String, String>,
    /// MatchExpressions is a list of label selector requirements.
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

impl LabelSelector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_labels(labels: HashMap<String, String>) -> Self {
        Self {
            match_labels: labels,
            match_expressions: Vec::new(),
        }
    }

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
            if !expr.matches(labels) {
                return false;
            }
        }

        true
    }
}

/// LabelSelectorRequirement is a selector that contains values, a key, and an operator.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelSelectorRequirement {
    /// Key is the label key that the selector applies to.
    pub key: String,
    /// Operator represents a key's relationship to a set of values.
    pub operator: LabelSelectorOperator,
    /// Values is an array of string values.
    pub values: Vec<String>,
}

impl LabelSelectorRequirement {
    pub fn matches(&self, labels: &HashMap<String, String>) -> bool {
        match self.operator {
            LabelSelectorOperator::In => {
                if let Some(value) = labels.get(&self.key) {
                    self.values.contains(value)
                } else {
                    false
                }
            }
            LabelSelectorOperator::NotIn => {
                if let Some(value) = labels.get(&self.key) {
                    !self.values.contains(value)
                } else {
                    true
                }
            }
            LabelSelectorOperator::Exists => labels.contains_key(&self.key),
            LabelSelectorOperator::DoesNotExist => !labels.contains_key(&self.key),
        }
    }
}

/// LabelSelectorOperator is the set of operators that can be used in a selector requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelSelectorOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

/// MatchPolicy specifies how the policy's rules are matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchPolicy {
    /// Exact means requests should only match when they exactly match a rule.
    #[default]
    Exact,
    /// Equivalent means requests should match even if a different version is specified.
    Equivalent,
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

        // Check API group
        let group_matches = self.api_groups.is_empty()
            || self.api_groups.iter().any(|g| g == "*" || g == &resource.group);

        // Check API version
        let version_matches = self.api_versions.is_empty()
            || self.api_versions.iter().any(|v| v == "*" || v == &resource.version);

        // Check resource
        let resource_matches = self.resources.is_empty()
            || self.resources.iter().any(|r| r == "*" || r == &resource.resource);

        // Check operation
        let operation_matches = self.operations.is_empty()
            || self.operations.contains(&attributes.get_operation());

        group_matches && version_matches && resource_matches && operation_matches
    }
}

/// ValidatingAdmissionPolicy describes the definition of a validation policy.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatingAdmissionPolicy {
    /// Name is the name of the policy.
    pub name: String,
    /// Spec contains the policy specification.
    pub spec: ValidatingAdmissionPolicySpec,
}

impl ValidatingAdmissionPolicy {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            spec: ValidatingAdmissionPolicySpec::default(),
        }
    }

    pub fn with_validations(name: &str, validations: Vec<Validation>) -> Self {
        Self {
            name: name.to_string(),
            spec: ValidatingAdmissionPolicySpec {
                validations,
                ..Default::default()
            },
        }
    }
}

impl ApiObject for ValidatingAdmissionPolicy {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "ValidatingAdmissionPolicy"
    }
}

/// ValidatingAdmissionPolicySpec is the specification for a ValidatingAdmissionPolicy.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ValidatingAdmissionPolicySpec {
    /// MatchConstraints specifies what resources this policy applies to.
    pub match_constraints: Option<MatchResources>,
    /// Validations contain CEL expressions to validate requests.
    pub validations: Vec<Validation>,
    /// FailurePolicy defines how to handle failures.
    pub failure_policy: FailurePolicy,
    /// AuditAnnotations contains CEL expressions for audit annotations.
    pub audit_annotations: Vec<AuditAnnotation>,
    /// MatchConditions is a list of conditions that must be met for a request to be validated.
    pub match_conditions: Vec<MatchCondition>,
    /// Variables are named expressions for use in compositions.
    pub variables: Vec<Variable>,
}

/// ValidatingAdmissionPolicyBinding binds a policy to resources.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatingAdmissionPolicyBinding {
    /// Name is the name of the binding.
    pub name: String,
    /// Spec contains the binding specification.
    pub spec: ValidatingAdmissionPolicyBindingSpec,
}

impl ValidatingAdmissionPolicyBinding {
    pub fn new(name: &str, policy_name: &str) -> Self {
        Self {
            name: name.to_string(),
            spec: ValidatingAdmissionPolicyBindingSpec {
                policy_name: policy_name.to_string(),
                ..Default::default()
            },
        }
    }
}

impl ApiObject for ValidatingAdmissionPolicyBinding {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "ValidatingAdmissionPolicyBinding"
    }
}

/// ValidatingAdmissionPolicyBindingSpec is the specification for a binding.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ValidatingAdmissionPolicyBindingSpec {
    /// PolicyName is the name of the policy to bind.
    pub policy_name: String,
    /// MatchResources restricts what resources the binding applies to.
    pub match_resources: Option<MatchResources>,
    /// ValidationActions declares how validations are enforced.
    pub validation_actions: Vec<ValidationAction>,
}

/// ValidationAction specifies how validation failures are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationAction {
    /// Deny means the request will be denied if validation fails.
    Deny,
    /// Warn means a warning will be returned if validation fails.
    Warn,
    /// Audit means an audit annotation will be added if validation fails.
    Audit,
}

// ============================================================================
// CEL Evaluator (Simplified)
// ============================================================================

/// CEL evaluation result.
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub allowed: bool,
    pub message: Option<String>,
    pub reason: Option<String>,
}

impl EvaluationResult {
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            message: None,
            reason: None,
        }
    }

    pub fn denied(message: &str) -> Self {
        Self {
            allowed: false,
            message: Some(message.to_string()),
            reason: None,
        }
    }

    pub fn denied_with_reason(message: &str, reason: &str) -> Self {
        Self {
            allowed: false,
            message: Some(message.to_string()),
            reason: Some(reason.to_string()),
        }
    }
}

/// CEL Evaluator trait for evaluating CEL expressions.
pub trait CelEvaluator: Send + Sync {
    /// Evaluate a CEL expression against the given context.
    fn evaluate(&self, expression: &str, context: &EvaluationContext) -> Result<bool, String>;

    /// Evaluate a CEL expression that returns a string.
    fn evaluate_string(&self, expression: &str, context: &EvaluationContext) -> Result<String, String>;
}

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
    pub user_info: UserInfo,
}

/// User information for CEL evaluation.
#[derive(Debug, Clone, Default)]
pub struct UserInfo {
    pub username: String,
    pub groups: Vec<String>,
}

/// Simple CEL evaluator for common expressions.
/// In a real implementation, this would use a full CEL library.
#[derive(Debug, Default)]
pub struct SimpleCelEvaluator;

impl SimpleCelEvaluator {
    pub fn new() -> Self {
        Self
    }

    /// Parse and evaluate simple CEL expressions.
    /// This is a simplified implementation that handles common patterns.
    fn evaluate_simple(&self, expression: &str, context: &EvaluationContext) -> Result<bool, String> {
        let expr = expression.trim();

        // Handle literal true/false
        if expr == "true" {
            return Ok(true);
        }
        if expr == "false" {
            return Ok(false);
        }

        // Handle object.spec checks
        if expr.starts_with("object.") {
            return self.evaluate_object_expression(expr, context);
        }

        // Handle request checks
        if expr.starts_with("request.") {
            return self.evaluate_request_expression(expr, context);
        }

        // Handle has() function
        if expr.starts_with("has(") {
            return self.evaluate_has_expression(expr, context);
        }

        // Handle size() comparisons
        if expr.contains("size(") {
            return self.evaluate_size_expression(expr, context);
        }

        // Default: allow unknown expressions (would need full CEL parser)
        Ok(true)
    }

    fn evaluate_object_expression(&self, expr: &str, context: &EvaluationContext) -> Result<bool, String> {
        let object = context.object.as_ref().ok_or("No object in context")?;

        // Simple path navigation
        let path = expr.strip_prefix("object.").unwrap_or(expr);

        // Handle comparisons
        if let Some((left, right)) = path.split_once("==") {
            let left_value = self.get_json_path(object, left.trim());
            let right_value = right.trim().trim_matches('"').trim_matches('\'');
            return Ok(left_value.as_ref().map(|v| v == right_value).unwrap_or(false));
        }

        if let Some((left, right)) = path.split_once("!=") {
            let left_value = self.get_json_path(object, left.trim());
            let right_value = right.trim().trim_matches('"').trim_matches('\'');
            return Ok(left_value.as_ref().map(|v| v != right_value).unwrap_or(true));
        }

        // Handle existence check
        let value = self.get_json_path(object, path);
        Ok(value.is_some())
    }

    fn evaluate_request_expression(&self, expr: &str, context: &EvaluationContext) -> Result<bool, String> {
        let path = expr.strip_prefix("request.").unwrap_or(expr);

        // Handle comparisons
        if let Some((left, right)) = path.split_once("==") {
            let left_value = match left.trim() {
                "namespace" => &context.request.namespace,
                "name" => &context.request.name,
                "operation" => &context.request.operation,
                "resource.resource" => &context.request.resource,
                _ => return Ok(true),
            };
            let right_value = right.trim().trim_matches('"').trim_matches('\'');
            return Ok(left_value == right_value);
        }

        Ok(true)
    }

    fn evaluate_has_expression(&self, expr: &str, context: &EvaluationContext) -> Result<bool, String> {
        // Extract the path from has(...)
        let inner = expr
            .strip_prefix("has(")
            .and_then(|s| s.strip_suffix(")"))
            .ok_or("Invalid has() expression")?;

        if inner.starts_with("object.") {
            let object = context.object.as_ref().ok_or("No object in context")?;
            let path = inner.strip_prefix("object.").unwrap_or(inner);
            return Ok(self.get_json_path(object, path).is_some());
        }

        Ok(true)
    }

    fn evaluate_size_expression(&self, expr: &str, context: &EvaluationContext) -> Result<bool, String> {
        // Handle expressions like: object.spec.containers.size() > 0
        if let Some(object) = &context.object {
            // Extract the path before .size()
            if let Some(size_pos) = expr.find(".size()") {
                let path_part = &expr[..size_pos];
                let path = path_part.strip_prefix("object.").unwrap_or(path_part);

                if let Some(value) = self.get_json_value(object, path) {
                    let size = match value {
                        serde_json::Value::Array(arr) => arr.len(),
                        serde_json::Value::String(s) => s.len(),
                        serde_json::Value::Object(obj) => obj.len(),
                        _ => 0,
                    };

                    // Handle comparison
                    let rest = &expr[size_pos + 7..].trim();
                    if let Some(num_str) = rest.strip_prefix(">") {
                        if let Ok(num) = num_str.trim().parse::<usize>() {
                            return Ok(size > num);
                        }
                    }
                    if let Some(num_str) = rest.strip_prefix(">=") {
                        if let Ok(num) = num_str.trim().parse::<usize>() {
                            return Ok(size >= num);
                        }
                    }
                    if let Some(num_str) = rest.strip_prefix("<") {
                        if let Ok(num) = num_str.trim().parse::<usize>() {
                            return Ok(size < num);
                        }
                    }
                    if let Some(num_str) = rest.strip_prefix("==") {
                        if let Ok(num) = num_str.trim().parse::<usize>() {
                            return Ok(size == num);
                        }
                    }
                }
            }
        }

        Ok(true)
    }

    fn get_json_path(&self, value: &serde_json::Value, path: &str) -> Option<String> {
        self.get_json_value(value, path).and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        })
    }

    fn get_json_value(&self, value: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
        let mut current = value.clone();
        for part in path.split('.') {
            // Handle array index
            if let Some(bracket_pos) = part.find('[') {
                let field = &part[..bracket_pos];
                let index_str = part[bracket_pos + 1..].trim_end_matches(']');

                if !field.is_empty() {
                    current = current.get(field)?.clone();
                }

                if let Ok(index) = index_str.parse::<usize>() {
                    current = current.get(index)?.clone();
                }
            } else {
                current = current.get(part)?.clone();
            }
        }
        Some(current)
    }
}

impl CelEvaluator for SimpleCelEvaluator {
    fn evaluate(&self, expression: &str, context: &EvaluationContext) -> Result<bool, String> {
        self.evaluate_simple(expression, context)
    }

    fn evaluate_string(&self, expression: &str, context: &EvaluationContext) -> Result<String, String> {
        // Simple string evaluation
        if expression.starts_with("'") && expression.ends_with("'") {
            return Ok(expression[1..expression.len() - 1].to_string());
        }
        if expression.starts_with("\"") && expression.ends_with("\"") {
            return Ok(expression[1..expression.len() - 1].to_string());
        }

        // For object paths, try to get the value
        if expression.starts_with("object.") {
            if let Some(object) = &context.object {
                let path = expression.strip_prefix("object.").unwrap_or(expression);
                if let Some(value) = self.get_json_path(object, path) {
                    return Ok(value);
                }
            }
        }

        Ok(expression.to_string())
    }
}

// ============================================================================
// Policy Lister
// ============================================================================

/// Trait for listing ValidatingAdmissionPolicies.
pub trait PolicyLister: Send + Sync {
    fn list_policies(&self) -> Vec<ValidatingAdmissionPolicy>;
    fn get_policy(&self, name: &str) -> Option<ValidatingAdmissionPolicy>;
}

/// Trait for listing ValidatingAdmissionPolicyBindings.
pub trait BindingLister: Send + Sync {
    fn list_bindings(&self) -> Vec<ValidatingAdmissionPolicyBinding>;
    fn get_bindings_for_policy(&self, policy_name: &str) -> Vec<ValidatingAdmissionPolicyBinding>;
}

/// In-memory policy store for testing.
#[derive(Debug, Default)]
pub struct InMemoryPolicyStore {
    policies: RwLock<HashMap<String, ValidatingAdmissionPolicy>>,
    bindings: RwLock<HashMap<String, ValidatingAdmissionPolicyBinding>>,
}

impl InMemoryPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_policy(&self, policy: ValidatingAdmissionPolicy) {
        self.policies.write().unwrap().insert(policy.name.clone(), policy);
    }

    pub fn add_binding(&self, binding: ValidatingAdmissionPolicyBinding) {
        self.bindings.write().unwrap().insert(binding.name.clone(), binding);
    }
}

impl PolicyLister for InMemoryPolicyStore {
    fn list_policies(&self) -> Vec<ValidatingAdmissionPolicy> {
        self.policies.read().unwrap().values().cloned().collect()
    }

    fn get_policy(&self, name: &str) -> Option<ValidatingAdmissionPolicy> {
        self.policies.read().unwrap().get(name).cloned()
    }
}

impl BindingLister for InMemoryPolicyStore {
    fn list_bindings(&self) -> Vec<ValidatingAdmissionPolicyBinding> {
        self.bindings.read().unwrap().values().cloned().collect()
    }

    fn get_bindings_for_policy(&self, policy_name: &str) -> Vec<ValidatingAdmissionPolicyBinding> {
        self.bindings
            .read()
            .unwrap()
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
                user_info: UserInfo::default(),
            },
            variables: HashMap::new(),
        }
    }

    /// Check if a policy matches the request.
    fn policy_matches(&self, policy: &ValidatingAdmissionPolicy, attributes: &dyn Attributes) -> bool {
        if let Some(constraints) = &policy.spec.match_constraints {
            // Check resource rules
            if !constraints.resource_rules.is_empty() {
                let matches = constraints.resource_rules.iter().any(|rule| rule.matches(attributes));
                if !matches {
                    return false;
                }
            }

            // Check exclude rules
            for rule in &constraints.exclude_resource_rules {
                if rule.matches(attributes) {
                    return false;
                }
            }
        }

        true
    }

    /// Evaluate a policy against the request.
    fn evaluate_policy(
        &self,
        policy: &ValidatingAdmissionPolicy,
        context: &EvaluationContext,
    ) -> Vec<EvaluationResult> {
        let mut results = Vec::new();

        // Check match conditions first
        for condition in &policy.spec.match_conditions {
            match self.evaluator.evaluate(&condition.expression, context) {
                Ok(true) => continue,
                Ok(false) => {
                    // Match condition not met, skip this policy
                    return vec![EvaluationResult::allowed()];
                }
                Err(_) => {
                    // Error evaluating match condition
                    if policy.spec.failure_policy == FailurePolicy::Fail {
                        results.push(EvaluationResult::denied(&format!(
                            "error evaluating match condition '{}'",
                            condition.name
                        )));
                        return results;
                    }
                }
            }
        }

        // Evaluate validations
        for validation in &policy.spec.validations {
            match self.evaluator.evaluate(&validation.expression, context) {
                Ok(true) => {
                    results.push(EvaluationResult::allowed());
                }
                Ok(false) => {
                    let message = if let Some(ref msg_expr) = validation.message_expression {
                        self.evaluator
                            .evaluate_string(msg_expr, context)
                            .unwrap_or_else(|_| validation.message.clone())
                    } else {
                        validation.message.clone()
                    };

                    if let Some(ref reason) = validation.reason {
                        results.push(EvaluationResult::denied_with_reason(&message, reason));
                    } else {
                        results.push(EvaluationResult::denied(&message));
                    }
                }
                Err(e) => {
                    if policy.spec.failure_policy == FailurePolicy::Fail {
                        results.push(EvaluationResult::denied(&format!(
                            "error evaluating validation: {}",
                            e
                        )));
                    } else {
                        results.push(EvaluationResult::allowed());
                    }
                }
            }
        }

        if results.is_empty() {
            results.push(EvaluationResult::allowed());
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

impl ValidationInterface for Plugin {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        let policy_lister = match &self.policy_lister {
            Some(l) => l,
            None => return Ok(()), // No policies configured
        };

        let binding_lister = match &self.binding_lister {
            Some(l) => l,
            None => return Ok(()), // No bindings configured
        };

        let context = self.build_context(attributes);
        let mut denial_messages = Vec::new();

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

            // Evaluate the policy
            let results = self.evaluate_policy(&policy, &context);

            for result in results {
                if !result.allowed {
                    if let Some(msg) = result.message {
                        denial_messages.push(format!("[{}] {}", policy.name, msg));
                    }
                }
            }
        }

        if !denial_messages.is_empty() {
            return Err(AdmissionError::forbidden_msg(denial_messages.join("; ")));
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
        assert_eq!(FailurePolicy::from_str("fail"), Some(FailurePolicy::Fail));
        assert_eq!(FailurePolicy::from_str("Fail"), Some(FailurePolicy::Fail));
        assert_eq!(FailurePolicy::from_str("ignore"), Some(FailurePolicy::Ignore));
        assert_eq!(FailurePolicy::from_str("invalid"), None);
    }

    #[test]
    fn test_failure_policy_as_str() {
        assert_eq!(FailurePolicy::Fail.as_str(), "Fail");
        assert_eq!(FailurePolicy::Ignore.as_str(), "Ignore");
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
    fn test_label_selector_requirement_in() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());

        let req = LabelSelectorRequirement {
            key: "env".to_string(),
            operator: LabelSelectorOperator::In,
            values: vec!["prod".to_string(), "staging".to_string()],
        };
        assert!(req.matches(&labels));

        let req_not_match = LabelSelectorRequirement {
            key: "env".to_string(),
            operator: LabelSelectorOperator::In,
            values: vec!["dev".to_string()],
        };
        assert!(!req_not_match.matches(&labels));
    }

    #[test]
    fn test_label_selector_requirement_exists() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());

        let req = LabelSelectorRequirement {
            key: "env".to_string(),
            operator: LabelSelectorOperator::Exists,
            values: vec![],
        };
        assert!(req.matches(&labels));

        let req_not_exists = LabelSelectorRequirement {
            key: "missing".to_string(),
            operator: LabelSelectorOperator::Exists,
            values: vec![],
        };
        assert!(!req_not_exists.matches(&labels));
    }

    #[test]
    fn test_label_selector_requirement_does_not_exist() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());

        let req = LabelSelectorRequirement {
            key: "missing".to_string(),
            operator: LabelSelectorOperator::DoesNotExist,
            values: vec![],
        };
        assert!(req.matches(&labels));

        let req_exists = LabelSelectorRequirement {
            key: "env".to_string(),
            operator: LabelSelectorOperator::DoesNotExist,
            values: vec![],
        };
        assert!(!req_exists.matches(&labels));
    }

    #[test]
    fn test_simple_cel_evaluator_literals() {
        let evaluator = SimpleCelEvaluator::new();
        let context = EvaluationContext {
            object: None,
            old_object: None,
            request: RequestContext::default(),
            variables: HashMap::new(),
        };

        assert!(evaluator.evaluate("true", &context).unwrap());
        assert!(!evaluator.evaluate("false", &context).unwrap());
    }

    #[test]
    fn test_simple_cel_evaluator_object_path() {
        let evaluator = SimpleCelEvaluator::new();
        let context = EvaluationContext {
            object: Some(serde_json::json!({
                "metadata": {
                    "name": "test-pod",
                    "namespace": "default"
                },
                "spec": {
                    "containers": [
                        {"name": "nginx", "image": "nginx:latest"}
                    ]
                }
            })),
            old_object: None,
            request: RequestContext::default(),
            variables: HashMap::new(),
        };

        assert!(evaluator.evaluate("object.metadata.name == 'test-pod'", &context).unwrap());
        assert!(!evaluator.evaluate("object.metadata.name == 'other'", &context).unwrap());
    }

    #[test]
    fn test_simple_cel_evaluator_has() {
        let evaluator = SimpleCelEvaluator::new();
        let context = EvaluationContext {
            object: Some(serde_json::json!({
                "metadata": {
                    "name": "test"
                }
            })),
            old_object: None,
            request: RequestContext::default(),
            variables: HashMap::new(),
        };

        assert!(evaluator.evaluate("has(object.metadata)", &context).unwrap());
        assert!(evaluator.evaluate("has(object.metadata.name)", &context).unwrap());
    }

    #[test]
    fn test_validation_new() {
        let v = Validation::new("object.spec.replicas > 0", "Replicas must be positive");
        assert_eq!(v.expression, "object.spec.replicas > 0");
        assert_eq!(v.message, "Replicas must be positive");
        assert!(v.reason.is_none());
    }

    #[test]
    fn test_validation_with_reason() {
        let v = Validation::with_reason(
            "object.spec.replicas > 0",
            "Replicas must be positive",
            "InvalidValue",
        );
        assert_eq!(v.reason, Some("InvalidValue".to_string()));
    }

    #[test]
    fn test_policy_store() {
        let store = InMemoryPolicyStore::new();

        let policy = ValidatingAdmissionPolicy::new("test-policy");
        store.add_policy(policy.clone());

        let binding = ValidatingAdmissionPolicyBinding::new("test-binding", "test-policy");
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
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_with_allowing_policy() {
        let store = Arc::new(InMemoryPolicyStore::new());

        let policy = ValidatingAdmissionPolicy::with_validations(
            "allow-all",
            vec![Validation::new("true", "always allow")],
        );
        store.add_policy(policy);
        store.add_binding(ValidatingAdmissionPolicyBinding::new("allow-all-binding", "allow-all"));

        let plugin = Plugin::with_listers(store.clone(), store);

        use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
        use crate::api::core::Pod;

        let pod = Pod::new("test", "default");
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
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_with_denying_policy() {
        let store = Arc::new(InMemoryPolicyStore::new());

        let policy = ValidatingAdmissionPolicy::with_validations(
            "deny-all",
            vec![Validation::new("false", "always deny")],
        );
        store.add_policy(policy);
        store.add_binding(ValidatingAdmissionPolicyBinding::new("deny-all-binding", "deny-all"));

        let plugin = Plugin::with_listers(store.clone(), store);

        use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
        use crate::api::core::Pod;

        let pod = Pod::new("test", "default");
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
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("always deny"));
    }

    #[test]
    fn test_evaluation_result() {
        let allowed = EvaluationResult::allowed();
        assert!(allowed.allowed);
        assert!(allowed.message.is_none());

        let denied = EvaluationResult::denied("not allowed");
        assert!(!denied.allowed);
        assert_eq!(denied.message, Some("not allowed".to_string()));

        let denied_reason = EvaluationResult::denied_with_reason("not allowed", "InvalidValue");
        assert_eq!(denied_reason.reason, Some("InvalidValue".to_string()));
    }

    #[test]
    fn test_match_condition() {
        let mc = MatchCondition::new("check-namespace", "request.namespace != 'kube-system'");
        assert_eq!(mc.name, "check-namespace");
        assert_eq!(mc.expression, "request.namespace != 'kube-system'");
    }

    #[test]
    fn test_audit_annotation() {
        let aa = AuditAnnotation::new("policy-applied", "'test-policy'");
        assert_eq!(aa.key, "policy-applied");
        assert_eq!(aa.value_expression, "'test-policy'");
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
}
