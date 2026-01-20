// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! DefaultIngressClass admission controller.
//!
//! This admission controller sets the default IngressClass on Ingress objects
//! that don't have an IngressClassName specified. It looks for IngressClass
//! objects with the annotation "ingressclass.kubernetes.io/is-default-class=true".

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins,
};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

pub const PLUGIN_NAME: &str = "DefaultIngressClass";

/// Annotation key for marking an IngressClass as default.
pub const ANNOTATION_IS_DEFAULT_INGRESS_CLASS: &str = "ingressclass.kubernetes.io/is-default-class";

/// Deprecated annotation key for ingress class (from v1beta1).
pub const ANNOTATION_INGRESS_CLASS: &str = "kubernetes.io/ingress.class";

pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// IngressClass represents the class of an Ingress.
#[derive(Debug, Clone, PartialEq)]
pub struct IngressClass {
    /// Name of the IngressClass.
    pub name: String,
    /// Annotations on the IngressClass.
    pub annotations: HashMap<String, String>,
    /// Creation timestamp (nanoseconds since epoch for sorting).
    pub creation_timestamp: i64,
}

impl IngressClass {
    /// Create a new IngressClass.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            annotations: HashMap::new(),
            creation_timestamp: 0,
        }
    }

    /// Create a new IngressClass with annotations.
    pub fn with_annotations(name: &str, annotations: HashMap<String, String>) -> Self {
        Self {
            name: name.to_string(),
            annotations,
            creation_timestamp: 0,
        }
    }

    /// Create a new default IngressClass.
    pub fn new_default(name: &str) -> Self {
        let mut annotations = HashMap::new();
        annotations.insert(ANNOTATION_IS_DEFAULT_INGRESS_CLASS.to_string(), "true".to_string());
        Self {
            name: name.to_string(),
            annotations,
            creation_timestamp: 0,
        }
    }

    /// Check if this IngressClass is marked as default.
    pub fn is_default(&self) -> bool {
        self.annotations
            .get(ANNOTATION_IS_DEFAULT_INGRESS_CLASS)
            .map(|v| v == "true")
            .unwrap_or(false)
    }
}

/// IngressSpec represents the specification of an Ingress.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IngressSpec {
    /// IngressClassName is the name of the IngressClass cluster resource.
    pub ingress_class_name: Option<String>,
}

/// Ingress represents a Kubernetes Ingress.
#[derive(Debug, Clone, PartialEq)]
pub struct Ingress {
    /// Name of the Ingress.
    pub name: String,
    /// Namespace of the Ingress.
    pub namespace: String,
    /// Annotations on the Ingress.
    pub annotations: HashMap<String, String>,
    /// Spec is the desired state of the Ingress.
    pub spec: IngressSpec,
}

impl Ingress {
    /// Create a new Ingress.
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            annotations: HashMap::new(),
            spec: IngressSpec::default(),
        }
    }
}

impl crate::api::core::ApiObject for Ingress {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "Ingress"
    }
}

/// Trait for listing IngressClass objects.
pub trait IngressClassLister: Send + Sync {
    /// List all IngressClass objects.
    fn list(&self) -> Vec<IngressClass>;
}

/// In-memory implementation of IngressClassLister for testing.
pub struct InMemoryIngressClassLister {
    classes: RwLock<Vec<IngressClass>>,
}

impl InMemoryIngressClassLister {
    pub fn new() -> Self {
        Self {
            classes: RwLock::new(Vec::new()),
        }
    }

    pub fn add_class(&self, class: IngressClass) {
        let mut classes = self.classes.write().unwrap();
        classes.push(class);
    }
}

impl Default for InMemoryIngressClassLister {
    fn default() -> Self {
        Self::new()
    }
}

impl IngressClassLister for InMemoryIngressClassLister {
    fn list(&self) -> Vec<IngressClass> {
        let classes = self.classes.read().unwrap();
        classes.clone()
    }
}

pub struct Plugin {
    handler: Handler,
    /// Lister for IngressClass objects.
    lister: Option<Arc<dyn IngressClassLister>>,
    /// Whether the plugin is ready.
    ready: bool,
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            lister: None,
            ready: false,
        }
    }

    /// Set the IngressClass lister and mark the plugin as ready.
    pub fn set_lister(&mut self, lister: Arc<dyn IngressClassLister>) {
        self.lister = Some(lister);
        self.ready = true;
    }

    /// Create a plugin with a lister already set.
    pub fn with_lister(lister: Arc<dyn IngressClassLister>) -> Self {
        let mut plugin = Self::new();
        plugin.set_lister(lister);
        plugin
    }

    /// Get the default IngressClass from the lister.
    /// If multiple defaults exist, choose the newest (by creation timestamp),
    /// then by name (lexicographically smaller) as a tie-breaker.
    fn get_default_class(&self) -> AdmissionResult<Option<IngressClass>> {
        let lister = match &self.lister {
            Some(l) => l,
            None => return Ok(None),
        };

        let classes = lister.list();
        let mut default_classes: Vec<IngressClass> = classes
            .into_iter()
            .filter(|c| c.is_default())
            .collect();

        if default_classes.is_empty() {
            return Ok(None);
        }

        // Sort by creation timestamp (descending), then by name (ascending) as tie-breaker
        default_classes.sort_by(|a, b| {
            if a.creation_timestamp == b.creation_timestamp {
                a.name.cmp(&b.name)
            } else {
                b.creation_timestamp.cmp(&a.creation_timestamp)
            }
        });

        Ok(Some(default_classes.remove(0)))
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
        let resource = attributes.get_resource();
        if resource.resource != "ingresses" {
            return Ok(());
        }

        // Ignore subresources
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        // Check if we're ready
        if !self.ready {
            return Err(AdmissionError::not_ready(PLUGIN_NAME));
        }

        // Get the Ingress object
        let ingress = match attributes
            .get_object_mut()
            .and_then(|obj| obj.as_any_mut().downcast_mut::<Ingress>())
        {
            Some(i) => i,
            None => {
                return Err(AdmissionError::BadRequest(format!(
                    "Expected Ingress resource, got: {}",
                    attributes.get_kind().kind
                )));
            }
        };

        // If IngressClassName field is already set, no need to set a default
        if ingress.spec.ingress_class_name.is_some() {
            return Ok(());
        }

        // If deprecated annotation is set, no need to set a default
        if ingress.annotations.contains_key(ANNOTATION_INGRESS_CLASS) {
            return Ok(());
        }

        // Get the default class
        let default_class = self.get_default_class()?;

        // No default class specified, no need to set a default value
        if default_class.is_none() {
            return Ok(());
        }

        // Set the default class
        ingress.spec.ingress_class_name = Some(default_class.unwrap().name);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    fn create_ingress(name: &str, class_name: Option<&str>) -> Ingress {
        let mut ingress = Ingress::new(name, "testing");
        ingress.spec.ingress_class_name = class_name.map(|s| s.to_string());
        ingress
    }

    fn create_ingress_with_annotation(name: &str, annotation_value: &str) -> Ingress {
        let mut ingress = Ingress::new(name, "testing");
        ingress.annotations.insert(ANNOTATION_INGRESS_CLASS.to_string(), annotation_value.to_string());
        ingress
    }

    fn create_default_class(name: &str, creation_timestamp: i64) -> IngressClass {
        let mut class = IngressClass::new_default(name);
        class.creation_timestamp = creation_timestamp;
        class
    }

    fn create_non_default_class(name: &str) -> IngressClass {
        IngressClass::new(name)
    }

    fn create_class_with_false_default(name: &str) -> IngressClass {
        let mut annotations = HashMap::new();
        annotations.insert(ANNOTATION_IS_DEFAULT_INGRESS_CLASS.to_string(), "false".to_string());
        IngressClass::with_annotations(name, annotations)
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Create));
        assert!(!plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_ingress_class_is_default() {
        let default_class = IngressClass::new_default("default");
        assert!(default_class.is_default());

        let non_default = IngressClass::new("nondefault");
        assert!(!non_default.is_default());

        let false_default = create_class_with_false_default("falsedefault");
        assert!(!false_default.is_default());
    }

    #[test]
    fn test_no_default_no_modification() {
        let lister = Arc::new(InMemoryIngressClassLister::new());
        lister.add_class(create_class_with_false_default("nondefault1"));
        lister.add_class(create_non_default_class("nondefault2"));

        let plugin = Plugin::with_lister(lister);

        let ingress = create_ingress("testing", None);
        let mut attrs = AttributesRecord::new(
            "testing",
            "testing",
            GroupVersionResource::new("networking.k8s.io", "v1", "ingresses"),
            "",
            Operation::Create,
            Some(Box::new(ingress)),
            None,
            GroupVersionKind::new("networking.k8s.io", "v1", "Ingress"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let ingress = attrs.get_object().unwrap().as_any().downcast_ref::<Ingress>().unwrap();
        assert!(ingress.spec.ingress_class_name.is_none());
    }

    #[test]
    fn test_one_default_sets_class() {
        let lister = Arc::new(InMemoryIngressClassLister::new());
        lister.add_class(create_default_class("default1", 0));
        lister.add_class(create_non_default_class("nondefault"));

        let plugin = Plugin::with_lister(lister);

        let ingress = create_ingress("testing", None);
        let mut attrs = AttributesRecord::new(
            "testing",
            "testing",
            GroupVersionResource::new("networking.k8s.io", "v1", "ingresses"),
            "",
            Operation::Create,
            Some(Box::new(ingress)),
            None,
            GroupVersionKind::new("networking.k8s.io", "v1", "Ingress"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let ingress = attrs.get_object().unwrap().as_any().downcast_ref::<Ingress>().unwrap();
        assert_eq!(ingress.spec.ingress_class_name, Some("default1".to_string()));
    }

    #[test]
    fn test_no_modification_when_class_field_set() {
        let lister = Arc::new(InMemoryIngressClassLister::new());
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let ingress = create_ingress("testing", Some("custom"));
        let mut attrs = AttributesRecord::new(
            "testing",
            "testing",
            GroupVersionResource::new("networking.k8s.io", "v1", "ingresses"),
            "",
            Operation::Create,
            Some(Box::new(ingress)),
            None,
            GroupVersionKind::new("networking.k8s.io", "v1", "Ingress"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let ingress = attrs.get_object().unwrap().as_any().downcast_ref::<Ingress>().unwrap();
        assert_eq!(ingress.spec.ingress_class_name, Some("custom".to_string()));
    }

    #[test]
    fn test_no_modification_when_class_field_empty() {
        let lister = Arc::new(InMemoryIngressClassLister::new());
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let ingress = create_ingress("testing", Some(""));
        let mut attrs = AttributesRecord::new(
            "testing",
            "testing",
            GroupVersionResource::new("networking.k8s.io", "v1", "ingresses"),
            "",
            Operation::Create,
            Some(Box::new(ingress)),
            None,
            GroupVersionKind::new("networking.k8s.io", "v1", "Ingress"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let ingress = attrs.get_object().unwrap().as_any().downcast_ref::<Ingress>().unwrap();
        // Empty string is still "set", so no modification
        assert_eq!(ingress.spec.ingress_class_name, Some("".to_string()));
    }

    #[test]
    fn test_no_modification_when_annotation_set() {
        let lister = Arc::new(InMemoryIngressClassLister::new());
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let ingress = create_ingress_with_annotation("testing", "custom");
        let mut attrs = AttributesRecord::new(
            "testing",
            "testing",
            GroupVersionResource::new("networking.k8s.io", "v1", "ingresses"),
            "",
            Operation::Create,
            Some(Box::new(ingress)),
            None,
            GroupVersionKind::new("networking.k8s.io", "v1", "Ingress"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let ingress = attrs.get_object().unwrap().as_any().downcast_ref::<Ingress>().unwrap();
        assert!(ingress.spec.ingress_class_name.is_none());
    }

    #[test]
    fn test_two_defaults_same_time_choose_lower_name() {
        let lister = Arc::new(InMemoryIngressClassLister::new());
        // Both have same creation timestamp (0)
        lister.add_class(create_default_class("default2", 0));
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let ingress = create_ingress("testing", None);
        let mut attrs = AttributesRecord::new(
            "testing",
            "testing",
            GroupVersionResource::new("networking.k8s.io", "v1", "ingresses"),
            "",
            Operation::Create,
            Some(Box::new(ingress)),
            None,
            GroupVersionKind::new("networking.k8s.io", "v1", "Ingress"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let ingress = attrs.get_object().unwrap().as_any().downcast_ref::<Ingress>().unwrap();
        // Should choose "default1" as it's lexicographically smaller
        assert_eq!(ingress.spec.ingress_class_name, Some("default1".to_string()));
    }

    #[test]
    fn test_two_defaults_choose_newer() {
        let lister = Arc::new(InMemoryIngressClassLister::new());
        // default2 has older timestamp (100), default1 has newer timestamp (200)
        lister.add_class(create_default_class("default2", 100));
        lister.add_class(create_default_class("default1", 200));

        let plugin = Plugin::with_lister(lister);

        let ingress = create_ingress("testing", None);
        let mut attrs = AttributesRecord::new(
            "testing",
            "testing",
            GroupVersionResource::new("networking.k8s.io", "v1", "ingresses"),
            "",
            Operation::Create,
            Some(Box::new(ingress)),
            None,
            GroupVersionKind::new("networking.k8s.io", "v1", "Ingress"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let ingress = attrs.get_object().unwrap().as_any().downcast_ref::<Ingress>().unwrap();
        // Should choose "default1" as it has newer creation timestamp
        assert_eq!(ingress.spec.ingress_class_name, Some("default1".to_string()));
    }

    #[test]
    fn test_ignores_non_ingress_resources() {
        let lister = Arc::new(InMemoryIngressClassLister::new());
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        // Create a pod instead of ingress
        let pod = crate::api::core::Pod::new("test", "testing");
        let mut attrs = AttributesRecord::new(
            "test",
            "testing",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        // Should return Ok without any modifications
        plugin.admit(&mut attrs).unwrap();
    }

    #[test]
    fn test_ignores_subresources() {
        let lister = Arc::new(InMemoryIngressClassLister::new());
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let ingress = create_ingress("testing", None);
        let mut attrs = AttributesRecord::new(
            "testing",
            "testing",
            GroupVersionResource::new("networking.k8s.io", "v1", "ingresses"),
            "status", // subresource
            Operation::Create,
            Some(Box::new(ingress)),
            None,
            GroupVersionKind::new("networking.k8s.io", "v1", "Ingress"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let ingress = attrs.get_object().unwrap().as_any().downcast_ref::<Ingress>().unwrap();
        // Should not set default because it's a subresource
        assert!(ingress.spec.ingress_class_name.is_none());
    }
}
