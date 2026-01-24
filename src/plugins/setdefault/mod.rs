// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! DefaultStorageClass admission controller.
//!
//! This admission controller sets the default StorageClass on PersistentVolumeClaim
//! objects that don't have a StorageClassName specified. It looks for StorageClass
//! objects with the annotation "storageclass.kubernetes.io/is-default-class=true".

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation,
    Plugins,
};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

pub const PLUGIN_NAME: &str = "DefaultStorageClass";

/// Annotation key for marking a StorageClass as default.
pub const ANNOTATION_IS_DEFAULT_STORAGE_CLASS: &str = "storageclass.kubernetes.io/is-default-class";

pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// StorageClass represents a storage class resource.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageClass {
    /// Name of the StorageClass.
    pub name: String,
    /// Annotations on the StorageClass.
    pub annotations: HashMap<String, String>,
    /// Provisioner indicates the type of the provisioner.
    pub provisioner: String,
    /// Creation timestamp (nanoseconds since epoch for sorting).
    pub creation_timestamp: i64,
}

impl StorageClass {
    /// Create a new StorageClass.
    pub fn new(name: &str, provisioner: &str) -> Self {
        Self {
            name: name.to_string(),
            annotations: HashMap::new(),
            provisioner: provisioner.to_string(),
            creation_timestamp: 0,
        }
    }

    /// Create a new default StorageClass.
    pub fn new_default(name: &str, provisioner: &str) -> Self {
        let mut annotations = HashMap::new();
        annotations.insert(ANNOTATION_IS_DEFAULT_STORAGE_CLASS.to_string(), "true".to_string());
        Self {
            name: name.to_string(),
            annotations,
            provisioner: provisioner.to_string(),
            creation_timestamp: 0,
        }
    }

    /// Check if this StorageClass is marked as default.
    pub fn is_default(&self) -> bool {
        self.annotations
            .get(ANNOTATION_IS_DEFAULT_STORAGE_CLASS)
            .map(|v| v == "true")
            .unwrap_or(false)
    }
}

/// PersistentVolumeClaimSpec represents the specification of a PVC.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PersistentVolumeClaimSpec {
    /// StorageClassName is the name of the StorageClass required by the claim.
    pub storage_class_name: Option<String>,
    /// Resources represents the minimum resources the volume should have.
    pub resources: HashMap<String, String>,
}

/// PersistentVolumeClaim represents a Kubernetes PVC.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistentVolumeClaim {
    /// Name of the PVC.
    pub name: String,
    /// Namespace of the PVC.
    pub namespace: String,
    /// Spec is the desired state of the PVC.
    pub spec: PersistentVolumeClaimSpec,
}

impl PersistentVolumeClaim {
    /// Create a new PVC.
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            spec: PersistentVolumeClaimSpec::default(),
        }
    }

    /// Check if the PVC has a storage class set.
    pub fn has_storage_class(&self) -> bool {
        self.spec.storage_class_name.is_some()
    }
}

impl crate::api::core::ApiObject for PersistentVolumeClaim {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "PersistentVolumeClaim"
    }
}

/// Trait for listing StorageClass objects.
pub trait StorageClassLister: Send + Sync {
    /// List all StorageClass objects.
    fn list(&self) -> Vec<StorageClass>;
}

/// In-memory implementation of StorageClassLister for testing.
pub struct InMemoryStorageClassLister {
    classes: RwLock<Vec<StorageClass>>,
}

impl InMemoryStorageClassLister {
    pub fn new() -> Self {
        Self {
            classes: RwLock::new(Vec::new()),
        }
    }

    pub fn add_class(&self, class: StorageClass) {
        let mut classes = self.classes.write().unwrap();
        classes.push(class);
    }
}

impl Default for InMemoryStorageClassLister {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageClassLister for InMemoryStorageClassLister {
    fn list(&self) -> Vec<StorageClass> {
        let classes = self.classes.read().unwrap();
        classes.clone()
    }
}

pub struct Plugin {
    handler: Handler,
    /// Lister for StorageClass objects.
    lister: Option<Arc<dyn StorageClassLister>>,
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

    /// Set the StorageClass lister and mark the plugin as ready.
    pub fn set_lister(&mut self, lister: Arc<dyn StorageClassLister>) {
        self.lister = Some(lister);
        self.ready = true;
    }

    /// Create a plugin with a lister already set.
    pub fn with_lister(lister: Arc<dyn StorageClassLister>) -> Self {
        let mut plugin = Self::new();
        plugin.set_lister(lister);
        plugin
    }

    /// Get the default StorageClass from the lister.
    /// If multiple defaults exist, choose the newest (by creation timestamp),
    /// then by name (lexicographically smaller) as a tie-breaker.
    fn get_default_class(&self) -> AdmissionResult<Option<StorageClass>> {
        let lister = match &self.lister {
            Some(l) => l,
            None => return Ok(None),
        };

        let classes = lister.list();
        let mut default_classes: Vec<StorageClass> = classes
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
        if resource.resource != "persistentvolumeclaims" {
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

        // Get the PVC object
        let pvc = match attributes
            .get_object_mut()
            .and_then(|obj| obj.as_any_mut().downcast_mut::<PersistentVolumeClaim>())
        {
            Some(p) => p,
            None => {
                // Can't convert, just return
                return Ok(());
            }
        };

        // If StorageClassName is already set, no need to set a default
        if pvc.has_storage_class() {
            return Ok(());
        }

        // Get the default class
        let default_class = self.get_default_class()?;

        // No default class specified, no need to set a default value
        if default_class.is_none() {
            return Ok(());
        }

        // Set the default class
        pvc.spec.storage_class_name = Some(default_class.unwrap().name);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    fn create_pvc(name: &str, class_name: Option<&str>) -> PersistentVolumeClaim {
        let mut pvc = PersistentVolumeClaim::new(name, "ns");
        pvc.spec.storage_class_name = class_name.map(|s| s.to_string());
        pvc
    }

    fn create_default_class(name: &str, creation_timestamp: i64) -> StorageClass {
        let mut class = StorageClass::new_default(name, name);
        class.creation_timestamp = creation_timestamp;
        class
    }

    fn create_non_default_class(name: &str) -> StorageClass {
        StorageClass::new(name, name)
    }

    fn create_class_with_false_default(name: &str) -> StorageClass {
        let mut annotations = HashMap::new();
        annotations.insert(ANNOTATION_IS_DEFAULT_STORAGE_CLASS.to_string(), "false".to_string());
        StorageClass {
            name: name.to_string(),
            annotations,
            provisioner: name.to_string(),
            creation_timestamp: 0,
        }
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
    fn test_storage_class_is_default() {
        let default_class = StorageClass::new_default("default", "provisioner");
        assert!(default_class.is_default());

        let non_default = StorageClass::new("nondefault", "provisioner");
        assert!(!non_default.is_default());

        let false_default = create_class_with_false_default("falsedefault");
        assert!(!false_default.is_default());
    }

    #[test]
    fn test_no_default_no_modification() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(create_class_with_false_default("nondefault1"));
        lister.add_class(create_non_default_class("nondefault2"));

        let plugin = Plugin::with_lister(lister);

        let pvc = create_pvc("claimWithNoClass", None);
        let mut attrs = AttributesRecord::new(
            "claimWithNoClass",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let pvc = attrs.get_object().unwrap().as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        assert!(pvc.spec.storage_class_name.is_none());
    }

    #[test]
    fn test_one_default_sets_class() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(create_default_class("default1", 0));
        lister.add_class(create_non_default_class("nondefault"));

        let plugin = Plugin::with_lister(lister);

        let pvc = create_pvc("claimWithNoClass", None);
        let mut attrs = AttributesRecord::new(
            "claimWithNoClass",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let pvc = attrs.get_object().unwrap().as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        assert_eq!(pvc.spec.storage_class_name, Some("default1".to_string()));
    }

    #[test]
    fn test_no_modification_when_class_set() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let pvc = create_pvc("claimWithClass", Some("foo"));
        let mut attrs = AttributesRecord::new(
            "claimWithClass",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let pvc = attrs.get_object().unwrap().as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        assert_eq!(pvc.spec.storage_class_name, Some("foo".to_string()));
    }

    #[test]
    fn test_no_modification_when_class_empty() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let pvc = create_pvc("claimWithEmptyClass", Some(""));
        let mut attrs = AttributesRecord::new(
            "claimWithEmptyClass",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let pvc = attrs.get_object().unwrap().as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        // Empty string is still "set", so no modification
        assert_eq!(pvc.spec.storage_class_name, Some("".to_string()));
    }

    #[test]
    fn test_two_defaults_same_time_choose_lower_name() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(create_default_class("default2", 0));
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let pvc = create_pvc("claimWithNoClass", None);
        let mut attrs = AttributesRecord::new(
            "claimWithNoClass",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let pvc = attrs.get_object().unwrap().as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        assert_eq!(pvc.spec.storage_class_name, Some("default1".to_string()));
    }

    #[test]
    fn test_two_defaults_choose_newer() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(create_default_class("default2", 100));
        lister.add_class(create_default_class("default1", 200));

        let plugin = Plugin::with_lister(lister);

        let pvc = create_pvc("claimWithNoClass", None);
        let mut attrs = AttributesRecord::new(
            "claimWithNoClass",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let pvc = attrs.get_object().unwrap().as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        assert_eq!(pvc.spec.storage_class_name, Some("default1".to_string()));
    }

    #[test]
    fn test_ignores_non_pvc_resources() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let pod = crate::api::core::Pod::new("test", "ns");
        let mut attrs = AttributesRecord::new(
            "test",
            "ns",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Create,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();
    }

    #[test]
    fn test_ignores_subresources() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(create_default_class("default1", 0));

        let plugin = Plugin::with_lister(lister);

        let pvc = create_pvc("claimWithNoClass", None);
        let mut attrs = AttributesRecord::new(
            "claimWithNoClass",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "status",
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        plugin.admit(&mut attrs).unwrap();

        let pvc = attrs.get_object().unwrap().as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        assert!(pvc.spec.storage_class_name.is_none());
    }
}
