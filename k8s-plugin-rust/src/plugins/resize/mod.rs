// Copyright 2024 The Kubernetes Authors.
// Licensed under the Apache License, Version 2.0

//! PersistentVolumeClaimResize admission controller.
//!
//! This admission controller validates PVC resize requests. It ensures that:
//! 1. Only bound PVCs can be expanded
//! 2. The StorageClass must allow volume expansion (AllowVolumeExpansion=true)
//! 3. Both old and new PVC must reference the same StorageClass

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

pub const PLUGIN_NAME: &str = "PersistentVolumeClaimResize";

pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

// ============================================================================
// Quantity - represents a Kubernetes resource quantity
// ============================================================================

/// Quantity represents a Kubernetes resource quantity (e.g., "1Gi", "500Mi").
/// This is a simplified implementation that parses and compares storage quantities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quantity {
    /// The raw value in bytes (for storage quantities)
    value: i64,
}

impl Quantity {
    /// Parse a quantity string like "1Gi", "500Mi", "1000", etc.
    pub fn parse(s: &str) -> Option<Self> {
        if s.is_empty() {
            return Some(Quantity { value: 0 });
        }

        let s = s.trim();

        // Try to find where the number ends and the suffix begins
        let mut num_end = s.len();
        for (i, c) in s.char_indices() {
            if !c.is_ascii_digit() && c != '.' && c != '-' && c != '+' {
                num_end = i;
                break;
            }
        }

        let num_str = &s[..num_end];
        let suffix = &s[num_end..];

        // Parse the numeric part
        let num: f64 = num_str.parse().ok()?;

        // Apply the suffix multiplier
        let multiplier: f64 = match suffix {
            "" => 1.0,
            // Decimal SI suffixes
            "k" => 1000.0,
            "M" => 1000.0 * 1000.0,
            "G" => 1000.0 * 1000.0 * 1000.0,
            "T" => 1000.0 * 1000.0 * 1000.0 * 1000.0,
            "P" => 1000.0 * 1000.0 * 1000.0 * 1000.0 * 1000.0,
            "E" => 1000.0 * 1000.0 * 1000.0 * 1000.0 * 1000.0 * 1000.0,
            // Binary SI suffixes
            "Ki" => 1024.0,
            "Mi" => 1024.0 * 1024.0,
            "Gi" => 1024.0 * 1024.0 * 1024.0,
            "Ti" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
            "Pi" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
            "Ei" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
            _ => return None,
        };

        Some(Quantity {
            value: (num * multiplier) as i64,
        })
    }

    /// Compare two quantities. Returns:
    /// - negative if self < other
    /// - zero if self == other
    /// - positive if self > other
    pub fn cmp(&self, other: &Quantity) -> i64 {
        self.value - other.value
    }
}

impl Default for Quantity {
    fn default() -> Self {
        Quantity { value: 0 }
    }
}

// ============================================================================
// PersistentVolumeClaim types
// ============================================================================

/// PersistentVolumeClaimPhase represents the phase of a PVC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistentVolumeClaimPhase {
    /// Pending means the PVC is not yet bound to a PV.
    Pending,
    /// Bound means the PVC is bound to a PV.
    Bound,
    /// Lost means the PVC lost its underlying PV.
    Lost,
}

impl Default for PersistentVolumeClaimPhase {
    fn default() -> Self {
        PersistentVolumeClaimPhase::Pending
    }
}

/// Resource name for storage.
pub const RESOURCE_STORAGE: &str = "storage";

/// VolumeResourceRequirements represents resource requirements for a volume.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VolumeResourceRequirements {
    /// Requests describes the minimum amount of storage required.
    pub requests: HashMap<String, String>,
}

impl VolumeResourceRequirements {
    /// Get the storage request as a Quantity.
    pub fn get_storage(&self) -> Quantity {
        self.requests
            .get(RESOURCE_STORAGE)
            .and_then(|s| Quantity::parse(s))
            .unwrap_or_default()
    }
}

/// PersistentVolumeClaimSpec represents the specification of a PVC.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PersistentVolumeClaimSpec {
    /// StorageClassName is the name of the StorageClass required by the claim.
    pub storage_class_name: Option<String>,
    /// VolumeName is the binding reference to the PersistentVolume.
    pub volume_name: Option<String>,
    /// Resources represents the minimum resources the volume should have.
    pub resources: VolumeResourceRequirements,
}

/// PersistentVolumeClaimStatus represents the status of a PVC.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PersistentVolumeClaimStatus {
    /// Phase represents the current phase of the claim.
    pub phase: PersistentVolumeClaimPhase,
    /// Capacity represents the actual resources of the underlying volume.
    pub capacity: HashMap<String, String>,
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
    /// Status is the current state of the PVC.
    pub status: PersistentVolumeClaimStatus,
}

impl PersistentVolumeClaim {
    /// Create a new PVC.
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            spec: PersistentVolumeClaimSpec::default(),
            status: PersistentVolumeClaimStatus::default(),
        }
    }

    /// Get the storage class name for this PVC.
    /// This mirrors the Go helper function GetPersistentVolumeClaimClass.
    pub fn get_storage_class(&self) -> Option<&str> {
        self.spec.storage_class_name.as_deref()
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

// ============================================================================
// StorageClass types
// ============================================================================

/// StorageClass represents a storage class resource.
#[derive(Debug, Clone, PartialEq)]
pub struct StorageClass {
    /// Name of the StorageClass.
    pub name: String,
    /// Provisioner indicates the type of the provisioner.
    pub provisioner: String,
    /// AllowVolumeExpansion indicates whether the storage class allows volume expansion.
    pub allow_volume_expansion: Option<bool>,
}

impl StorageClass {
    /// Create a new StorageClass.
    pub fn new(name: &str, provisioner: &str) -> Self {
        Self {
            name: name.to_string(),
            provisioner: provisioner.to_string(),
            allow_volume_expansion: None,
        }
    }

    /// Create a new StorageClass with volume expansion setting.
    pub fn with_expansion(name: &str, provisioner: &str, allow_expansion: bool) -> Self {
        Self {
            name: name.to_string(),
            provisioner: provisioner.to_string(),
            allow_volume_expansion: Some(allow_expansion),
        }
    }

    /// Check if this StorageClass allows volume expansion.
    pub fn allows_expansion(&self) -> bool {
        self.allow_volume_expansion.unwrap_or(false)
    }
}

// ============================================================================
// StorageClass Lister
// ============================================================================

/// Trait for getting StorageClass objects by name.
pub trait StorageClassLister: Send + Sync {
    /// Get a StorageClass by name.
    fn get(&self, name: &str) -> Option<StorageClass>;
}

/// In-memory implementation of StorageClassLister for testing.
pub struct InMemoryStorageClassLister {
    classes: RwLock<HashMap<String, StorageClass>>,
}

impl InMemoryStorageClassLister {
    pub fn new() -> Self {
        Self {
            classes: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_class(&self, class: StorageClass) {
        let mut classes = self.classes.write().unwrap();
        classes.insert(class.name.clone(), class);
    }
}

impl Default for InMemoryStorageClassLister {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageClassLister for InMemoryStorageClassLister {
    fn get(&self, name: &str) -> Option<StorageClass> {
        let classes = self.classes.read().unwrap();
        classes.get(name).cloned()
    }
}

// ============================================================================
// Plugin Implementation
// ============================================================================

pub struct Plugin {
    handler: Handler,
    /// Lister for StorageClass objects.
    sc_lister: Option<Arc<dyn StorageClassLister>>,
    /// Whether the plugin is ready.
    ready: bool,
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Update]),
            sc_lister: None,
            ready: false,
        }
    }

    /// Set the StorageClass lister and mark the plugin as ready.
    pub fn set_lister(&mut self, lister: Arc<dyn StorageClassLister>) {
        self.sc_lister = Some(lister);
        self.ready = true;
    }

    /// Create a plugin with a lister already set.
    pub fn with_lister(lister: Arc<dyn StorageClassLister>) -> Self {
        let mut plugin = Self::new();
        plugin.set_lister(lister);
        plugin
    }

    /// Check if resize is allowed for the given PVC.
    /// Growing Persistent volumes is only allowed for PVCs for which their StorageClass
    /// explicitly allows it.
    fn allow_resize(&self, pvc: &PersistentVolumeClaim, old_pvc: &PersistentVolumeClaim) -> bool {
        let pvc_storage_class = pvc.get_storage_class();
        let old_pvc_storage_class = old_pvc.get_storage_class();

        // Both must have a storage class, and they must be the same
        match (pvc_storage_class, old_pvc_storage_class) {
            (Some(new_class), Some(old_class)) if !new_class.is_empty() && !old_class.is_empty() => {
                if new_class != old_class {
                    return false;
                }

                // Look up the storage class
                if let Some(ref lister) = self.sc_lister {
                    if let Some(sc) = lister.get(new_class) {
                        return sc.allows_expansion();
                    }
                }
                false
            }
            _ => false,
        }
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

        // Only handle persistentvolumeclaims
        if resource.resource != "persistentvolumeclaims" {
            return Ok(());
        }

        // Ignore subresources
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        // Get the new PVC object
        let pvc = match attributes
            .get_object()
            .and_then(|obj| obj.as_any().downcast_ref::<PersistentVolumeClaim>())
        {
            Some(p) => p,
            None => {
                // Can't convert, just return
                return Ok(());
            }
        };

        // Get the old PVC object
        let old_pvc = match attributes
            .get_old_object()
            .and_then(|obj| obj.as_any().downcast_ref::<PersistentVolumeClaim>())
        {
            Some(p) => p,
            None => {
                // Can't convert, just return
                return Ok(());
            }
        };

        // Compare sizes
        let old_size = old_pvc.spec.resources.get_storage();
        let new_size = pvc.spec.resources.get_storage();

        // If size is not increasing, allow the update
        if new_size.cmp(&old_size) <= 0 {
            return Ok(());
        }

        // Only bound PVCs can be expanded
        if old_pvc.status.phase != PersistentVolumeClaimPhase::Bound {
            return Err(AdmissionError::BadRequest(
                "Only bound persistent volume claims can be expanded".to_string(),
            ));
        }

        // Check if the StorageClass allows resize
        if !self.allow_resize(pvc, old_pvc) {
            return Err(AdmissionError::BadRequest(
                "only dynamically provisioned pvc can be resized and the storageclass that provisions the pvc must support resize".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    fn get_resource_list(storage: &str) -> HashMap<String, String> {
        let mut res = HashMap::new();
        if !storage.is_empty() {
            res.insert(RESOURCE_STORAGE.to_string(), storage.to_string());
        }
        res
    }

    fn create_pvc(
        name: &str,
        volume_name: Option<&str>,
        storage_class: Option<&str>,
        storage_request: &str,
        phase: PersistentVolumeClaimPhase,
    ) -> PersistentVolumeClaim {
        PersistentVolumeClaim {
            name: name.to_string(),
            namespace: "default".to_string(),
            spec: PersistentVolumeClaimSpec {
                storage_class_name: storage_class.map(|s| s.to_string()),
                volume_name: volume_name.map(|s| s.to_string()),
                resources: VolumeResourceRequirements {
                    requests: get_resource_list(storage_request),
                },
            },
            status: PersistentVolumeClaimStatus {
                phase,
                capacity: get_resource_list(storage_request),
            },
        }
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Create));
        assert!(!plugin.handles(Operation::Delete));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_quantity_parsing() {
        // Test various quantity formats
        assert_eq!(Quantity::parse("1Gi").unwrap().value, 1024 * 1024 * 1024);
        assert_eq!(Quantity::parse("2Gi").unwrap().value, 2 * 1024 * 1024 * 1024);
        assert_eq!(Quantity::parse("500Mi").unwrap().value, 500 * 1024 * 1024);
        assert_eq!(Quantity::parse("1G").unwrap().value, 1000 * 1000 * 1000);
        assert_eq!(Quantity::parse("0Gi").unwrap().value, 0);
        assert_eq!(Quantity::parse("").unwrap().value, 0);
    }

    #[test]
    fn test_quantity_comparison() {
        let q1 = Quantity::parse("1Gi").unwrap();
        let q2 = Quantity::parse("2Gi").unwrap();
        let q3 = Quantity::parse("1Gi").unwrap();

        assert!(q1.cmp(&q2) < 0);
        assert!(q2.cmp(&q1) > 0);
        assert_eq!(q1.cmp(&q3), 0);
    }

    #[test]
    fn test_storage_class_allows_expansion() {
        let sc_with_expansion = StorageClass::with_expansion("gold", "provisioner", true);
        assert!(sc_with_expansion.allows_expansion());

        let sc_without_expansion = StorageClass::with_expansion("silver", "provisioner", false);
        assert!(!sc_without_expansion.allows_expansion());

        let sc_default = StorageClass::new("bronze", "provisioner");
        assert!(!sc_default.allows_expansion());
    }

    #[test]
    fn test_pvc_resize_allowed() {
        // Setup: Create storage classes
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(StorageClass::with_expansion("gold", "kubernetes.io/glusterfs", true));
        lister.add_class(StorageClass::with_expansion("silver", "kubernetes.io/glusterfs", false));

        let plugin = Plugin::with_lister(lister);

        // Test case 1: Resize with gold class (expansion allowed) - should succeed
        let old_pvc = create_pvc("pvc1", Some("volume1"), Some("gold"), "1Gi", PersistentVolumeClaimPhase::Bound);
        let new_pvc = create_pvc("pvc1", Some("volume1"), Some("gold"), "2Gi", PersistentVolumeClaimPhase::Bound);

        let attrs = AttributesRecord::new(
            "pvc1",
            "default",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Update,
            Some(Box::new(new_pvc)),
            Some(Box::new(old_pvc)),
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected resize to be allowed with gold class");
    }

    #[test]
    fn test_pvc_resize_no_storage_class() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(StorageClass::with_expansion("gold", "kubernetes.io/glusterfs", true));

        let plugin = Plugin::with_lister(lister);

        // PVC without storage class - should fail
        let old_pvc = create_pvc("pvc3", Some("volume3"), None, "1Gi", PersistentVolumeClaimPhase::Bound);
        let new_pvc = create_pvc("pvc3", Some("volume3"), None, "2Gi", PersistentVolumeClaimPhase::Bound);

        let attrs = AttributesRecord::new(
            "pvc3",
            "default",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Update,
            Some(Box::new(new_pvc)),
            Some(Box::new(old_pvc)),
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("only dynamically provisioned pvc can be resized"));
    }

    #[test]
    fn test_pvc_resize_storage_class_disallows() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(StorageClass::with_expansion("silver", "kubernetes.io/glusterfs", false));

        let plugin = Plugin::with_lister(lister);

        // PVC with silver class (expansion not allowed) - should fail
        let old_pvc = create_pvc("pvc4", Some("volume4"), Some("silver"), "1Gi", PersistentVolumeClaimPhase::Bound);
        let new_pvc = create_pvc("pvc4", Some("volume4"), Some("silver"), "2Gi", PersistentVolumeClaimPhase::Bound);

        let attrs = AttributesRecord::new(
            "pvc4",
            "default",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Update,
            Some(Box::new(new_pvc)),
            Some(Box::new(old_pvc)),
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("only dynamically provisioned pvc can be resized"));
    }

    #[test]
    fn test_pvc_no_size_change_allowed() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(StorageClass::with_expansion("silver", "kubernetes.io/glusterfs", false));

        let plugin = Plugin::with_lister(lister);

        // No change in size - should succeed even with non-expandable class
        let old_pvc = create_pvc("pvc5", None, Some("silver"), "1Gi", PersistentVolumeClaimPhase::Pending);
        let mut new_pvc = create_pvc("pvc5", Some("volume4"), Some("silver"), "1Gi", PersistentVolumeClaimPhase::Bound);
        new_pvc.status.capacity = get_resource_list("1Gi");

        let attrs = AttributesRecord::new(
            "pvc5",
            "default",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Update,
            Some(Box::new(new_pvc)),
            Some(Box::new(old_pvc)),
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected no-size-change update to be allowed");
    }

    #[test]
    fn test_pvc_resize_pending_state() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(StorageClass::with_expansion("silver", "kubernetes.io/glusterfs", false));

        let plugin = Plugin::with_lister(lister);

        // Expand PVC in pending state - should fail
        let old_pvc = create_pvc("pvc6", None, Some("silver"), "1Gi", PersistentVolumeClaimPhase::Pending);
        let new_pvc = create_pvc("pvc6", None, Some("silver"), "2Gi", PersistentVolumeClaimPhase::Pending);

        let attrs = AttributesRecord::new(
            "pvc6",
            "default",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Update,
            Some(Box::new(new_pvc)),
            Some(Box::new(old_pvc)),
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Only bound persistent volume claims can be expanded"));
    }

    #[test]
    fn test_ignores_non_pvc_resources() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        let plugin = Plugin::with_lister(lister);

        // Create a pod instead of PVC
        let pod = crate::api::core::Pod::new("test", "default");
        let attrs = AttributesRecord::new(
            "test",
            "default",
            GroupVersionResource::new("", "v1", "pods"),
            "",
            Operation::Update,
            Some(Box::new(pod)),
            None,
            GroupVersionKind::new("", "v1", "Pod"),
            false,
        );

        // Should return Ok without any validation
        let result = plugin.validate(&attrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ignores_subresources() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(StorageClass::with_expansion("gold", "kubernetes.io/glusterfs", true));

        let plugin = Plugin::with_lister(lister);

        // Status subresource update - should be ignored
        let old_pvc = create_pvc("pvc7", Some("volume1"), Some("gold"), "1Gi", PersistentVolumeClaimPhase::Bound);
        let new_pvc = create_pvc("pvc7", Some("volume1"), Some("gold"), "2Gi", PersistentVolumeClaimPhase::Bound);

        let attrs = AttributesRecord::new(
            "pvc7",
            "default",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "status", // subresource
            Operation::Update,
            Some(Box::new(new_pvc)),
            Some(Box::new(old_pvc)),
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected subresource update to be ignored");
    }

    #[test]
    fn test_size_decrease_allowed() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        // Even without expansion support, size decrease should be allowed (validation only checks increases)
        lister.add_class(StorageClass::with_expansion("silver", "kubernetes.io/glusterfs", false));

        let plugin = Plugin::with_lister(lister);

        // Size decrease - should be allowed (not checked by this plugin)
        let old_pvc = create_pvc("pvc8", Some("volume1"), Some("silver"), "2Gi", PersistentVolumeClaimPhase::Bound);
        let new_pvc = create_pvc("pvc8", Some("volume1"), Some("silver"), "1Gi", PersistentVolumeClaimPhase::Bound);

        let attrs = AttributesRecord::new(
            "pvc8",
            "default",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Update,
            Some(Box::new(new_pvc)),
            Some(Box::new(old_pvc)),
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_ok(), "Expected size decrease to be allowed (not validated by this plugin)");
    }

    #[test]
    fn test_storage_class_mismatch() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        lister.add_class(StorageClass::with_expansion("gold", "kubernetes.io/glusterfs", true));
        lister.add_class(StorageClass::with_expansion("silver", "kubernetes.io/glusterfs", true));

        let plugin = Plugin::with_lister(lister);

        // Different storage classes between old and new - should fail
        let old_pvc = create_pvc("pvc9", Some("volume1"), Some("gold"), "1Gi", PersistentVolumeClaimPhase::Bound);
        let new_pvc = create_pvc("pvc9", Some("volume1"), Some("silver"), "2Gi", PersistentVolumeClaimPhase::Bound);

        let attrs = AttributesRecord::new(
            "pvc9",
            "default",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Update,
            Some(Box::new(new_pvc)),
            Some(Box::new(old_pvc)),
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("only dynamically provisioned pvc can be resized"));
    }

    #[test]
    fn test_storage_class_not_found() {
        let lister = Arc::new(InMemoryStorageClassLister::new());
        // Don't add the storage class - simulate it not existing

        let plugin = Plugin::with_lister(lister);

        // Storage class doesn't exist - should fail
        let old_pvc = create_pvc("pvc10", Some("volume1"), Some("nonexistent"), "1Gi", PersistentVolumeClaimPhase::Bound);
        let new_pvc = create_pvc("pvc10", Some("volume1"), Some("nonexistent"), "2Gi", PersistentVolumeClaimPhase::Bound);

        let attrs = AttributesRecord::new(
            "pvc10",
            "default",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Update,
            Some(Box::new(new_pvc)),
            Some(Box::new(old_pvc)),
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.validate(&attrs);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("only dynamically provisioned pvc can be resized"));
    }
}
