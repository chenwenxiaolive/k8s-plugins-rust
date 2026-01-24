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

//! StorageObjectInUseProtection admission controller.
//!
//! This admission controller sets finalizers on PersistentVolumes (PVs),
//! PersistentVolumeClaims (PVCs), and VolumeAttributesClasses (VACs) during creation.
//! The finalizers are removed by respective protection controllers when the objects
//! are no longer referenced.
//!
//! This prevents:
//! - Users from deleting a PVC that's used by a running pod
//! - Admins from deleting a PV that's bound by a PVC
//! - Deletion of VACs that are in use (when VolumeAttributesClass feature is enabled)

use crate::admission::{
    AdmissionResult, Attributes, Handler, Interface, MutationInterface, Operation, Plugins,
};
use crate::api::core::ApiObject;
use std::any::Any;
use std::io::Read;
use std::sync::Arc;

/// Plugin name for the StorageObjectInUseProtection admission controller.
pub const PLUGIN_NAME: &str = "StorageObjectInUseProtection";

/// Finalizer for PersistentVolume protection.
pub const PV_PROTECTION_FINALIZER: &str = "kubernetes.io/pv-protection";

/// Finalizer for PersistentVolumeClaim protection.
pub const PVC_PROTECTION_FINALIZER: &str = "kubernetes.io/pvc-protection";

/// Finalizer for VolumeAttributesClass protection.
pub const VAC_PROTECTION_FINALIZER: &str = "kubernetes.io/vac-protection";

// ============================================================================
// Storage Types
// ============================================================================

/// ObjectMeta contains metadata for Kubernetes objects.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ObjectMeta {
    /// Name of the object.
    pub name: String,
    /// Namespace of the object.
    pub namespace: String,
    /// Finalizers are values that must be cleared before the object is deleted.
    pub finalizers: Vec<String>,
}

/// PersistentVolume represents a storage resource in the cluster.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistentVolume {
    /// Object metadata.
    pub metadata: ObjectMeta,
}

impl PersistentVolume {
    /// Create a new PersistentVolume with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: String::new(),
                finalizers: Vec::new(),
            },
        }
    }

    /// Create a new PersistentVolume with existing finalizers.
    pub fn with_finalizers(name: &str, finalizers: Vec<String>) -> Self {
        Self {
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: String::new(),
                finalizers,
            },
        }
    }

    /// Check if the PV has a specific finalizer.
    pub fn has_finalizer(&self, finalizer: &str) -> bool {
        self.metadata.finalizers.iter().any(|f| f == finalizer)
    }

    /// Add a finalizer if it doesn't already exist.
    pub fn add_finalizer(&mut self, finalizer: &str) {
        if !self.has_finalizer(finalizer) {
            self.metadata.finalizers.push(finalizer.to_string());
        }
    }
}

impl ApiObject for PersistentVolume {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "PersistentVolume"
    }
}

/// PersistentVolumeClaim represents a user's request for storage.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistentVolumeClaim {
    /// Object metadata.
    pub metadata: ObjectMeta,
}

impl PersistentVolumeClaim {
    /// Create a new PersistentVolumeClaim with the given name and namespace.
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: namespace.to_string(),
                finalizers: Vec::new(),
            },
        }
    }

    /// Create a new PersistentVolumeClaim with existing finalizers.
    pub fn with_finalizers(name: &str, namespace: &str, finalizers: Vec<String>) -> Self {
        Self {
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: namespace.to_string(),
                finalizers,
            },
        }
    }

    /// Check if the PVC has a specific finalizer.
    pub fn has_finalizer(&self, finalizer: &str) -> bool {
        self.metadata.finalizers.iter().any(|f| f == finalizer)
    }

    /// Add a finalizer if it doesn't already exist.
    pub fn add_finalizer(&mut self, finalizer: &str) {
        if !self.has_finalizer(finalizer) {
            self.metadata.finalizers.push(finalizer.to_string());
        }
    }
}

impl ApiObject for PersistentVolumeClaim {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "PersistentVolumeClaim"
    }
}

/// VolumeAttributesClass represents a class of volume attributes.
#[derive(Debug, Clone, PartialEq)]
pub struct VolumeAttributesClass {
    /// Object metadata.
    pub metadata: ObjectMeta,
    /// DriverName is the name of the CSI driver.
    pub driver_name: String,
}

impl VolumeAttributesClass {
    /// Create a new VolumeAttributesClass with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: String::new(),
                finalizers: Vec::new(),
            },
            driver_name: String::new(),
        }
    }

    /// Create a new VolumeAttributesClass with existing finalizers.
    pub fn with_finalizers(name: &str, finalizers: Vec<String>) -> Self {
        Self {
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: String::new(),
                finalizers,
            },
            driver_name: String::new(),
        }
    }

    /// Check if the VAC has a specific finalizer.
    pub fn has_finalizer(&self, finalizer: &str) -> bool {
        self.metadata.finalizers.iter().any(|f| f == finalizer)
    }

    /// Add a finalizer if it doesn't already exist.
    pub fn add_finalizer(&mut self, finalizer: &str) {
        if !self.has_finalizer(finalizer) {
            self.metadata.finalizers.push(finalizer.to_string());
        }
    }
}

impl ApiObject for VolumeAttributesClass {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn kind(&self) -> &str {
        "VolumeAttributesClass"
    }
}

// ============================================================================
// Plugin Implementation
// ============================================================================

/// Register the StorageObjectInUseProtection plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// StorageObjectInUseProtection admission plugin.
///
/// This plugin adds protection finalizers to PVs, PVCs, and VACs during creation.
/// The finalizers prevent deletion of storage objects while they are in use.
pub struct Plugin {
    handler: Handler,
    /// Whether the VolumeAttributesClass feature gate is enabled.
    /// In production, this would check the actual feature gate.
    volume_attributes_class_enabled: bool,
}

impl Plugin {
    /// Create a new StorageObjectInUseProtection admission controller.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            volume_attributes_class_enabled: true, // Default to enabled
        }
    }

    /// Create a new plugin with specific feature gate settings.
    pub fn with_feature_gate(volume_attributes_class_enabled: bool) -> Self {
        Self {
            handler: Handler::new(&[Operation::Create]),
            volume_attributes_class_enabled,
        }
    }

    /// Admit a PersistentVolume, adding the protection finalizer.
    fn admit_pv(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Skip subresource requests
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        let obj = match attributes.get_object_mut() {
            Some(o) => o,
            None => return Ok(()),
        };

        let pv = match obj.as_any_mut().downcast_mut::<PersistentVolume>() {
            Some(p) => p,
            None => return Ok(()), // Can't convert, just return
        };

        // Check if finalizer already exists
        if pv.has_finalizer(PV_PROTECTION_FINALIZER) {
            return Ok(());
        }

        // Add the protection finalizer
        pv.add_finalizer(PV_PROTECTION_FINALIZER);

        Ok(())
    }

    /// Admit a PersistentVolumeClaim, adding the protection finalizer.
    fn admit_pvc(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Skip subresource requests
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        let obj = match attributes.get_object_mut() {
            Some(o) => o,
            None => return Ok(()),
        };

        let pvc = match obj.as_any_mut().downcast_mut::<PersistentVolumeClaim>() {
            Some(p) => p,
            None => return Ok(()), // Can't convert, just return
        };

        // Check if finalizer already exists
        if pvc.has_finalizer(PVC_PROTECTION_FINALIZER) {
            return Ok(());
        }

        // Add the protection finalizer
        pvc.add_finalizer(PVC_PROTECTION_FINALIZER);

        Ok(())
    }

    /// Admit a VolumeAttributesClass, adding the protection finalizer.
    fn admit_vac(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        // Skip subresource requests
        if !attributes.get_subresource().is_empty() {
            return Ok(());
        }

        let obj = match attributes.get_object_mut() {
            Some(o) => o,
            None => return Ok(()),
        };

        let vac = match obj.as_any_mut().downcast_mut::<VolumeAttributesClass>() {
            Some(v) => v,
            None => return Ok(()), // Can't convert, just return
        };

        // Check if finalizer already exists
        if vac.has_finalizer(VAC_PROTECTION_FINALIZER) {
            return Ok(());
        }

        // Add the protection finalizer
        vac.add_finalizer(VAC_PROTECTION_FINALIZER);

        Ok(())
    }
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for Plugin {
    /// Handles returns true for Create operations only.
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl MutationInterface for Plugin {
    /// Admit adds protection finalizers to PVs, PVCs, and VACs.
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()> {
        let resource = attributes.get_resource();
        let group_resource = resource.group_resource();

        // Handle PersistentVolumes (core API group)
        if group_resource.group.is_empty() && group_resource.resource == "persistentvolumes" {
            return self.admit_pv(attributes);
        }

        // Handle PersistentVolumeClaims (core API group)
        if group_resource.group.is_empty() && group_resource.resource == "persistentvolumeclaims" {
            return self.admit_pvc(attributes);
        }

        // Handle VolumeAttributesClasses (storage.k8s.io API group)
        if group_resource.group == "storage.k8s.io"
            && group_resource.resource == "volumeattributesclasses"
        {
            // Only process if the feature gate is enabled
            if self.volume_attributes_class_enabled {
                return self.admit_vac(attributes);
            }
            return Ok(());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};

    // ========================================================================
    // PersistentVolumeClaim Tests
    // ========================================================================

    #[test]
    fn test_pvc_create_adds_finalizer() {
        let plugin = Plugin::new();

        let pvc = PersistentVolumeClaim::new("claim", "ns");
        let mut attrs = AttributesRecord::new(
            "claim",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());

        let obj = attrs.get_object().unwrap();
        let pvc = obj.as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        assert_eq!(pvc.metadata.finalizers.len(), 1);
        assert_eq!(pvc.metadata.finalizers[0], PVC_PROTECTION_FINALIZER);
    }

    #[test]
    fn test_pvc_with_existing_finalizer_no_duplicate() {
        let plugin = Plugin::new();

        let pvc = PersistentVolumeClaim::with_finalizers(
            "claim",
            "ns",
            vec![PVC_PROTECTION_FINALIZER.to_string()],
        );
        let mut attrs = AttributesRecord::new(
            "claim",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "",
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let obj = attrs.get_object().unwrap();
        let pvc = obj.as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        assert_eq!(pvc.metadata.finalizers.len(), 1);
        assert_eq!(pvc.metadata.finalizers[0], PVC_PROTECTION_FINALIZER);
    }

    // ========================================================================
    // PersistentVolume Tests
    // ========================================================================

    #[test]
    fn test_pv_create_adds_finalizer() {
        let plugin = Plugin::new();

        let pv = PersistentVolume::new("pv");
        let mut attrs = AttributesRecord::new(
            "pv",
            "",
            GroupVersionResource::new("", "v1", "persistentvolumes"),
            "",
            Operation::Create,
            Some(Box::new(pv)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolume"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());

        let obj = attrs.get_object().unwrap();
        let pv = obj.as_any().downcast_ref::<PersistentVolume>().unwrap();
        assert_eq!(pv.metadata.finalizers.len(), 1);
        assert_eq!(pv.metadata.finalizers[0], PV_PROTECTION_FINALIZER);
    }

    #[test]
    fn test_pv_with_existing_finalizer_no_duplicate() {
        let plugin = Plugin::new();

        let pv =
            PersistentVolume::with_finalizers("pv", vec![PV_PROTECTION_FINALIZER.to_string()]);
        let mut attrs = AttributesRecord::new(
            "pv",
            "",
            GroupVersionResource::new("", "v1", "persistentvolumes"),
            "",
            Operation::Create,
            Some(Box::new(pv)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolume"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let obj = attrs.get_object().unwrap();
        let pv = obj.as_any().downcast_ref::<PersistentVolume>().unwrap();
        assert_eq!(pv.metadata.finalizers.len(), 1);
        assert_eq!(pv.metadata.finalizers[0], PV_PROTECTION_FINALIZER);
    }

    // ========================================================================
    // VolumeAttributesClass Tests
    // ========================================================================

    #[test]
    fn test_vac_feature_gate_disabled_no_finalizer() {
        let plugin = Plugin::with_feature_gate(false);

        let vac = VolumeAttributesClass::new("vac");
        let mut attrs = AttributesRecord::new(
            "vac",
            "",
            GroupVersionResource::new("storage.k8s.io", "v1beta1", "volumeattributesclasses"),
            "",
            Operation::Create,
            Some(Box::new(vac)),
            None,
            GroupVersionKind::new("storage.k8s.io", "v1beta1", "VolumeAttributesClass"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let obj = attrs.get_object().unwrap();
        let vac = obj
            .as_any()
            .downcast_ref::<VolumeAttributesClass>()
            .unwrap();
        assert!(
            vac.metadata.finalizers.is_empty(),
            "no finalizer should be added when feature gate is disabled"
        );
    }

    #[test]
    fn test_vac_feature_gate_disabled_existing_finalizer_unchanged() {
        let plugin = Plugin::with_feature_gate(false);

        let vac = VolumeAttributesClass::with_finalizers(
            "vac",
            vec![VAC_PROTECTION_FINALIZER.to_string()],
        );
        let mut attrs = AttributesRecord::new(
            "vac",
            "",
            GroupVersionResource::new("storage.k8s.io", "v1beta1", "volumeattributesclasses"),
            "",
            Operation::Create,
            Some(Box::new(vac)),
            None,
            GroupVersionKind::new("storage.k8s.io", "v1beta1", "VolumeAttributesClass"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let obj = attrs.get_object().unwrap();
        let vac = obj
            .as_any()
            .downcast_ref::<VolumeAttributesClass>()
            .unwrap();
        // Existing finalizer should remain unchanged
        assert_eq!(vac.metadata.finalizers.len(), 1);
        assert_eq!(vac.metadata.finalizers[0], VAC_PROTECTION_FINALIZER);
    }

    #[test]
    fn test_vac_feature_gate_enabled_adds_finalizer() {
        let plugin = Plugin::with_feature_gate(true);

        let vac = VolumeAttributesClass::new("vac");
        let mut attrs = AttributesRecord::new(
            "vac",
            "",
            GroupVersionResource::new("storage.k8s.io", "v1beta1", "volumeattributesclasses"),
            "",
            Operation::Create,
            Some(Box::new(vac)),
            None,
            GroupVersionKind::new("storage.k8s.io", "v1beta1", "VolumeAttributesClass"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());

        let obj = attrs.get_object().unwrap();
        let vac = obj
            .as_any()
            .downcast_ref::<VolumeAttributesClass>()
            .unwrap();
        assert_eq!(vac.metadata.finalizers.len(), 1);
        assert_eq!(vac.metadata.finalizers[0], VAC_PROTECTION_FINALIZER);
    }

    #[test]
    fn test_vac_feature_gate_enabled_existing_finalizer_no_duplicate() {
        let plugin = Plugin::with_feature_gate(true);

        let vac = VolumeAttributesClass::with_finalizers(
            "vac",
            vec![VAC_PROTECTION_FINALIZER.to_string()],
        );
        let mut attrs = AttributesRecord::new(
            "vac",
            "",
            GroupVersionResource::new("storage.k8s.io", "v1beta1", "volumeattributesclasses"),
            "",
            Operation::Create,
            Some(Box::new(vac)),
            None,
            GroupVersionKind::new("storage.k8s.io", "v1beta1", "VolumeAttributesClass"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let obj = attrs.get_object().unwrap();
        let vac = obj
            .as_any()
            .downcast_ref::<VolumeAttributesClass>()
            .unwrap();
        assert_eq!(vac.metadata.finalizers.len(), 1);
        assert_eq!(vac.metadata.finalizers[0], VAC_PROTECTION_FINALIZER);
    }

    // ========================================================================
    // Subresource Tests
    // ========================================================================

    #[test]
    fn test_pvc_subresource_ignored() {
        let plugin = Plugin::new();

        let pvc = PersistentVolumeClaim::new("claim", "ns");
        let mut attrs = AttributesRecord::new(
            "claim",
            "ns",
            GroupVersionResource::new("", "v1", "persistentvolumeclaims"),
            "status", // Subresource
            Operation::Create,
            Some(Box::new(pvc)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolumeClaim"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let obj = attrs.get_object().unwrap();
        let pvc = obj.as_any().downcast_ref::<PersistentVolumeClaim>().unwrap();
        assert!(
            pvc.metadata.finalizers.is_empty(),
            "no finalizer should be added for subresource requests"
        );
    }

    #[test]
    fn test_pv_subresource_ignored() {
        let plugin = Plugin::new();

        let pv = PersistentVolume::new("pv");
        let mut attrs = AttributesRecord::new(
            "pv",
            "",
            GroupVersionResource::new("", "v1", "persistentvolumes"),
            "status", // Subresource
            Operation::Create,
            Some(Box::new(pv)),
            None,
            GroupVersionKind::new("", "v1", "PersistentVolume"),
            false,
        );

        let result = plugin.admit(&mut attrs);
        assert!(result.is_ok());

        let obj = attrs.get_object().unwrap();
        let pv = obj.as_any().downcast_ref::<PersistentVolume>().unwrap();
        assert!(
            pv.metadata.finalizers.is_empty(),
            "no finalizer should be added for subresource requests"
        );
    }

    // ========================================================================
    // Handler Tests
    // ========================================================================

    #[test]
    fn test_handles_create_only() {
        let plugin = Plugin::new();

        assert!(plugin.handles(Operation::Create));
        assert!(!plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }

    // ========================================================================
    // Other Resource Tests
    // ========================================================================

    #[test]
    fn test_other_resources_ignored() {
        let plugin = Plugin::new();

        // Use a Pod as a non-storage resource
        let pod = crate::api::core::Pod::new("test", "default");
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
        assert!(result.is_ok(), "should not error for non-storage resources");
    }

    // ========================================================================
    // Registration Tests
    // ========================================================================

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);

        assert!(plugins.is_registered(PLUGIN_NAME));

        let plugin = plugins.new_from_plugins(PLUGIN_NAME, None).unwrap();
        assert!(plugin.handles(Operation::Create));
        assert!(!plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }

    // ========================================================================
    // Type Tests
    // ========================================================================

    #[test]
    fn test_persistent_volume_type() {
        let pv = PersistentVolume::new("test-pv");
        assert_eq!(pv.metadata.name, "test-pv");
        assert!(pv.metadata.finalizers.is_empty());
        assert_eq!(pv.kind(), "PersistentVolume");

        let mut pv = pv;
        pv.add_finalizer(PV_PROTECTION_FINALIZER);
        assert!(pv.has_finalizer(PV_PROTECTION_FINALIZER));
        assert_eq!(pv.metadata.finalizers.len(), 1);

        // Adding same finalizer again should not duplicate
        pv.add_finalizer(PV_PROTECTION_FINALIZER);
        assert_eq!(pv.metadata.finalizers.len(), 1);
    }

    #[test]
    fn test_persistent_volume_claim_type() {
        let pvc = PersistentVolumeClaim::new("test-pvc", "default");
        assert_eq!(pvc.metadata.name, "test-pvc");
        assert_eq!(pvc.metadata.namespace, "default");
        assert!(pvc.metadata.finalizers.is_empty());
        assert_eq!(pvc.kind(), "PersistentVolumeClaim");

        let mut pvc = pvc;
        pvc.add_finalizer(PVC_PROTECTION_FINALIZER);
        assert!(pvc.has_finalizer(PVC_PROTECTION_FINALIZER));
        assert_eq!(pvc.metadata.finalizers.len(), 1);
    }

    #[test]
    fn test_volume_attributes_class_type() {
        let vac = VolumeAttributesClass::new("test-vac");
        assert_eq!(vac.metadata.name, "test-vac");
        assert!(vac.metadata.finalizers.is_empty());
        assert_eq!(vac.kind(), "VolumeAttributesClass");

        let mut vac = vac;
        vac.add_finalizer(VAC_PROTECTION_FINALIZER);
        assert!(vac.has_finalizer(VAC_PROTECTION_FINALIZER));
        assert_eq!(vac.metadata.finalizers.len(), 1);
    }

    #[test]
    fn test_default_plugin() {
        let plugin = Plugin::default();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.volume_attributes_class_enabled);
    }
}
