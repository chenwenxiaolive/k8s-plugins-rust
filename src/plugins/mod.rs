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

//! Admission plugins module.

pub mod admit;
pub mod alwayspullimages;
pub mod antiaffinity;
pub mod autoprovision;
pub mod certapproval;
pub mod certsigning;
pub mod certsubjectrestriction;
pub mod ctbattest;
pub mod defaultingressclass;
pub mod defaulttolerationseconds;
pub mod deny;
pub mod denyserviceexternalips;
pub mod eventratelimit;
pub mod exists;
pub mod extendedresourcetoleration;
pub mod gc;
pub mod imagepolicy;
pub mod lifecycle;
pub mod limitranger;
pub mod mutatingadmissionpolicy;
pub mod mutatingwebhook;
pub mod nodetaint;
pub mod noderestriction;
pub mod podnodeselector;
pub mod podpriority;
pub mod podsecurity;
pub mod podtolerationrestriction;
pub mod podtopologylabels;
pub mod resize;
pub mod resourcequota;
pub mod runtimeclass;
pub mod serviceaccount;
pub mod setdefault;
pub mod storageobjectinuseprotection;
pub mod validatingadmissionpolicy;
pub mod validatingwebhook;

use crate::admission::Plugins;

/// All ordered plugins in execution order.
/// This corresponds to AllOrderedPlugins in plugins.go
pub const ALL_ORDERED_PLUGINS: &[&str] = &[
    "AlwaysAdmit",                         // admit.PluginName
    "NamespaceAutoProvision",              // autoprovision.PluginName
    "NamespaceLifecycle",                  // lifecycle.PluginName
    "NamespaceExists",                     // exists.PluginName
    "LimitPodHardAntiAffinityTopology",    // antiaffinity.PluginName
    "LimitRanger",                         // limitranger.PluginName
    "ServiceAccount",                      // serviceaccount.PluginName
    "NodeRestriction",                     // noderestriction.PluginName
    "TaintNodesByCondition",               // nodetaint.PluginName
    alwayspullimages::PLUGIN_NAME,         // AlwaysPullImages
    "ImagePolicyWebhook",                  // imagepolicy.PluginName
    "PodSecurity",                         // podsecurity.PluginName
    "PodNodeSelector",                     // podnodeselector.PluginName
    "Priority",                            // podpriority.PluginName
    "DefaultTolerationSeconds",            // defaulttolerationseconds.PluginName
    "PodTolerationRestriction",            // podtolerationrestriction.PluginName
    "EventRateLimit",                      // eventratelimit.PluginName
    "ExtendedResourceToleration",          // extendedresourcetoleration.PluginName
    "DefaultStorageClass",                 // setdefault.PluginName
    "StorageObjectInUseProtection",        // storageobjectinuseprotection.PluginName
    "OwnerReferencesPermissionEnforcement", // gc.PluginName
    "PersistentVolumeClaimResize",         // resize.PluginName
    "RuntimeClass",                        // runtimeclass.PluginName
    "CertificateApproval",                 // certapproval.PluginName
    "CertificateSigning",                  // certsigning.PluginName
    "ClusterTrustBundleAttest",            // ctbattest.PluginName
    "CertificateSubjectRestriction",       // certsubjectrestriction.PluginName
    "DefaultIngressClass",                 // defaultingressclass.PluginName
    "DenyServiceExternalIPs",              // denyserviceexternalips.PluginName
    "PodTopologyLabels",                   // podtopologylabels.PluginName
    // webhook, resourcequota, and deny plugins must go at the end
    "MutatingAdmissionPolicy",             // mutatingadmissionpolicy.PluginName
    "MutatingAdmissionWebhook",            // mutatingwebhook.PluginName
    "ValidatingAdmissionPolicy",           // validatingadmissionpolicy.PluginName
    "ValidatingAdmissionWebhook",          // validatingwebhook.PluginName
    "ResourceQuota",                       // resourcequota.PluginName
    "AlwaysDeny",                          // deny.PluginName
];

/// Default plugins that are ON by default for kube-apiserver.
pub const DEFAULT_ON_PLUGINS: &[&str] = &[
    "NamespaceLifecycle",
    "LimitRanger",
    "ServiceAccount",
    "DefaultStorageClass",
    "PersistentVolumeClaimResize",
    "DefaultTolerationSeconds",
    "MutatingAdmissionWebhook",
    "ValidatingAdmissionWebhook",
    "ResourceQuota",
    "StorageObjectInUseProtection",
    "Priority",
    "TaintNodesByCondition",
    "RuntimeClass",
    "CertificateApproval",
    "CertificateSigning",
    "ClusterTrustBundleAttest",
    "CertificateSubjectRestriction",
    "DefaultIngressClass",
    "PodSecurity",
    "PodTopologyLabels",
    "MutatingAdmissionPolicy",
    "ValidatingAdmissionPolicy",
];

/// Get the list of plugins that are OFF by default.
pub fn default_off_plugins() -> Vec<&'static str> {
    ALL_ORDERED_PLUGINS
        .iter()
        .filter(|p| !DEFAULT_ON_PLUGINS.contains(p))
        .copied()
        .collect()
}

/// Register all admission plugins.
/// This corresponds to RegisterAllAdmissionPlugins in plugins.go
pub fn register_all_admission_plugins(plugins: &Plugins) {
    admit::register(plugins);
    alwayspullimages::register(plugins);
    antiaffinity::register(plugins);
    autoprovision::register(plugins);
    certapproval::register(plugins);
    certsigning::register(plugins);
    certsubjectrestriction::register(plugins);
    ctbattest::register(plugins);
    defaultingressclass::register(plugins);
    defaulttolerationseconds::register(plugins);
    deny::register(plugins);
    denyserviceexternalips::register(plugins);
    eventratelimit::register(plugins);
    exists::register(plugins);
    extendedresourcetoleration::register(plugins);
    gc::register(plugins);
    imagepolicy::register(plugins);
    lifecycle::register(plugins);
    limitranger::register(plugins);
    mutatingadmissionpolicy::register(plugins);
    mutatingwebhook::register(plugins);
    nodetaint::register(plugins);
    noderestriction::register(plugins);
    podnodeselector::register(plugins);
    podpriority::register(plugins);
    podsecurity::register(plugins);
    podtolerationrestriction::register(plugins);
    podtopologylabels::register(plugins);
    resize::register(plugins);
    resourcequota::register(plugins);
    runtimeclass::register(plugins);
    serviceaccount::register(plugins);
    setdefault::register(plugins);
    storageobjectinuseprotection::register(plugins);
    validatingadmissionpolicy::register(plugins);
    validatingwebhook::register(plugins);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_ordered_plugins_contains_always_pull_images() {
        assert!(ALL_ORDERED_PLUGINS.contains(&"AlwaysPullImages"));
    }

    #[test]
    fn test_always_pull_images_is_off_by_default() {
        let off_plugins = default_off_plugins();
        assert!(off_plugins.contains(&"AlwaysPullImages"));
    }

    #[test]
    fn test_default_on_plugins() {
        assert!(DEFAULT_ON_PLUGINS.contains(&"NamespaceLifecycle"));
        assert!(DEFAULT_ON_PLUGINS.contains(&"ResourceQuota"));
        assert!(!DEFAULT_ON_PLUGINS.contains(&"AlwaysPullImages"));
    }

    #[test]
    fn test_register_all_admission_plugins() {
        let plugins = Plugins::new();
        register_all_admission_plugins(&plugins);
        assert!(plugins.is_registered("AlwaysPullImages"));
    }
}
