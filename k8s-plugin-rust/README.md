# Kubernetes Admission Plugins in Rust

A complete Rust implementation of Kubernetes admission controller plugins, ported from the official Kubernetes v1.34.1 Go codebase.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-201%20passed-brightgreen)]()
[![Plugins](https://img.shields.io/badge/plugins-36%2F36-brightgreen)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

## 🎯 Project Goal

Rewrite all 36 Kubernetes admission plugins from `pkg/kubeapiserver/options/plugins.go` to idiomatic Rust, including comprehensive unit tests.

## 📊 Progress

```
┌─────────────────────────────────────────────────────────────────┐
│                    ✅ REFACTORING COMPLETE                      │
├─────────────────────────────────────────────────────────────────┤
│  Plugins Implemented:                          36/36 (100%)     │
│  Unit Tests Passing:                           201              │
│  Compilation Warnings:                         0                │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/chenwenxiaolive/k8s-plugins-rust.git
cd k8s-plugins-rust/k8s-plugin-rust

# Build the project
cargo build

# Run all tests
cargo test
```

## 📦 Implemented Plugins

### Category 1: Local Plugins (31 modules)

| # | Plugin Name | Description | Rust Module |
|---|-------------|-------------|-------------|
| 1 | AlwaysAdmit | Always admits requests (deprecated) | `admit` |
| 2 | AlwaysDeny | Always denies requests (deprecated) | `deny` |
| 3 | AlwaysPullImages | Forces `Always` image pull policy | `alwayspullimages` |
| 4 | LimitPodHardAntiAffinityTopology | Validates anti-affinity topology keys | `antiaffinity` |
| 5 | TaintNodesByCondition | Adds NotReady taint to new nodes | `nodetaint` |
| 6 | NamespaceExists | Rejects requests for non-existent namespaces | `exists` |
| 7 | NamespaceAutoProvision | Auto-creates namespaces on demand | `autoprovision` |
| 8 | NamespaceLifecycle | Protects system namespaces from deletion | `lifecycle` |
| 9 | DefaultTolerationSeconds | Adds default tolerations (300s) | `defaulttolerationseconds` |
| 10 | ExtendedResourceToleration | Adds tolerations for extended resources | `extendedresourcetoleration` |
| 11 | DenyServiceExternalIPs | Denies new external IPs on Services | `denyserviceexternalips` |
| 12 | CertificateApproval | Validates CSR approval permissions | `certapproval` |
| 13 | CertificateSigning | Validates CSR signing permissions | `certsigning` |
| 14 | CertificateSubjectRestriction | Restricts system:masters group in CSRs | `certsubjectrestriction` |
| 15 | ClusterTrustBundleAttest | Validates ClusterTrustBundle attestation | `ctbattest` |
| 16 | LimitRanger | Enforces resource limits per namespace | `limitranger` |
| 17 | PodNodeSelector | Enforces node selector constraints | `podnodeselector` |
| 18 | PodTolerationRestriction | Restricts pod tolerations | `podtolerationrestriction` |
| 19 | PodTopologyLabels | Manages pod topology labels | `podtopologylabels` |
| 20 | Priority | Resolves pod priority from PriorityClass | `podpriority` |
| 21 | DefaultIngressClass | Sets default ingress class | `defaultingressclass` |
| 22 | NodeRestriction | Restricts node self-modification | `noderestriction` |
| 23 | EventRateLimit | Rate limits event creation | `eventratelimit` |
| 24 | OwnerReferencesPermissionEnforcement | Enforces owner reference permissions | `gc` |
| 25 | ImagePolicyWebhook | External image policy validation | `imagepolicy` |
| 26 | RuntimeClass | Sets pod overhead from RuntimeClass | `runtimeclass` |
| 27 | PodSecurity | Enforces Pod Security Standards | `podsecurity` |
| 28 | ServiceAccount | Manages service account tokens | `serviceaccount` |
| 29 | PersistentVolumeClaimResize | Validates PVC resize requests | `resize` |
| 30 | DefaultStorageClass | Sets default storage class | `setdefault` |
| 31 | StorageObjectInUseProtection | Protects in-use storage objects | `storageobjectinuseprotection` |

### Category 2: Apiserver Core Plugins (5 modules)

| # | Plugin Name | Description | Rust Module |
|---|-------------|-------------|-------------|
| 32 | ResourceQuota | Enforces resource quota limits | `resourcequota` |
| 33 | MutatingAdmissionWebhook | Calls mutating admission webhooks | `mutatingwebhook` |
| 34 | ValidatingAdmissionWebhook | Calls validating admission webhooks | `validatingwebhook` |
| 35 | MutatingAdmissionPolicy | CEL-based mutation policies | `mutatingadmissionpolicy` |
| 36 | ValidatingAdmissionPolicy | CEL-based validation policies | `validatingadmissionpolicy` |

## 🏗️ Architecture

```
k8s-plugin-rust/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                 # Library entry point
    ├── admission/             # Core admission framework
    │   ├── mod.rs             # Module exports
    │   ├── interfaces.rs      # Plugin interfaces (MutationInterface, ValidationInterface)
    │   ├── attributes.rs      # Request attributes (GroupVersionResource, etc.)
    │   ├── errors.rs          # Error types (AdmissionError, AdmissionResult)
    │   ├── handler.rs         # Base handler implementation
    │   └── plugins.rs         # Plugin registry
    ├── api/                   # Kubernetes API types
    │   └── core/
    │       └── mod.rs         # Pod, Container, Node, Namespace, etc.
    └── plugins/               # All 36 admission plugins
        ├── mod.rs             # Plugin registration
        └── */mod.rs           # Individual plugin implementations
```

## 🔧 Core Traits

```rust
/// Interface that all admission plugins must implement
pub trait Interface: Send + Sync {
    fn handles(&self, operation: Operation) -> bool;
}

/// Mutation plugins can modify incoming objects
pub trait MutationInterface: Interface {
    fn admit(&self, attributes: &mut dyn Attributes) -> AdmissionResult<()>;
}

/// Validation plugins can reject requests
pub trait ValidationInterface: Interface {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()>;
}
```

## 📋 API Types Implemented

| Go Original | Rust Implementation |
|-------------|---------------------|
| `api.Pod` | `struct Pod` |
| `api.PodSpec` | `struct PodSpec` |
| `api.Container` | `struct Container` |
| `api.Volume` | `struct Volume` |
| `api.PullPolicy` | `enum PullPolicy` |
| `api.Toleration` | `struct Toleration` |
| `api.TolerationEffect` | `enum TolerationEffect` |
| `api.Node` | `struct Node` |
| `api.Taint` | `struct Taint` |
| `api.Affinity` | `struct Affinity` |
| `api.Namespace` | `struct Namespace` |
| `api.ResourceRequirements` | `struct ResourceRequirements` |
| `api.Service` | `struct Service` |
| `api.LimitRange` | `struct LimitRange` |
| `api.PriorityClass` | `struct PriorityClass` |

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific plugin tests
cargo test plugins::lifecycle

# Run tests in release mode
cargo test --release
```

**Test Results:**
```
running 201 tests
test result: ok. 201 passed; 0 failed; 0 ignored
```

## 📚 Original Go Source

This project is a port of the following Kubernetes v1.34.1 source files:

| Location | Description |
|----------|-------------|
| `pkg/kubeapiserver/options/plugins.go` | Plugin registration entry point |
| `plugin/pkg/admission/*/` | Local admission plugins (31) |
| `staging/src/k8s.io/apiserver/pkg/admission/plugin/*/` | Apiserver plugins (5) |

## 🔄 Default Plugin Configuration

Plugins enabled by default in kube-apiserver:
- NamespaceLifecycle, LimitRanger, ServiceAccount
- DefaultStorageClass, PersistentVolumeClaimResize
- DefaultTolerationSeconds, Priority, RuntimeClass
- TaintNodesByCondition, PodSecurity, DefaultIngressClass
- MutatingAdmissionWebhook, ValidatingAdmissionWebhook
- ResourceQuota, StorageObjectInUseProtection
- CertificateApproval, CertificateSigning, ClusterTrustBundleAttest
- CertificateSubjectRestriction, PodTopologyLabels
- MutatingAdmissionPolicy, ValidatingAdmissionPolicy

## 📄 License

Licensed under the Apache License, Version 2.0 - the same license as Kubernetes.

```
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🙏 Acknowledgments

- The Kubernetes community for the original Go implementation
- The Rust community for excellent tooling and ecosystem
