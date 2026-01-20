# Kubernetes Admission Plugins in Rust

A Rust implementation of Kubernetes admission controller plugins, ported from the official Kubernetes v1.34.1 Go codebase.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-584%20passed-brightgreen)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

## 🎯 Project Goal

Rewrite all 36 Kubernetes admission plugins from `pkg/kubeapiserver/options/plugins.go` to idiomatic Rust, including comprehensive unit tests.

## 📊 Progress

```
┌─────────────────────────────────────────────────────────────────┐
│                      Refactoring Progress                       │
├─────────────────────────────────────────────────────────────────┤
│  Total Plugins:                                36               │
│  Full Implementation:                          36 (100%)        │
│  Skeleton Implementation:                       0 (0%)          │
├─────────────────────────────────────────────────────────────────┤
│  Unit Tests Passing:                           584              │
│  Compilation Warnings:                         13 (minor)       │
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

## 📦 Plugin Implementation Status

### ✅ All 36 Plugins Fully Implemented

| # | Plugin Name | Description | Rust Module | Tests |
|---|-------------|-------------|-------------|-------|
| 1 | AlwaysAdmit | Always admits requests (deprecated) | `admit` | ✅ |
| 2 | AlwaysDeny | Always denies requests (deprecated) | `deny` | ✅ |
| 3 | AlwaysPullImages | Forces `Always` image pull policy | `alwayspullimages` | ✅ |
| 4 | LimitPodHardAntiAffinityTopology | Validates anti-affinity topology keys | `antiaffinity` | ✅ |
| 5 | TaintNodesByCondition | Adds NotReady taint to new nodes | `nodetaint` | ✅ |
| 6 | NamespaceExists | Rejects requests for non-existent namespaces | `exists` | ✅ |
| 7 | NamespaceAutoProvision | Auto-creates namespaces on demand | `autoprovision` | ✅ |
| 8 | NamespaceLifecycle | Protects system namespaces from deletion | `lifecycle` | ✅ |
| 9 | LimitRanger | Enforces resource limits per namespace | `limitranger` | ✅ |
| 10 | PodNodeSelector | Enforces node selector constraints | `podnodeselector` | ✅ |
| 11 | Priority | Resolves pod priority from PriorityClass | `podpriority` | ✅ |
| 12 | DefaultTolerationSeconds | Adds default tolerations (300s) | `defaulttolerationseconds` | ✅ |
| 13 | ExtendedResourceToleration | Adds tolerations for extended resources | `extendedresourcetoleration` | ✅ |
| 14 | DenyServiceExternalIPs | Denies new external IPs on Services | `denyserviceexternalips` | ✅ |
| 15 | CertificateSubjectRestriction | Restricts system:masters group in CSRs | `certsubjectrestriction` | ✅ |
| 16 | CertificateApproval | Validates CSR approval requests | `certapproval` | ✅ |
| 17 | CertificateSigning | Validates CSR signing requests | `certsigning` | ✅ |
| 18 | ClusterTrustBundleAttest | Validates ClusterTrustBundle attestations | `ctbattest` | ✅ |
| 19 | EventRateLimit | Rate limits event creation | `eventratelimit` | ✅ |
| 20 | OwnerReferencesPermissionEnforcement | Enforces owner reference permissions | `gc` | ✅ |
| 21 | ImagePolicyWebhook | Validates images via external webhook | `imagepolicy` | ✅ |
| 22 | DefaultIngressClass | Sets default IngressClass on Ingress | `defaultingressclass` | ✅ |
| 23 | NodeRestriction | Restricts node self-modifications | `noderestriction` | ✅ |
| 24 | PodTolerationRestriction | Restricts pod tolerations per namespace | `podtolerationrestriction` | ✅ |
| 25 | PodTopologyLabels | Copies topology labels from Node to Pod | `podtopologylabels` | ✅ |
| 26 | RuntimeClass | Sets pod overhead from RuntimeClass | `runtimeclass` | ✅ |
| 27 | PodSecurity | Enforces Pod Security Standards (PSS) | `podsecurity` | ✅ |
| 28 | ServiceAccount | Validates and injects ServiceAccount | `serviceaccount` | ✅ |
| 29 | PersistentVolumeClaimResize | Validates PVC resize requests | `resize` | ✅ |
| 30 | DefaultStorageClass | Sets default StorageClass on PVC | `setdefault` | ✅ |
| 31 | StorageObjectInUseProtection | Adds finalizers to in-use PV/PVC | `storageobjectinuseprotection` | ✅ |
| 32 | ResourceQuota | Enforces resource quotas | `resourcequota` | ✅ |
| 33 | MutatingAdmissionWebhook | Calls mutating webhooks | `mutatingwebhook` | ✅ |
| 34 | ValidatingAdmissionWebhook | Calls validating webhooks | `validatingwebhook` | ✅ |
| 35 | MutatingAdmissionPolicy | CEL-based mutating policies | `mutatingadmissionpolicy` | ✅ |
| 36 | ValidatingAdmissionPolicy | CEL-based validating policies | `validatingadmissionpolicy` | ✅ |

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
| `api.SecurityContext` | `struct SecurityContext` |
| `api.PodSecurityContext` | `struct PodSecurityContext` |
| `api.Capabilities` | `struct Capabilities` |
| `api.Ingress` | `struct Ingress` |
| `api.IngressClass` | `struct IngressClass` |
| `api.StorageClass` | `struct StorageClass` |
| `api.PersistentVolumeClaim` | `struct PersistentVolumeClaim` |
| `api.RuntimeClass` | `struct RuntimeClass` |
| `api.Binding` | `struct Binding` |

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
running 584 tests
test result: ok. 584 passed; 0 failed; 0 ignored
```

## 📚 Original Go Source

This project is a port of the following Kubernetes v1.34.1 source files:

| Location | Description |
|----------|-------------|
| `pkg/kubeapiserver/options/plugins.go` | Plugin registration entry point |
| `plugin/pkg/admission/*/` | Local admission plugins (31) |
| `staging/src/k8s.io/apiserver/pkg/admission/plugin/*/` | Apiserver plugins (5) |

## 🔑 Key Features

- **100% Plugin Coverage**: All 36 admission plugins from Kubernetes v1.34.1 implemented
- **Comprehensive Testing**: 584+ unit tests covering all plugin functionality
- **Type Safety**: Rust's type system ensures correct API object handling
- **Thread Safety**: All plugins implement `Send + Sync` for concurrent use
- **Trait-based Design**: Clean separation of mutation and validation interfaces
- **Dependency Injection**: Plugins use trait objects for testability

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
