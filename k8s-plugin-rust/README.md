# Kubernetes Admission Plugins in Rust

A Rust implementation of Kubernetes admission controller plugins, ported from the official Kubernetes v1.34.1 Go codebase.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-201%20passed-brightgreen)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

## 🎯 Project Goal

Rewrite all 36 Kubernetes admission plugins from `pkg/kubeapiserver/options/plugins.go` to idiomatic Rust, including comprehensive unit tests.

## 📊 Progress

```
┌─────────────────────────────────────────────────────────────────┐
│                      Refactoring Progress                       │
├─────────────────────────────────────────────────────────────────┤
│  Total Plugins:                                36               │
│  Full Implementation:                          15 (42%)         │
│  Skeleton Implementation:                      21 (58%)         │
├─────────────────────────────────────────────────────────────────┤
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

## 📦 Plugin Implementation Status

### ✅ Fully Implemented (15 plugins)

These plugins have complete business logic matching the Go implementation:

| # | Plugin Name | Description | Rust Module | Lines |
|---|-------------|-------------|-------------|-------|
| 1 | AlwaysAdmit | Always admits requests (deprecated) | `admit` | 159 |
| 2 | AlwaysDeny | Always denies requests (deprecated) | `deny` | 174 |
| 3 | AlwaysPullImages | Forces `Always` image pull policy | `alwayspullimages` | 628 |
| 4 | LimitPodHardAntiAffinityTopology | Validates anti-affinity topology keys | `antiaffinity` | 432 |
| 5 | TaintNodesByCondition | Adds NotReady taint to new nodes | `nodetaint` | 308 |
| 6 | NamespaceExists | Rejects requests for non-existent namespaces | `exists` | 394 |
| 7 | NamespaceAutoProvision | Auto-creates namespaces on demand | `autoprovision` | 433 |
| 8 | NamespaceLifecycle | Protects system namespaces from deletion | `lifecycle` | 415 |
| 9 | LimitRanger | Enforces resource limits per namespace | `limitranger` | 986 |
| 10 | PodNodeSelector | Enforces node selector constraints | `podnodeselector` | 564 |
| 11 | Priority | Resolves pod priority from PriorityClass | `podpriority` | 572 |
| 12 | DefaultTolerationSeconds | Adds default tolerations (300s) | `defaulttolerationseconds` | 491 |
| 13 | ExtendedResourceToleration | Adds tolerations for extended resources | `extendedresourcetoleration` | 345 |
| 14 | DenyServiceExternalIPs | Denies new external IPs on Services | `denyserviceexternalips` | 325 |
| 15 | CertificateSubjectRestriction | Restricts system:masters group in CSRs | `certsubjectrestriction` | 318 |

### 🔧 Skeleton Implementation (21 plugins)

These plugins have the correct interface structure but need business logic implementation. They require Kubernetes client infrastructure (Informers, Listers, HTTP clients) that is not yet available in this Rust codebase.

| # | Plugin Name | Rust Module | Missing Dependencies |
|---|-------------|-------------|----------------------|
| 16 | CertificateApproval | `certapproval` | Authorizer, CSR Lister |
| 17 | CertificateSigning | `certsigning` | Signer, CSR Lister |
| 18 | ClusterTrustBundleAttest | `ctbattest` | ClusterTrustBundle Lister |
| 19 | EventRateLimit | `eventratelimit` | Rate Limiter, Event Cache |
| 20 | OwnerReferencesPermissionEnforcement | `gc` | Authorizer |
| 21 | ImagePolicyWebhook | `imagepolicy` | HTTP Client, TLS, Webhook Server |
| 22 | DefaultIngressClass | `defaultingressclass` | IngressClass Lister |
| 23 | NodeRestriction | `noderestriction` | Node Lister, Authorizer |
| 24 | PodTolerationRestriction | `podtolerationrestriction` | Namespace Lister, Config |
| 25 | PodTopologyLabels | `podtopologylabels` | Node Lister |
| 26 | RuntimeClass | `runtimeclass` | RuntimeClass Lister |
| 27 | PodSecurity | `podsecurity` | Pod Security Standards Evaluator |
| 28 | ServiceAccount | `serviceaccount` | ServiceAccount Lister, Secret Lister |
| 29 | PersistentVolumeClaimResize | `resize` | PVC Lister, StorageClass Lister |
| 30 | DefaultStorageClass | `setdefault` | StorageClass Lister |
| 31 | StorageObjectInUseProtection | `storageobjectinuseprotection` | PV/PVC Lister |
| 32 | ResourceQuota | `resourcequota` | Quota Evaluator, Registry |
| 33 | MutatingAdmissionWebhook | `mutatingwebhook` | Webhook Client, JSON Patch |
| 34 | ValidatingAdmissionWebhook | `validatingwebhook` | Webhook Client |
| 35 | MutatingAdmissionPolicy | `mutatingadmissionpolicy` | CEL Compiler, Expression Evaluator |
| 36 | ValidatingAdmissionPolicy | `validatingadmissionpolicy` | CEL Compiler, Expression Evaluator |

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

## 🔄 Next Steps

To complete the remaining 21 plugins, the following infrastructure needs to be implemented:

1. **Kubernetes Client Library**
   - Informer/Lister mechanism
   - REST client for API server
   - Watch mechanism for resource changes

2. **External Dependencies**
   - CEL (Common Expression Language) compiler for admission policies
   - HTTP client for webhook calls
   - TLS configuration for secure communications

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
