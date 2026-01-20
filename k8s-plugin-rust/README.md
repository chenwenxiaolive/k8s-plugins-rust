# Kubernetes Admission Plugins in Rust

This project is a Rust implementation of Kubernetes admission controller plugins, originally implemented in Go (Kubernetes v1.34.1). The implementation follows the same architecture and interfaces as the original Kubernetes codebase.

## Project Goal

Rewrite all admission plugins from `pkg/kubeapiserver/options/plugins.go` entry point to Rust, including all related unit tests.

## Progress Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Refactoring Progress                       │
├─────────────────────────────────────────────────────────────────┤
│  Total Plugins:                                    36           │
│  Completed:                                        11 (30.6%)   │
│  Remaining:                                        25           │
├─────────────────────────────────────────────────────────────────┤
│  Total Go Test Files:                              73           │
│  Test Files Migrated:                              11           │
│  Tests Passing:                                    88           │
└─────────────────────────────────────────────────────────────────┘
```

## Modules to Refactor

### Category 1: Local Plugins (k8s.io/kubernetes/plugin/pkg/admission/) - 31 modules

| # | Package | Plugin Name | Go Path | Test File | Status |
|---|---------|-------------|---------|-----------|--------|
| 1 | admit | AlwaysAdmit | `admit/` | `admission_test.go` | ✅ Done |
| 2 | alwayspullimages | AlwaysPullImages | `alwayspullimages/` | `admission_test.go` | ✅ Done |
| 3 | antiaffinity | LimitPodHardAntiAffinityTopology | `antiaffinity/` | `admission_test.go` | ✅ Done |
| 4 | certapproval | CertificateApproval | `certificates/approval/` | `admission_test.go` | ❌ |
| 5 | certsigning | CertificateSigning | `certificates/signing/` | `admission_test.go` | ❌ |
| 6 | ctbattest | ClusterTrustBundleAttest | `certificates/ctbattest/` | `admission_test.go` | ❌ |
| 7 | certsubjectrestriction | CertificateSubjectRestriction | `certificates/subjectrestriction/` | `admission_test.go` | ✅ Done |
| 8 | defaulttolerationseconds | DefaultTolerationSeconds | `defaulttolerationseconds/` | `admission_test.go` | ✅ Done |
| 9 | deny | AlwaysDeny | `deny/` | `admission_test.go` | ✅ Done |
| 10 | eventratelimit | EventRateLimit | `eventratelimit/` | `admission_test.go`, `cache_test.go`, `validation_test.go` | ❌ |
| 11 | extendedresourcetoleration | ExtendedResourceToleration | `extendedresourcetoleration/` | `admission_test.go` | ✅ Done |
| 12 | gc | OwnerReferencesPermissionEnforcement | `gc/` | `gc_admission_test.go` | ❌ |
| 13 | imagepolicy | ImagePolicyWebhook | `imagepolicy/` | `admission_test.go`, `certs_test.go`, `config_test.go` | ❌ |
| 14 | limitranger | LimitRanger | `limitranger/` | `admission_test.go` | ❌ |
| 15 | autoprovision | NamespaceAutoProvision | `namespace/autoprovision/` | `admission_test.go` | ✅ Done |
| 16 | exists | NamespaceExists | `namespace/exists/` | `admission_test.go` | ✅ Done |
| 17 | defaultingressclass | DefaultIngressClass | `network/defaultingressclass/` | `admission_test.go` | ❌ |
| 18 | denyserviceexternalips | DenyServiceExternalIPs | `network/denyserviceexternalips/` | `admission_test.go` | ✅ Done |
| 19 | noderestriction | NodeRestriction | `noderestriction/` | `admission_test.go` | ❌ |
| 20 | nodetaint | TaintNodesByCondition | `nodetaint/` | `admission_test.go` | ✅ Done |
| 21 | podnodeselector | PodNodeSelector | `podnodeselector/` | `admission_test.go` | ❌ |
| 22 | podtolerationrestriction | PodTolerationRestriction | `podtolerationrestriction/` | `admission_test.go`, `validation_test.go` | ❌ |
| 23 | podtopologylabels | PodTopologyLabels | `podtopologylabels/` | `admission_test.go` | ❌ |
| 24 | podpriority | Priority | `priority/` | `admission_test.go` | ❌ |
| 25 | runtimeclass | RuntimeClass | `runtimeclass/` | `admission_test.go` | ❌ |
| 26 | podsecurity | PodSecurity | `security/podsecurity/` | `admission_test.go` | ❌ |
| 27 | serviceaccount | ServiceAccount | `serviceaccount/` | `admission_test.go` | ❌ |
| 28 | resize | PersistentVolumeClaimResize | `storage/persistentvolume/resize/` | `admission_test.go` | ❌ |
| 29 | setdefault | DefaultStorageClass | `storage/storageclass/setdefault/` | `admission_test.go` | ❌ |
| 30 | storageobjectinuseprotection | StorageObjectInUseProtection | `storage/storageobjectinuseprotection/` | `admission_test.go` | ❌ |
| 31 | resourcequota | ResourceQuota | `resourcequota/` | `admission_test.go` | ❌ |

### Category 2: Apiserver Core Plugins (k8s.io/apiserver/pkg/admission/plugin/) - 5 modules

| # | Package | Plugin Name | Go Path | Test Files | Status |
|---|---------|-------------|---------|------------|--------|
| 32 | lifecycle | NamespaceLifecycle | `namespace/lifecycle/` | `admission_test.go` | ❌ |
| 33 | mutatingwebhook | MutatingAdmissionWebhook | `webhook/mutating/` | `dispatcher_test.go`, `plugin_test.go` + shared | ❌ |
| 34 | validatingwebhook | ValidatingAdmissionWebhook | `webhook/validating/` | `plugin_test.go` + shared | ❌ |
| 35 | mutatingadmissionpolicy | MutatingAdmissionPolicy | `policy/mutating/` | `compilation_test.go`, `dispatcher_test.go`, `plugin_test.go`, etc. | ❌ |
| 36 | validatingadmissionpolicy | ValidatingAdmissionPolicy | `policy/validating/` | `admission_test.go`, `validator_test.go`, etc. | ❌ |

## Completed Plugins

### 1. AlwaysAdmit (admit)
- Deprecated plugin that always admits requests
- Implements both MutationInterface and ValidationInterface

### 2. AlwaysDeny (deny)
- Deprecated plugin that always denies requests
- Implements both MutationInterface and ValidationInterface

### 3. AlwaysPullImages
- Forces all containers to use `Always` image pull policy
- Supports KEP-4639 Image Volumes

### 4. LimitPodHardAntiAffinityTopology (antiaffinity)
- Validates pod anti-affinity topology keys are `kubernetes.io/hostname`

### 5. TaintNodesByCondition (nodetaint)
- Adds NotReady taint to nodes on creation

### 6. NamespaceExists (exists)
- Rejects requests if namespace doesn't exist

### 7. NamespaceAutoProvision (autoprovision)
- Auto-creates namespaces on resource creation

### 8. DefaultTolerationSeconds
- Adds default tolerations for not-ready/unreachable taints (300s)

### 9. ExtendedResourceToleration
- Adds tolerations for extended resource requests (e.g., GPUs)

### 10. DenyServiceExternalIPs
- Denies new external IPs on Services
- Allows removing or keeping existing external IPs

## Project Structure

```
k8s-plugin-rust/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs
    ├── admission/
    │   ├── mod.rs
    │   ├── interfaces.rs
    │   ├── attributes.rs
    │   ├── errors.rs
    │   ├── handler.rs
    │   └── plugins.rs
    ├── api/
    │   └── core/
    │       └── mod.rs
    └── plugins/
        ├── mod.rs
        ├── admit/mod.rs               # ✅
        ├── alwayspullimages/mod.rs    # ✅
        ├── antiaffinity/mod.rs        # ✅
        ├── autoprovision/mod.rs       # ✅
        ├── defaulttolerationseconds/mod.rs  # ✅
        ├── deny/mod.rs                # ✅
        ├── exists/mod.rs              # ✅
        ├── extendedresourcetoleration/mod.rs  # ✅
        └── nodetaint/mod.rs           # ✅
```

## Implemented API Types

| Go Original | Rust Implementation | Status |
|-------------|---------------------|--------|
| `api.Pod` | `struct Pod` | ✅ |
| `api.PodSpec` | `struct PodSpec` | ✅ |
| `api.Container` | `struct Container` | ✅ |
| `api.Volume` | `struct Volume` | ✅ |
| `api.PullPolicy` | `enum PullPolicy` | ✅ |
| `api.Toleration` | `struct Toleration` | ✅ |
| `api.TolerationEffect` | `enum TolerationEffect` | ✅ |
| `api.Node` | `struct Node` | ✅ |
| `api.Taint` | `struct Taint` | ✅ |
| `api.Affinity` | `struct Affinity` | ✅ |
| `api.Namespace` | `struct Namespace` | ✅ |
| `api.ResourceRequirements` | `struct ResourceRequirements` | ✅ |

## Testing

Run all tests:

```bash
cd k8s-plugin-rust
cargo test
```

Current test results:
```
running 72 tests
test result: ok. 72 passed; 0 failed; 0 ignored
```

## Original Go Source

This project is a port of the following Kubernetes v1.34.1 source files:

- Entry point: `pkg/kubeapiserver/options/plugins.go`
- Local plugins: `plugin/pkg/admission/*/`
- Apiserver plugins: `staging/src/k8s.io/apiserver/pkg/admission/plugin/*/`

## License

Licensed under the Apache License, Version 2.0 - the same license as Kubernetes.
