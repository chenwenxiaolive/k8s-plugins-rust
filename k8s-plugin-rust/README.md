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
│  Completed:                                         1 (2.8%)    │
│  Remaining:                                        35           │
├─────────────────────────────────────────────────────────────────┤
│  Total Go Test Files:                              73           │
│    - Local plugins (plugin/pkg/admission):         36           │
│    - Apiserver plugins (apiserver/pkg/admission):  37           │
│  Test Files Migrated:                               1           │
└─────────────────────────────────────────────────────────────────┘
```

## Modules to Refactor

### Category 1: Local Plugins (k8s.io/kubernetes/plugin/pkg/admission/) - 31 modules

| # | Package | Plugin Name | Go Path | Test File | Status |
|---|---------|-------------|---------|-----------|--------|
| 1 | admit | AlwaysAdmit | `admit/` | `admission_test.go` | ❌ |
| 2 | **alwayspullimages** | AlwaysPullImages | `alwayspullimages/` | `admission_test.go` | ✅ Done |
| 3 | antiaffinity | LimitPodHardAntiAffinityTopology | `antiaffinity/` | `admission_test.go` | ❌ |
| 4 | certapproval | CertificateApproval | `certificates/approval/` | `admission_test.go` | ❌ |
| 5 | certsigning | CertificateSigning | `certificates/signing/` | `admission_test.go` | ❌ |
| 6 | ctbattest | ClusterTrustBundleAttest | `certificates/ctbattest/` | `admission_test.go` | ❌ |
| 7 | certsubjectrestriction | CertificateSubjectRestriction | `certificates/subjectrestriction/` | `admission_test.go` | ❌ |
| 8 | defaulttolerationseconds | DefaultTolerationSeconds | `defaulttolerationseconds/` | `admission_test.go` | ❌ |
| 9 | deny | AlwaysDeny | `deny/` | `admission_test.go` | ❌ |
| 10 | eventratelimit | EventRateLimit | `eventratelimit/` | `admission_test.go`, `cache_test.go`, `validation_test.go` | ❌ |
| 11 | extendedresourcetoleration | ExtendedResourceToleration | `extendedresourcetoleration/` | `admission_test.go` | ❌ |
| 12 | gc | OwnerReferencesPermissionEnforcement | `gc/` | `gc_admission_test.go` | ❌ |
| 13 | imagepolicy | ImagePolicyWebhook | `imagepolicy/` | `admission_test.go`, `certs_test.go`, `config_test.go` | ❌ |
| 14 | limitranger | LimitRanger | `limitranger/` | `admission_test.go` | ❌ |
| 15 | autoprovision | NamespaceAutoProvision | `namespace/autoprovision/` | `admission_test.go` | ❌ |
| 16 | exists | NamespaceExists | `namespace/exists/` | `admission_test.go` | ❌ |
| 17 | defaultingressclass | DefaultIngressClass | `network/defaultingressclass/` | `admission_test.go` | ❌ |
| 18 | denyserviceexternalips | DenyServiceExternalIPs | `network/denyserviceexternalips/` | `admission_test.go` | ❌ |
| 19 | noderestriction | NodeRestriction | `noderestriction/` | `admission_test.go` | ❌ |
| 20 | nodetaint | TaintNodesByCondition | `nodetaint/` | `admission_test.go` | ❌ |
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

## Project Structure

```
k8s-plugin-rust/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                          # Main library entry point
    ├── admission/
    │   ├── mod.rs                      # Admission module
    │   ├── interfaces.rs               # Interface, MutationInterface, ValidationInterface traits
    │   ├── attributes.rs               # Attributes trait, AttributesRecord, GVR/GVK types
    │   ├── errors.rs                   # AdmissionError, ForbiddenError, AggregateError
    │   ├── handler.rs                  # Handler base struct
    │   └── plugins.rs                  # Plugin registry system
    ├── api/
    │   ├── mod.rs
    │   └── core/
    │       └── mod.rs                  # Pod, Container, PullPolicy, Volume API types
    └── plugins/
        ├── mod.rs                      # AllOrderedPlugins, register_all_admission_plugins
        └── alwayspullimages/           # ✅ COMPLETED
            └── mod.rs
        # TODO: Add remaining 35 plugin modules
```

## Implemented Components

### Core Admission Framework

| Go Original | Rust Implementation | Status |
|-------------|---------------------|--------|
| `admission.Interface` | `trait Interface` | ✅ |
| `admission.MutationInterface` | `trait MutationInterface` | ✅ |
| `admission.ValidationInterface` | `trait ValidationInterface` | ✅ |
| `admission.Handler` | `struct Handler` | ✅ |
| `admission.Plugins` | `struct Plugins` | ✅ |
| `admission.Attributes` | `trait Attributes` | ✅ |
| `admission.Operation` | `enum Operation` | ✅ |

### Kubernetes API Types

| Go Original | Rust Implementation | Status |
|-------------|---------------------|--------|
| `api.Pod` | `struct Pod` | ✅ |
| `api.PodSpec` | `struct PodSpec` | ✅ |
| `api.Container` | `struct Container` | ✅ |
| `api.Volume` | `struct Volume` | ✅ |
| `api.PullPolicy` | `enum PullPolicy` | ✅ |
| `api.ImageVolumeSource` | `struct ImageVolumeSource` | ✅ |
| `pods.VisitContainersWithPath()` | `PodSpec::visit_containers_with_path()` | ✅ |

## Completed Plugin: alwayspullimages

### Features Ported
- `PluginName` constant
- `Register()` function
- `AlwaysPullImages` struct
- `NewAlwaysPullImages()` constructor
- `Admit()` method (MutationInterface)
- `Validate()` method (ValidationInterface)
- `shouldIgnore()` helper
- `isUpdateWithNoNewImages()` helper
- KEP-4639 Image Volumes support

### Tests Ported (from admission_test.go)
| Go Test | Rust Test | Description |
|---------|-----------|-------------|
| `TestAdmission` | `test_admission` | Verifies CREATE sets all ImagePullPolicy to Always |
| `TestValidate` | `test_validate` | Verifies validation errors for non-Always policies |
| `TestOtherResources` | `test_other_resources` | Verifies no-op for non-pod resources/subresources |
| `TestUpdatePod` | `test_update_pod` | Verifies update behavior with/without new images |

## Testing

Run all tests:

```bash
cd k8s-plugin-rust
cargo test
```

Current test results:
```
running 27 tests
test admission::attributes::tests::test_attributes_record_new_pod ... ok
test admission::attributes::tests::test_group_version_resource ... ok
test admission::errors::tests::test_aggregate_error_display ... ok
test admission::errors::tests::test_forbidden_error_display ... ok
test admission::handler::tests::test_handler_new ... ok
test admission::handler::tests::test_handler_new_all ... ok
test admission::handler::tests::test_handler_new_create_update ... ok
test admission::interfaces::tests::test_operation_display ... ok
test admission::interfaces::tests::test_operation_from_str ... ok
test admission::plugins::tests::test_plugins_new_from_plugins ... ok
test admission::plugins::tests::test_plugins_register ... ok
test admission::plugins::tests::test_plugins_unknown_plugin ... ok
test api::core::tests::test_container ... ok
test api::core::tests::test_image_volume ... ok
test api::core::tests::test_pod_as_api_object ... ok
test api::core::tests::test_pod_spec_visit_containers ... ok
test api::core::tests::test_pod_spec_visit_containers_short_circuit ... ok
test api::core::tests::test_pull_policy ... ok
test plugins::alwayspullimages::tests::test_admission ... ok
test plugins::alwayspullimages::tests::test_validate ... ok
test plugins::alwayspullimages::tests::test_other_resources ... ok
test plugins::alwayspullimages::tests::test_update_pod ... ok
test plugins::alwayspullimages::tests::test_plugin_registration ... ok
test plugins::tests::test_all_ordered_plugins_contains_always_pull_images ... ok
test plugins::tests::test_always_pull_images_is_off_by_default ... ok
test plugins::tests::test_default_on_plugins ... ok
test plugins::tests::test_register_all_admission_plugins ... ok

test result: ok. 27 passed; 0 failed; 0 ignored
```

## Original Go Source

This project is a port of the following Kubernetes v1.34.1 source files:

- Entry point: `pkg/kubeapiserver/options/plugins.go`
- Local plugins: `plugin/pkg/admission/*/`
- Apiserver plugins: `staging/src/k8s.io/apiserver/pkg/admission/plugin/*/`

## License

Licensed under the Apache License, Version 2.0 - the same license as Kubernetes.

## Contributing

Contributions are welcome! Priority areas:

1. **Simple plugins first**: admit, deny, antiaffinity
2. **Common plugins**: serviceaccount, limitranger, resourcequota
3. **Complex plugins**: noderestriction, podsecurity, webhook-related
4. **Additional API types** as needed by each plugin
5. **All corresponding test migrations**
