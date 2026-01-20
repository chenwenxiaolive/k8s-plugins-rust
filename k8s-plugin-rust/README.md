# Kubernetes Admission Plugins in Rust

This project is a Rust implementation of Kubernetes admission controller plugins, originally implemented in Go (Kubernetes v1.34.1). The implementation follows the same architecture and interfaces as the original Kubernetes codebase.

## Overview

This crate provides a Rust reimplementation of the Kubernetes admission plugin system, starting with the `AlwaysPullImages` plugin as the first complete example. The goal is to provide a type-safe, memory-safe alternative to the Go implementation while maintaining API compatibility.

## Project Structure

```
k8s-plugin-rust/
├── Cargo.toml
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
        └── alwayspullimages/
            └── mod.rs                  # AlwaysPullImages plugin implementation & tests
```

## Implemented Components

### Core Admission Framework

| Go Original | Rust Implementation |
|-------------|---------------------|
| `admission.Interface` | `trait Interface` |
| `admission.MutationInterface` | `trait MutationInterface` |
| `admission.ValidationInterface` | `trait ValidationInterface` |
| `admission.Handler` | `struct Handler` |
| `admission.Plugins` | `struct Plugins` |
| `admission.Attributes` | `trait Attributes` |
| `admission.Operation` | `enum Operation` |

### Kubernetes API Types

| Go Original | Rust Implementation |
|-------------|---------------------|
| `api.Pod` | `struct Pod` |
| `api.PodSpec` | `struct PodSpec` |
| `api.Container` | `struct Container` |
| `api.Volume` | `struct Volume` |
| `api.PullPolicy` | `enum PullPolicy` |
| `api.ImageVolumeSource` | `struct ImageVolumeSource` |
| `pods.VisitContainersWithPath()` | `PodSpec::visit_containers_with_path()` |

### Plugins

| Go Original | Rust Implementation | Status |
|-------------|---------------------|--------|
| `alwayspullimages` | `plugins::alwayspullimages` | ✅ Complete |
| `AllOrderedPlugins` | `ALL_ORDERED_PLUGINS` | ✅ Complete |
| `DefaultOffAdmissionPlugins()` | `default_off_plugins()` | ✅ Complete |
| Other plugins | - | 🚧 Planned |

## Usage

### Basic Example

```rust
use k8s_plugin_rust::admission::{Plugins, Operation};
use k8s_plugin_rust::plugins::alwayspullimages;

// Create plugin registry
let plugins = Plugins::new();

// Register the AlwaysPullImages plugin
alwayspullimages::register(&plugins);

// Create a plugin instance
let plugin = plugins.new_from_plugins("AlwaysPullImages", None).unwrap();

// Check if the plugin handles CREATE operations
assert!(plugin.handles(Operation::Create));
```

### Using the AlwaysPullImages Plugin

```rust
use k8s_plugin_rust::admission::{AttributesRecord, MutationInterface, Operation};
use k8s_plugin_rust::api::core::{Pod, PodSpec, Container, PullPolicy};
use k8s_plugin_rust::plugins::alwayspullimages::AlwaysPullImages;

// Create the plugin
let plugin = AlwaysPullImages::new();

// Create a pod with various image pull policies
let pod = Pod {
    name: "my-pod".to_string(),
    namespace: "default".to_string(),
    spec: PodSpec {
        containers: vec![
            Container::with_pull_policy("nginx", "nginx:latest", PullPolicy::IfNotPresent),
        ],
        ..Default::default()
    },
};

// Create admission attributes
let mut attrs = AttributesRecord::new_pod("my-pod", "default", Operation::Create, pod, None);

// Apply the mutation - this will set all image pull policies to Always
plugin.admit(&mut attrs).unwrap();

// Verify the policy was changed
let modified_pod = attrs.get_pod().unwrap();
assert_eq!(modified_pod.spec.containers[0].image_pull_policy, PullPolicy::Always);
```

## Testing

Run all tests:

```bash
cargo test
```

The test suite includes 27 tests covering:
- Core admission framework (interfaces, handler, plugins, errors, attributes)
- Kubernetes API types (Pod, Container, PullPolicy, Volume)
- AlwaysPullImages plugin (ported from Go tests):
  - `test_admission` - Tests mutation of image pull policies
  - `test_validate` - Tests validation of image pull policies
  - `test_other_resources` - Tests that non-pod resources are ignored
  - `test_update_pod` - Tests update operations with/without new images

## Original Go Source

This project is a port of the following Kubernetes v1.34.1 source files:

- `pkg/kubeapiserver/options/plugins.go` - Plugin registration and ordering
- `plugin/pkg/admission/alwayspullimages/admission.go` - AlwaysPullImages plugin
- `plugin/pkg/admission/alwayspullimages/admission_test.go` - Plugin tests
- `staging/src/k8s.io/apiserver/pkg/admission/` - Core admission interfaces

## License

Licensed under the Apache License, Version 2.0 - the same license as Kubernetes.

## Contributing

Contributions are welcome! Areas for future development:

1. Implement additional admission plugins (LimitRanger, ServiceAccount, etc.)
2. Add serialization/deserialization support (serde)
3. Integration with actual Kubernetes API server
4. Performance benchmarks comparing Go and Rust implementations
