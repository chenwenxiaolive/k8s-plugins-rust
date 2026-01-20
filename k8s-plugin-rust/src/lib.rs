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

//! Kubernetes Admission Plugins reimplemented in Rust
//!
//! This crate provides a Rust implementation of Kubernetes admission controller plugins,
//! originally implemented in Go. The implementation follows the same architecture and
//! interfaces as the original Kubernetes codebase.

pub mod admission;
pub mod api;
pub mod plugins;

// Re-export commonly used types
pub use admission::{
    Attributes, Handler, Interface, MutationInterface, Operation, ValidationInterface,
};
pub use api::core::{Container, Pod, PodSpec, PullPolicy, Volume};
