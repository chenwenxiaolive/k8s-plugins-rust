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

//! Admission controller interfaces and types.
//!
//! This module provides the core types and traits for implementing admission controllers,
//! mirroring the Go interfaces from k8s.io/apiserver/pkg/admission.

pub mod attributes;
pub mod errors;
mod handler;
mod interfaces;
mod plugins;

pub use attributes::{Attributes, AttributesRecord};
pub use errors::{AdmissionError, AdmissionResult};
pub use handler::Handler;
pub use interfaces::{Interface, MutationInterface, Operation, ValidationInterface};
pub use plugins::{Factory, PluginInitializer, Plugins};
