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

//! EventRateLimit admission controller.
//!
//! This admission controller enforces rate limits on event creation to prevent
//! event storms from overwhelming the API server. It supports multiple limit types:
//! - Server: A single global rate limit for all events
//! - Namespace: Per-namespace rate limits
//! - User: Per-user rate limits
//! - SourceAndObject: Per source+object combination rate limits

use crate::admission::{
    AdmissionError, AdmissionResult, Attributes, Handler, Interface, Operation, Plugins,
    ValidationInterface,
};
use crate::api::core::ApiObject;
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Plugin name for the EventRateLimit admission controller.
pub const PLUGIN_NAME: &str = "EventRateLimit";

/// Default cache size if not specified in configuration.
const DEFAULT_CACHE_SIZE: usize = 4096;

// ============================================================================
// Configuration Types
// ============================================================================

/// LimitType is the type of the limit (e.g., per-namespace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitType {
    /// Server is a type of limit where there is one bucket shared by
    /// all of the event queries received by the API Server.
    Server,
    /// Namespace is a type of limit where there is one bucket used by
    /// each namespace.
    Namespace,
    /// User is a type of limit where there is one bucket used by each user.
    User,
    /// SourceAndObject is a type of limit where there is one bucket used
    /// by each combination of source and involved object of the event.
    SourceAndObject,
}

impl std::fmt::Display for LimitType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitType::Server => write!(f, "Server"),
            LimitType::Namespace => write!(f, "Namespace"),
            LimitType::User => write!(f, "User"),
            LimitType::SourceAndObject => write!(f, "SourceAndObject"),
        }
    }
}

/// Limit is the configuration for a particular limit type.
#[derive(Debug, Clone)]
pub struct Limit {
    /// Type is the type of limit to which this configuration applies.
    pub limit_type: LimitType,
    /// QPS is the number of event queries per second that are allowed.
    pub qps: f32,
    /// Burst is the burst number of event queries that are allowed.
    pub burst: i32,
    /// CacheSize is the size of the LRU cache for this type of limit.
    /// If limitType is 'Server', then cacheSize is ignored.
    pub cache_size: usize,
}

impl Limit {
    /// Create a new limit configuration.
    pub fn new(limit_type: LimitType, qps: f32, burst: i32) -> Self {
        Self {
            limit_type,
            qps,
            burst,
            cache_size: DEFAULT_CACHE_SIZE,
        }
    }

    /// Create a new limit configuration with cache size.
    pub fn with_cache_size(limit_type: LimitType, qps: f32, burst: i32, cache_size: usize) -> Self {
        Self {
            limit_type,
            qps,
            burst,
            cache_size,
        }
    }
}

/// Configuration provides configuration for the EventRateLimit admission controller.
#[derive(Debug, Clone, Default)]
pub struct Configuration {
    /// Limits are the limits to place on event queries received.
    pub limits: Vec<Limit>,
}

impl Configuration {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a limit to the configuration.
    pub fn add_limit(&mut self, limit: Limit) {
        self.limits.push(limit);
    }
}

// ============================================================================
// Event Types (for source+object key extraction)
// ============================================================================

/// EventSource contains information for an event's source.
#[derive(Debug, Clone, Default)]
pub struct EventSource {
    /// Component from which the event is generated.
    pub component: String,
    /// Node name on which the event is generated.
    pub host: String,
}

/// ObjectReference contains enough information to let you inspect or modify the referred object.
#[derive(Debug, Clone, Default)]
pub struct EventObjectReference {
    /// Kind of the referent.
    pub kind: String,
    /// Namespace of the referent.
    pub namespace: String,
    /// Name of the referent.
    pub name: String,
    /// UID of the referent.
    pub uid: String,
    /// API version of the referent.
    pub api_version: String,
}

/// Event represents a Kubernetes Event.
#[derive(Debug, Clone)]
pub struct Event {
    /// Name of the event.
    pub name: String,
    /// Namespace of the event.
    pub namespace: String,
    /// The object that this event is about.
    pub involved_object: EventObjectReference,
    /// The component reporting this event.
    pub source: EventSource,
}

impl Event {
    /// Create a new event.
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            involved_object: EventObjectReference::default(),
            source: EventSource::default(),
        }
    }

    /// Create an event with a source component.
    pub fn with_source_component(name: &str, namespace: &str, component: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            involved_object: EventObjectReference::default(),
            source: EventSource {
                component: component.to_string(),
                host: String::new(),
            },
        }
    }
}

impl ApiObject for Event {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn kind(&self) -> &str {
        "Event"
    }
}

// ============================================================================
// Clock Trait (for testing)
// ============================================================================

/// Clock trait for abstracting time operations.
pub trait Clock: Send + Sync {
    /// Returns the current instant.
    fn now(&self) -> Instant;
}

/// Real clock implementation using system time.
#[derive(Debug, Clone, Default)]
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Fake clock for testing.
#[derive(Debug)]
pub struct FakeClock {
    current: Mutex<Instant>,
}

impl FakeClock {
    /// Create a new fake clock.
    pub fn new() -> Self {
        Self {
            current: Mutex::new(Instant::now()),
        }
    }

    /// Advance the clock by the given duration.
    pub fn step(&self, duration: Duration) {
        let mut current = self.current.lock().unwrap();
        *current += duration;
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.current.lock().unwrap()
    }
}

// ============================================================================
// Token Bucket Rate Limiter
// ============================================================================

/// TokenBucketRateLimiter implements a token bucket rate limiting algorithm.
pub struct TokenBucketRateLimiter {
    /// Tokens added per second.
    qps: f32,
    /// Maximum tokens in the bucket.
    burst: i32,
    /// Current available tokens (stored as float for precision).
    tokens: f32,
    /// Last time tokens were updated.
    last_update: Instant,
    /// Clock for time operations.
    clock: Arc<dyn Clock>,
}

impl TokenBucketRateLimiter {
    /// Create a new token bucket rate limiter.
    pub fn new(qps: f32, burst: i32, clock: Arc<dyn Clock>) -> Self {
        Self {
            qps,
            burst,
            tokens: burst as f32,
            last_update: clock.now(),
            clock,
        }
    }

    /// Try to accept a request. Returns true if the request is accepted.
    pub fn try_accept(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = self.clock.now();
        let elapsed = now.duration_since(self.last_update);
        let elapsed_secs = elapsed.as_secs_f32();

        // Add tokens based on elapsed time
        self.tokens += elapsed_secs * self.qps;

        // Cap at burst
        if self.tokens > self.burst as f32 {
            self.tokens = self.burst as f32;
        }

        self.last_update = now;
    }
}

/// Trait for rate limiters.
pub trait RateLimiter: Send + Sync {
    /// Try to accept a request.
    fn try_accept(&self) -> bool;
}

/// Thread-safe wrapper for TokenBucketRateLimiter.
pub struct SyncRateLimiter {
    inner: Mutex<TokenBucketRateLimiter>,
}

impl SyncRateLimiter {
    /// Create a new sync rate limiter.
    pub fn new(qps: f32, burst: i32, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(TokenBucketRateLimiter::new(qps, burst, clock)),
        }
    }
}

impl RateLimiter for SyncRateLimiter {
    fn try_accept(&self) -> bool {
        self.inner
            .lock()
            .expect("rate limiter lock poisoned")
            .try_accept()
    }
}

// ============================================================================
// Cache Implementations
// ============================================================================

/// Cache trait for storing rate limiters.
pub trait Cache: Send + Sync {
    /// Get the rate limiter for the given key.
    fn get(&self, key: &str) -> Arc<dyn RateLimiter>;
}

/// SingleCache is a cache that only stores a single, constant rate limiter.
/// Used for Server limit type.
pub struct SingleCache {
    rate_limiter: Arc<dyn RateLimiter>,
}

impl SingleCache {
    /// Create a new single cache.
    pub fn new(rate_limiter: Arc<dyn RateLimiter>) -> Self {
        Self { rate_limiter }
    }
}

impl Cache for SingleCache {
    fn get(&self, _key: &str) -> Arc<dyn RateLimiter> {
        Arc::clone(&self.rate_limiter)
    }
}

/// LRU cache entry.
struct LruEntry {
    rate_limiter: Arc<dyn RateLimiter>,
    /// Last access order (higher = more recent).
    order: u64,
}

/// LruCache is a least-recently-used cache for rate limiters.
pub struct LruCache {
    /// Maximum cache size.
    max_size: usize,
    /// QPS for new rate limiters.
    qps: f32,
    /// Burst for new rate limiters.
    burst: i32,
    /// Clock for rate limiters.
    clock: Arc<dyn Clock>,
    /// The actual cache.
    cache: RwLock<HashMap<String, LruEntry>>,
    /// Counter for LRU ordering.
    counter: Mutex<u64>,
}

impl LruCache {
    /// Create a new LRU cache.
    pub fn new(max_size: usize, qps: f32, burst: i32, clock: Arc<dyn Clock>) -> Self {
        Self {
            max_size,
            qps,
            burst,
            clock,
            cache: RwLock::new(HashMap::new()),
            counter: Mutex::new(0),
        }
    }

    /// Get the next order value.
    fn next_order(&self) -> u64 {
        let mut counter = self.counter.lock().expect("counter lock poisoned");
        *counter += 1;
        *counter
    }

    /// Evict least recently used entries if over capacity.
    fn evict_if_needed(&self, cache: &mut HashMap<String, LruEntry>) {
        while cache.len() >= self.max_size {
            // Find the entry with the lowest order
            let lru_key = cache
                .iter()
                .min_by_key(|(_, entry)| entry.order)
                .map(|(key, _)| key.clone());

            if let Some(key) = lru_key {
                cache.remove(&key);
            } else {
                break;
            }
        }
    }
}

impl Cache for LruCache {
    fn get(&self, key: &str) -> Arc<dyn RateLimiter> {
        // Try to get existing entry
        {
            let mut cache = self.cache.write().expect("cache lock poisoned");
            if let Some(entry) = cache.get_mut(key) {
                entry.order = self.next_order();
                return Arc::clone(&entry.rate_limiter);
            }
        }

        // Create new rate limiter
        let rate_limiter: Arc<dyn RateLimiter> =
            Arc::new(SyncRateLimiter::new(self.qps, self.burst, Arc::clone(&self.clock)));
        let order = self.next_order();

        let mut cache = self.cache.write().expect("cache lock poisoned");

        // Check again in case another thread added it
        if let Some(entry) = cache.get(key) {
            return Arc::clone(&entry.rate_limiter);
        }

        // Evict if needed
        self.evict_if_needed(&mut cache);

        // Insert new entry
        cache.insert(
            key.to_string(),
            LruEntry {
                rate_limiter: Arc::clone(&rate_limiter),
                order,
            },
        );

        rate_limiter
    }
}

// ============================================================================
// Limit Enforcer
// ============================================================================

/// Key function type for extracting cache keys from attributes.
type KeyFn = Box<dyn Fn(&dyn Attributes) -> String + Send + Sync>;

/// LimitEnforcer enforces a single type of event rate limit.
pub struct LimitEnforcer {
    /// Type of this limit.
    limit_type: LimitType,
    /// Cache for holding the rate limiters.
    cache: Arc<dyn Cache>,
    /// Key function for computing cache keys.
    key_fn: KeyFn,
}

impl LimitEnforcer {
    /// Create a new limit enforcer.
    pub fn new(config: &Limit, clock: Arc<dyn Clock>) -> Result<Self, String> {
        let (cache, key_fn): (Arc<dyn Cache>, KeyFn) = match config.limit_type {
            LimitType::Server => {
                let rate_limiter: Arc<dyn RateLimiter> =
                    Arc::new(SyncRateLimiter::new(config.qps, config.burst, clock));
                (
                    Arc::new(SingleCache::new(rate_limiter)),
                    Box::new(get_server_key),
                )
            }
            LimitType::Namespace => {
                let cache_size = if config.cache_size == 0 {
                    DEFAULT_CACHE_SIZE
                } else {
                    config.cache_size
                };
                (
                    Arc::new(LruCache::new(cache_size, config.qps, config.burst, clock)),
                    Box::new(get_namespace_key),
                )
            }
            LimitType::User => {
                let cache_size = if config.cache_size == 0 {
                    DEFAULT_CACHE_SIZE
                } else {
                    config.cache_size
                };
                (
                    Arc::new(LruCache::new(cache_size, config.qps, config.burst, clock)),
                    Box::new(get_user_key),
                )
            }
            LimitType::SourceAndObject => {
                let cache_size = if config.cache_size == 0 {
                    DEFAULT_CACHE_SIZE
                } else {
                    config.cache_size
                };
                (
                    Arc::new(LruCache::new(cache_size, config.qps, config.burst, clock)),
                    Box::new(get_source_and_object_key),
                )
            }
        };

        Ok(Self {
            limit_type: config.limit_type,
            cache,
            key_fn,
        })
    }

    /// Accept or reject a request based on the rate limit.
    pub fn accept(&self, attr: &dyn Attributes) -> Result<(), String> {
        let key = (self.key_fn)(attr);
        let rate_limiter = self.cache.get(&key);

        if !rate_limiter.try_accept() {
            return Err(format!(
                "limit reached on type {} for key {}",
                self.limit_type, key
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Key Functions
// ============================================================================

/// Get server key (always empty, single bucket).
fn get_server_key(_attr: &dyn Attributes) -> String {
    String::new()
}

/// Get namespace key based on the namespace of the event request.
fn get_namespace_key(attr: &dyn Attributes) -> String {
    attr.get_namespace().to_string()
}

/// Get user key based on the user of the event request.
/// Note: In this implementation, we use the name from attributes as a proxy for user.
fn get_user_key(attr: &dyn Attributes) -> String {
    // In a full implementation, this would use attr.GetUserInfo().GetName()
    // For now, we'll use the request name as a placeholder
    attr.get_name().to_string()
}

/// Get source and object key based on the source+object of the event.
fn get_source_and_object_key(attr: &dyn Attributes) -> String {
    let obj = match attr.get_object() {
        Some(o) => o,
        None => return String::new(),
    };

    let event = match obj.as_any().downcast_ref::<Event>() {
        Some(e) => e,
        None => return String::new(),
    };

    // Concatenate all components of source and involved object
    format!(
        "{}{}{}{}{}{}{}",
        event.source.component,
        event.source.host,
        event.involved_object.kind,
        event.involved_object.namespace,
        event.involved_object.name,
        event.involved_object.uid,
        event.involved_object.api_version,
    )
}

// ============================================================================
// Plugin Implementation
// ============================================================================

/// Register the EventRateLimit plugin with the plugin registry.
pub fn register(plugins: &Plugins) {
    plugins.register(PLUGIN_NAME, |_config: Option<&mut dyn Read>| {
        Ok(Arc::new(Plugin::new()) as Arc<dyn Interface>)
    });
}

/// Plugin implements an admission controller that can enforce event rate limits.
pub struct Plugin {
    handler: Handler,
    /// Collection of limit enforcers. There is one limit enforcer for each
    /// active limit type.
    limit_enforcers: Vec<LimitEnforcer>,
}

impl Plugin {
    /// Create a new EventRateLimit plugin with default configuration.
    pub fn new() -> Self {
        Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            limit_enforcers: Vec::new(),
        }
    }

    /// Create a new EventRateLimit plugin with the given configuration.
    pub fn with_config(config: &Configuration, clock: Arc<dyn Clock>) -> Result<Self, String> {
        let mut limit_enforcers = Vec::with_capacity(config.limits.len());

        for limit_config in &config.limits {
            let enforcer = LimitEnforcer::new(limit_config, Arc::clone(&clock))?;
            limit_enforcers.push(enforcer);
        }

        Ok(Self {
            handler: Handler::new(&[Operation::Create, Operation::Update]),
            limit_enforcers,
        })
    }
}

impl Default for Plugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for Plugin {
    fn handles(&self, operation: Operation) -> bool {
        self.handler.handles(operation)
    }
}

impl ValidationInterface for Plugin {
    fn validate(&self, attributes: &dyn Attributes) -> AdmissionResult<()> {
        // Ignore all operations that do not correspond to an Event kind
        let kind = attributes.get_kind();
        if kind.kind != "Event" {
            return Ok(());
        }

        // Ignore all requests that specify dry-run
        // because they don't correspond to any calls to etcd,
        // they should not be affected by the ratelimit
        if attributes.is_dry_run() {
            return Ok(());
        }

        let mut errors = Vec::new();

        // Give each limit enforcer a chance to reject the event
        for enforcer in &self.limit_enforcers {
            if let Err(e) = enforcer.accept(attributes) {
                errors.push(e);
            }
        }

        if !errors.is_empty() {
            return Err(AdmissionError::too_many_requests(&errors.join("; ")));
        }

        Ok(())
    }
}

// ============================================================================
// Extended Attributes for User Info
// ============================================================================

/// Extended attributes that include user information.
pub trait ExtendedAttributes: Attributes {
    /// Get the username of the requester.
    fn get_username(&self) -> &str;
}

/// Extended attributes record with user info.
pub struct ExtendedAttributesRecord {
    /// Base attributes.
    pub inner: crate::admission::AttributesRecord,
    /// Username of the requester.
    pub username: String,
}

impl ExtendedAttributesRecord {
    /// Create new extended attributes with user info.
    pub fn new(inner: crate::admission::AttributesRecord, username: &str) -> Self {
        Self {
            inner,
            username: username.to_string(),
        }
    }
}

impl Attributes for ExtendedAttributesRecord {
    fn get_name(&self) -> &str {
        self.inner.get_name()
    }

    fn get_namespace(&self) -> &str {
        self.inner.get_namespace()
    }

    fn get_resource(&self) -> &crate::admission::attributes::GroupVersionResource {
        self.inner.get_resource()
    }

    fn get_subresource(&self) -> &str {
        self.inner.get_subresource()
    }

    fn get_operation(&self) -> Operation {
        self.inner.get_operation()
    }

    fn get_object(&self) -> Option<&dyn ApiObject> {
        self.inner.get_object()
    }

    fn get_object_mut(&mut self) -> Option<&mut (dyn ApiObject + 'static)> {
        self.inner.get_object_mut()
    }

    fn get_old_object(&self) -> Option<&dyn ApiObject> {
        self.inner.get_old_object()
    }

    fn get_kind(&self) -> &crate::admission::attributes::GroupVersionKind {
        self.inner.get_kind()
    }

    fn is_dry_run(&self) -> bool {
        self.inner.is_dry_run()
    }
}

impl ExtendedAttributes for ExtendedAttributesRecord {
    fn get_username(&self) -> &str {
        &self.username
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::attributes::{AttributesRecord, GroupVersionKind, GroupVersionResource};
    use std::time::Duration;

    const QPS: f32 = 1.0;

    /// Create attributes for a request.
    fn attributes_for_request(
        kind: &str,
        namespace: &str,
        username: &str,
        event: Option<Event>,
        dry_run: bool,
    ) -> ExtendedAttributesRecord {
        let gvr = GroupVersionResource::new("", "v1", "events");
        let gvk = GroupVersionKind::new("", "v1", kind);

        let inner = AttributesRecord::new(
            "name",
            namespace,
            gvr,
            "",
            Operation::Create,
            event.map(|e| Box::new(e) as Box<dyn ApiObject>),
            None,
            gvk,
            dry_run,
        );

        ExtendedAttributesRecord::new(inner, username)
    }

    /// Create an event request.
    fn new_event_request() -> ExtendedAttributesRecord {
        attributes_for_request("Event", "", "", None, false)
    }

    /// Create a non-event request.
    fn new_non_event_request() -> ExtendedAttributesRecord {
        attributes_for_request("NonEvent", "", "", None, false)
    }

    /// Create an event request with namespace.
    fn new_event_request_with_namespace(namespace: &str) -> ExtendedAttributesRecord {
        attributes_for_request("Event", namespace, "", None, false)
    }

    /// Create an event request with user.
    fn new_event_request_with_user(username: &str) -> ExtendedAttributesRecord {
        let gvr = GroupVersionResource::new("", "v1", "events");
        let gvk = GroupVersionKind::new("", "v1", "Event");

        let inner = AttributesRecord::new(
            username, // Use username as name for user key extraction
            "",
            gvr,
            "",
            Operation::Create,
            None,
            None,
            gvk,
            false,
        );

        ExtendedAttributesRecord::new(inner, username)
    }

    /// Create an event request with event component.
    fn new_event_request_with_component(component: &str) -> ExtendedAttributesRecord {
        let event = Event::with_source_component("test", "default", component);
        attributes_for_request("Event", "", "", Some(event), false)
    }

    /// Create an event request with dry run.
    fn new_event_request_with_dry_run(dry_run: bool) -> ExtendedAttributesRecord {
        attributes_for_request("Event", "", "", None, dry_run)
    }

    /// Create an event request with a specific event.
    fn new_event_request_with_event(event: Event) -> ExtendedAttributesRecord {
        attributes_for_request("Event", "", "", Some(event), false)
    }

    #[test]
    fn test_handles() {
        let plugin = Plugin::new();
        assert!(plugin.handles(Operation::Create));
        assert!(plugin.handles(Operation::Update));
        assert!(!plugin.handles(Operation::Delete));
        assert!(!plugin.handles(Operation::Connect));
    }

    #[test]
    fn test_plugin_registration() {
        let plugins = Plugins::new();
        register(&plugins);
        assert!(plugins.is_registered(PLUGIN_NAME));
    }

    #[test]
    fn test_event_not_blocked_when_tokens_available() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 3));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        let attrs = new_event_request();
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_non_event_not_blocked() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 3));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        let attrs = new_non_event_request();
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_event_blocked_after_tokens_exhausted() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 3));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // First 3 should succeed
        for _ in 0..3 {
            let attrs = new_event_request();
            assert!(plugin.validate(&attrs).is_ok());
        }

        // 4th should be blocked
        let attrs = new_event_request();
        assert!(plugin.validate(&attrs).is_err());
    }

    #[test]
    fn test_event_not_blocked_by_dry_run_requests() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 3));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Use 2 tokens
        for _ in 0..2 {
            let attrs = new_event_request();
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Dry run requests should not consume tokens
        for _ in 0..4 {
            let attrs = new_event_request_with_dry_run(true);
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Should still have 1 token left
        let attrs = new_event_request();
        assert!(plugin.validate(&attrs).is_ok());

        // Now should be blocked
        let attrs = new_event_request();
        assert!(plugin.validate(&attrs).is_err());

        // Dry run should still work
        let attrs = new_event_request_with_dry_run(true);
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_non_event_not_blocked_after_tokens_exhausted() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 3));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Exhaust tokens
        for _ in 0..3 {
            let attrs = new_event_request();
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Non-event should still pass
        let attrs = new_non_event_request();
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_non_events_should_not_count_against_limit() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 3));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // 2 events
        for _ in 0..2 {
            let attrs = new_event_request();
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Non-event
        let attrs = new_non_event_request();
        assert!(plugin.validate(&attrs).is_ok());

        // 3rd event should still work
        let attrs = new_event_request();
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_event_accepted_after_token_refill() {
        let clock = Arc::new(FakeClock::new());
        let clock_dyn: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 3));

        let plugin = Plugin::with_config(&config, clock_dyn).unwrap();

        // Exhaust tokens
        for _ in 0..3 {
            let attrs = new_event_request();
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Should be blocked
        let attrs = new_event_request();
        assert!(plugin.validate(&attrs).is_err());

        // Wait for refill
        clock.step(Duration::from_secs(1));

        // Should work now
        let attrs = new_event_request();
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_event_blocked_by_namespace_limits() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::Namespace, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Exhaust namespace A tokens
        for _ in 0..3 {
            let attrs = new_event_request_with_namespace("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Namespace A should be blocked
        let attrs = new_event_request_with_namespace("A");
        assert!(plugin.validate(&attrs).is_err());
    }

    #[test]
    fn test_event_from_other_namespace_not_blocked() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::Namespace, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Exhaust namespace A tokens
        for _ in 0..3 {
            let attrs = new_event_request_with_namespace("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Namespace B should still work
        let attrs = new_event_request_with_namespace("B");
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_events_from_other_namespaces_should_not_count_against_limit() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::Namespace, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // 2 from A
        for _ in 0..2 {
            let attrs = new_event_request_with_namespace("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // 1 from B
        let attrs = new_event_request_with_namespace("B");
        assert!(plugin.validate(&attrs).is_ok());

        // 3rd from A should still work
        let attrs = new_event_request_with_namespace("A");
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_event_accepted_after_namespace_token_refill() {
        let clock = Arc::new(FakeClock::new());
        let clock_dyn: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::Namespace, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock_dyn).unwrap();

        // Exhaust namespace A tokens
        for _ in 0..3 {
            let attrs = new_event_request_with_namespace("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Should be blocked
        let attrs = new_event_request_with_namespace("A");
        assert!(plugin.validate(&attrs).is_err());

        // Wait for refill
        clock.step(Duration::from_secs(1));

        // Should work now
        let attrs = new_event_request_with_namespace("A");
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_namespace_limits_from_lru_should_clear_when_cache_size_exceeded() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::Namespace, QPS, 3, 2));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Use some of A's tokens
        for _ in 0..2 {
            let attrs = new_event_request_with_namespace("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Exhaust B's tokens
        for _ in 0..3 {
            let attrs = new_event_request_with_namespace("B");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Use A's last token (this makes A more recent than B)
        let attrs = new_event_request_with_namespace("A");
        assert!(plugin.validate(&attrs).is_ok());

        // Both should be blocked now
        let attrs = new_event_request_with_namespace("B");
        assert!(plugin.validate(&attrs).is_err());
        let attrs = new_event_request_with_namespace("A");
        assert!(plugin.validate(&attrs).is_err());

        // Adding C should evict B (LRU)
        let attrs = new_event_request_with_namespace("C");
        assert!(plugin.validate(&attrs).is_ok());

        // A should still be blocked
        let attrs = new_event_request_with_namespace("A");
        assert!(plugin.validate(&attrs).is_err());

        // B should work now (fresh bucket after eviction)
        let attrs = new_event_request_with_namespace("B");
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_event_blocked_by_source_and_object_limits() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::SourceAndObject, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Exhaust component A tokens
        for _ in 0..3 {
            let attrs = new_event_request_with_component("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Component A should be blocked
        let attrs = new_event_request_with_component("A");
        assert!(plugin.validate(&attrs).is_err());
    }

    #[test]
    fn test_event_from_other_source_and_object_not_blocked() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::SourceAndObject, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Exhaust component A tokens
        for _ in 0..3 {
            let attrs = new_event_request_with_component("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Component B should still work
        let attrs = new_event_request_with_component("B");
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_event_accepted_after_source_and_object_token_refill() {
        let clock = Arc::new(FakeClock::new());
        let clock_dyn: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::SourceAndObject, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock_dyn).unwrap();

        // Exhaust component A tokens
        for _ in 0..3 {
            let attrs = new_event_request_with_component("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // Should be blocked
        let attrs = new_event_request_with_component("A");
        assert!(plugin.validate(&attrs).is_err());

        // Wait for refill
        clock.step(Duration::from_secs(1));

        // Should work now
        let attrs = new_event_request_with_component("A");
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_source_host_should_be_included_in_source_and_object_key() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::SourceAndObject, QPS, 1, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Create events with different hosts
        let mut event_a = Event::new("test", "default");
        event_a.source.host = "A".to_string();

        let mut event_b = Event::new("test", "default");
        event_b.source.host = "B".to_string();

        // First request with host A should work
        let attrs = new_event_request_with_event(event_a.clone());
        assert!(plugin.validate(&attrs).is_ok());

        // Second request with host A should be blocked
        let attrs = new_event_request_with_event(event_a);
        assert!(plugin.validate(&attrs).is_err());

        // Request with host B should work (different key)
        let attrs = new_event_request_with_event(event_b);
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_involved_object_kind_should_be_included_in_source_and_object_key() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::SourceAndObject, QPS, 1, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        let mut event_a = Event::new("test", "default");
        event_a.involved_object.kind = "A".to_string();

        let mut event_b = Event::new("test", "default");
        event_b.involved_object.kind = "B".to_string();

        let attrs = new_event_request_with_event(event_a.clone());
        assert!(plugin.validate(&attrs).is_ok());

        let attrs = new_event_request_with_event(event_a);
        assert!(plugin.validate(&attrs).is_err());

        let attrs = new_event_request_with_event(event_b);
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_involved_object_namespace_should_be_included_in_source_and_object_key() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::SourceAndObject, QPS, 1, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        let mut event_a = Event::new("test", "default");
        event_a.involved_object.namespace = "A".to_string();

        let mut event_b = Event::new("test", "default");
        event_b.involved_object.namespace = "B".to_string();

        let attrs = new_event_request_with_event(event_a.clone());
        assert!(plugin.validate(&attrs).is_ok());

        let attrs = new_event_request_with_event(event_a);
        assert!(plugin.validate(&attrs).is_err());

        let attrs = new_event_request_with_event(event_b);
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_involved_object_name_should_be_included_in_source_and_object_key() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::SourceAndObject, QPS, 1, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        let mut event_a = Event::new("test", "default");
        event_a.involved_object.name = "A".to_string();

        let mut event_b = Event::new("test", "default");
        event_b.involved_object.name = "B".to_string();

        let attrs = new_event_request_with_event(event_a.clone());
        assert!(plugin.validate(&attrs).is_ok());

        let attrs = new_event_request_with_event(event_a);
        assert!(plugin.validate(&attrs).is_err());

        let attrs = new_event_request_with_event(event_b);
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_involved_object_uid_should_be_included_in_source_and_object_key() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::SourceAndObject, QPS, 1, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        let mut event_a = Event::new("test", "default");
        event_a.involved_object.uid = "A".to_string();

        let mut event_b = Event::new("test", "default");
        event_b.involved_object.uid = "B".to_string();

        let attrs = new_event_request_with_event(event_a.clone());
        assert!(plugin.validate(&attrs).is_ok());

        let attrs = new_event_request_with_event(event_a);
        assert!(plugin.validate(&attrs).is_err());

        let attrs = new_event_request_with_event(event_b);
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_involved_object_api_version_should_be_included_in_source_and_object_key() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::new(LimitType::Server, QPS, 100));
        config.add_limit(Limit::with_cache_size(LimitType::SourceAndObject, QPS, 1, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        let mut event_a = Event::new("test", "default");
        event_a.involved_object.api_version = "A".to_string();

        let mut event_b = Event::new("test", "default");
        event_b.involved_object.api_version = "B".to_string();

        let attrs = new_event_request_with_event(event_a.clone());
        assert!(plugin.validate(&attrs).is_ok());

        let attrs = new_event_request_with_event(event_a);
        assert!(plugin.validate(&attrs).is_err());

        let attrs = new_event_request_with_event(event_b);
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_event_blocked_by_user_limits() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::with_cache_size(LimitType::User, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Exhaust user A tokens
        for _ in 0..3 {
            let attrs = new_event_request_with_user("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // User A should be blocked
        let attrs = new_event_request_with_user("A");
        assert!(plugin.validate(&attrs).is_err());
    }

    #[test]
    fn test_event_from_other_user_not_blocked() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::with_cache_size(LimitType::User, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // Exhaust user A tokens
        for _ in 0..3 {
            let attrs = new_event_request_with_user("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // User B should still work
        let attrs = new_event_request_with_user("B");
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_events_from_other_user_should_not_count_against_limit() {
        let clock = Arc::new(FakeClock::new());
        let mut config = Configuration::new();
        config.add_limit(Limit::with_cache_size(LimitType::User, QPS, 3, 10));

        let plugin = Plugin::with_config(&config, clock).unwrap();

        // 2 from A
        for _ in 0..2 {
            let attrs = new_event_request_with_user("A");
            assert!(plugin.validate(&attrs).is_ok());
        }

        // 1 from B
        let attrs = new_event_request_with_user("B");
        assert!(plugin.validate(&attrs).is_ok());

        // 3rd from A should still work
        let attrs = new_event_request_with_user("A");
        assert!(plugin.validate(&attrs).is_ok());
    }

    #[test]
    fn test_single_cache() {
        let clock = Arc::new(FakeClock::new());
        let rate_limiter: Arc<dyn RateLimiter> = Arc::new(SyncRateLimiter::new(1.0, 1, clock));
        let cache = SingleCache::new(rate_limiter);

        // All keys should return the same rate limiter
        let rl1 = cache.get("key1");
        let rl2 = cache.get("key2");
        let rl3 = cache.get("");

        // First try_accept should work
        assert!(rl1.try_accept());
        // Subsequent should fail (same limiter)
        assert!(!rl2.try_accept());
        assert!(!rl3.try_accept());
    }

    #[test]
    fn test_lru_cache() {
        let clock = Arc::new(FakeClock::new());
        let cache = LruCache::new(2, 1.0, 1, clock);

        // Get limiter for key 0
        let rl0 = cache.get("0");
        assert!(rl0.try_accept());
        assert!(!rl0.try_accept()); // exhausted

        // Get limiter for key 0 again (should be same)
        let rl0_again = cache.get("0");
        assert!(!rl0_again.try_accept()); // still exhausted

        // Get limiter for key 1
        let rl1 = cache.get("1");
        assert!(rl1.try_accept());
        assert!(!rl1.try_accept());

        // Get limiter for key 1 again
        let rl1_again = cache.get("1");
        assert!(!rl1_again.try_accept());

        // Access key 0 to make it more recent
        let _ = cache.get("0");

        // Get limiter for key 2 (should evict key 1)
        let rl2 = cache.get("2");
        assert!(rl2.try_accept());

        // Key 0 should still be exhausted
        let rl0_third = cache.get("0");
        assert!(!rl0_third.try_accept());

        // Key 1 should have fresh bucket (was evicted and re-added)
        let rl1_fresh = cache.get("1");
        assert!(rl1_fresh.try_accept());
    }

    #[test]
    fn test_token_bucket_rate_limiter() {
        let clock = Arc::new(FakeClock::new());
        let clock_dyn: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
        let mut limiter = TokenBucketRateLimiter::new(1.0, 3, clock_dyn);

        // Should allow 3 requests (burst)
        assert!(limiter.try_accept());
        assert!(limiter.try_accept());
        assert!(limiter.try_accept());

        // 4th should be blocked
        assert!(!limiter.try_accept());

        // Wait 1 second for 1 token to refill
        clock.step(Duration::from_secs(1));
        assert!(limiter.try_accept());
        assert!(!limiter.try_accept());

        // Wait 3 seconds for full refill
        clock.step(Duration::from_secs(3));
        assert!(limiter.try_accept());
        assert!(limiter.try_accept());
        assert!(limiter.try_accept());
        assert!(!limiter.try_accept());
    }

    #[test]
    fn test_limit_enforcer_server() {
        let clock = Arc::new(FakeClock::new());
        let limit = Limit::new(LimitType::Server, 1.0, 2);
        let enforcer = LimitEnforcer::new(&limit, clock).unwrap();

        let attrs = new_event_request();

        assert!(enforcer.accept(&attrs).is_ok());
        assert!(enforcer.accept(&attrs).is_ok());
        assert!(enforcer.accept(&attrs).is_err());
    }

    #[test]
    fn test_limit_enforcer_namespace() {
        let clock = Arc::new(FakeClock::new());
        let limit = Limit::with_cache_size(LimitType::Namespace, 1.0, 1, 10);
        let enforcer = LimitEnforcer::new(&limit, clock).unwrap();

        let attrs_a = new_event_request_with_namespace("ns-a");
        let attrs_b = new_event_request_with_namespace("ns-b");

        assert!(enforcer.accept(&attrs_a).is_ok());
        assert!(enforcer.accept(&attrs_a).is_err());

        assert!(enforcer.accept(&attrs_b).is_ok());
        assert!(enforcer.accept(&attrs_b).is_err());
    }

    #[test]
    fn test_configuration() {
        let mut config = Configuration::new();
        assert!(config.limits.is_empty());

        config.add_limit(Limit::new(LimitType::Server, 10.0, 100));
        assert_eq!(config.limits.len(), 1);

        config.add_limit(Limit::with_cache_size(LimitType::Namespace, 5.0, 50, 1000));
        assert_eq!(config.limits.len(), 2);
    }

    #[test]
    fn test_event_type() {
        let event = Event::new("my-event", "my-namespace");
        assert_eq!(event.name, "my-event");
        assert_eq!(event.namespace, "my-namespace");
        assert_eq!(event.kind(), "Event");

        let event = Event::with_source_component("my-event", "my-namespace", "kubelet");
        assert_eq!(event.source.component, "kubelet");
    }

    #[test]
    fn test_limit_type_display() {
        assert_eq!(format!("{}", LimitType::Server), "Server");
        assert_eq!(format!("{}", LimitType::Namespace), "Namespace");
        assert_eq!(format!("{}", LimitType::User), "User");
        assert_eq!(format!("{}", LimitType::SourceAndObject), "SourceAndObject");
    }
}
