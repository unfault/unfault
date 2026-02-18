use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::config::EngineConfig;
use crate::error::EngineError;
use crate::profiles::ProfileRegistry;
use crate::rules::registry::RuleRegistry;
use crate::session::InternalSessionState;
use crate::types::context::SessionContextInput;
use crate::types::meta::ReviewSessionMeta;
use crate::types::session_result::ReviewSessionResult;

/// The Unfault analysis engine.
///
/// Thread-safe and designed for concurrent use. Configuration, rules, and profiles
/// can be hot-swapped via `ArcSwap`.
///
/// # Profile-based Analysis
///
/// The engine supports profile-based analysis where:
/// 1. Clients advertise which profiles they think apply to their project
/// 2. The engine resolves these to internal Profile definitions
/// 3. Profiles determine which rules are active and provide file selection hints
///
/// # Usage
///
/// ```rust,ignore
/// use unfault_engine::engine::Engine;
/// use unfault_engine::types::meta::ReviewSessionMeta;
/// use unfault_engine::types::context::SessionContextInput;
///
/// let engine = Engine::with_default_config();
///
/// // Analyze with all rules
/// let result = engine.analyze(meta, contexts).await?;
///
/// // Or analyze with specific rule IDs (from resolved profiles)
/// let result = engine.analyze_with_rules(meta, contexts, &rule_ids).await?;
/// ```
pub struct Engine {
    pub config: ArcSwap<EngineConfig>,
    pub rule_registry: ArcSwap<RuleRegistry>,
    pub profile_registry: ArcSwap<ProfileRegistry>,
}

impl Engine {
    /// Create a new engine with the given configuration, rules, and profiles.
    pub fn new(
        config: EngineConfig,
        rule_registry: RuleRegistry,
        profile_registry: ProfileRegistry,
    ) -> Self {
        Self {
            config: ArcSwap::from_pointee(config),
            rule_registry: ArcSwap::from_pointee(rule_registry),
            profile_registry: ArcSwap::from_pointee(profile_registry),
        }
    }

    /// Convenience constructor with default configuration, built-in rules, and built-in profiles.
    pub fn with_default_config() -> Self {
        Self::new(
            EngineConfig::default(),
            RuleRegistry::with_builtin_rules(),
            ProfileRegistry::with_builtin_profiles(),
        )
    }

    /// Convenience constructor with default config and empty registries.
    ///
    /// Useful for testing when you want to register rules/profiles manually.
    pub fn with_defaults_and_builtin_rules() -> Self {
        let config = EngineConfig::default();
        let registry = RuleRegistry::new();
        let profiles = ProfileRegistry::new();
        Self::new(config, registry, profiles)
    }

    /// Main entry point: analyze a set of contexts and return all findings.
    ///
    /// This uses all rules in the registry. For profile-based analysis,
    /// use `analyze_with_rules` with the rule IDs from resolved profiles.
    ///
    /// This is pure from the caller's perspective:
    /// - no channels
    /// - no streaming
    /// - one request in, one result out
    ///
    /// The engine is stateless between calls; all state lives inside the call.
    pub async fn analyze(
        &self,
        meta: ReviewSessionMeta,
        contexts: Vec<SessionContextInput>,
    ) -> Result<ReviewSessionResult, EngineError> {
        let rules = self.rule_registry.load_full();
        let mut state = InternalSessionState::new(meta, contexts, rules);
        state.run().await
    }

    /// Analyze with a specific set of rules (by ID).
    ///
    /// This is the preferred method for profile-based analysis:
    /// 1. Client creates a session with advertised profiles
    /// 2. Server resolves profiles and returns rule IDs
    /// 3. Client uploads files and calls this method with the rule IDs
    ///
    /// Rules not found in the registry are silently ignored.
    pub async fn analyze_with_rules(
        &self,
        meta: ReviewSessionMeta,
        contexts: Vec<SessionContextInput>,
        rule_ids: &[String],
    ) -> Result<ReviewSessionResult, EngineError> {
        let full_registry = self.rule_registry.load_full();
        let filtered_registry = full_registry.filter_by_ids(rule_ids);
        let mut state = InternalSessionState::new(meta, contexts, Arc::new(filtered_registry));
        state.run().await
    }

    /// Get the profile registry.
    pub fn profiles(&self) -> arc_swap::Guard<Arc<ProfileRegistry>> {
        self.profile_registry.load()
    }

    /// Get the rule registry.
    pub fn rules(&self) -> arc_swap::Guard<Arc<RuleRegistry>> {
        self.rule_registry.load()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_engine_new_with_custom_config() {
        let config = EngineConfig {
            max_parallel_files: 32,
        };
        let registry = RuleRegistry::new();
        let profiles = ProfileRegistry::new();
        let engine = Engine::new(config, registry, profiles);

        let loaded_config = engine.config.load();
        assert_eq!(loaded_config.max_parallel_files, 32);
    }

    #[test]
    fn test_engine_with_default_config() {
        let engine = Engine::with_default_config();

        let loaded_config = engine.config.load();
        assert_eq!(loaded_config.max_parallel_files, 16);
    }

    #[test]
    fn test_engine_with_defaults_and_builtin_rules() {
        let engine = Engine::with_defaults_and_builtin_rules();

        let loaded_config = engine.config.load();
        assert_eq!(loaded_config.max_parallel_files, 16);

        // Registry should be empty (no rules registered in this constructor)
        let registry = engine.rule_registry.load();
        assert_eq!(registry.all().len(), 0);
    }

    #[test]
    fn test_engine_config_is_arc_swappable() {
        let engine = Engine::with_default_config();

        // Verify we can load the config
        let config1 = engine.config.load();
        assert_eq!(config1.max_parallel_files, 16);

        // Swap in a new config
        let new_config = EngineConfig {
            max_parallel_files: 64,
        };
        engine.config.store(Arc::new(new_config));

        // Verify the new config is loaded
        let config2 = engine.config.load();
        assert_eq!(config2.max_parallel_files, 64);
    }

    #[test]
    fn test_engine_rule_registry_is_arc_swappable() {
        let engine = Engine::with_default_config();

        // Load initial registry
        let registry1 = engine.rule_registry.load();
        let initial_count = registry1.all().len();

        // Swap in a new registry (empty)
        let new_registry = RuleRegistry::new();
        engine.rule_registry.store(Arc::new(new_registry));

        // Verify the new registry is loaded
        let registry2 = engine.rule_registry.load();
        assert_eq!(registry2.all().len(), 0);

        // The initial count should be >= 0 (builtin rules may or may not be present)
        assert!(initial_count >= 0);
    }

    #[test]
    fn test_engine_config_load_full() {
        let engine = Engine::with_default_config();

        // load_full returns Arc<EngineConfig>
        let config_arc = engine.config.load_full();
        assert_eq!(config_arc.max_parallel_files, 16);
    }

    #[test]
    fn test_engine_registry_load_full() {
        let engine = Engine::with_default_config();

        // load_full returns Arc<RuleRegistry>
        let registry_arc = engine.rule_registry.load_full();
        // Just verify we can access it
        let _ = registry_arc.all();
    }

    #[tokio::test]
    async fn test_engine_analyze_empty_contexts() {
        let engine = Engine::with_defaults_and_builtin_rules();

        let meta = ReviewSessionMeta::default();
        let contexts = vec![];

        let result = engine.analyze(meta, contexts).await;

        assert!(result.is_ok());
        let session_result = result.unwrap();
        assert_eq!(session_result.contexts.len(), 0);
    }

    #[tokio::test]
    async fn test_engine_analyze_with_context() {
        use crate::types::context::{Dimension, Language, SourceFile};

        let engine = Engine::with_defaults_and_builtin_rules();

        let meta = ReviewSessionMeta::default();
        let contexts = vec![SessionContextInput {
            id: "ctx-1".to_string(),
            label: "Test Context".to_string(),
            dimension: Dimension::Stability,
            files: vec![SourceFile {
                path: "test.py".to_string(),
                language: Language::Python,
                content: "print('hello')".to_string(),
            }],
        }];

        let result = engine.analyze(meta, contexts).await;

        assert!(result.is_ok());
        let session_result = result.unwrap();
        assert_eq!(session_result.contexts.len(), 1);
        assert_eq!(session_result.contexts[0].context_id, "ctx-1");
    }

    #[test]
    fn test_engine_multiple_instances_independent() {
        let engine1 = Engine::with_default_config();
        let engine2 = Engine::with_default_config();

        // Modify engine1's config
        engine1.config.store(Arc::new(EngineConfig {
            max_parallel_files: 100,
        }));

        // engine2 should still have default config
        let config2 = engine2.config.load();
        assert_eq!(config2.max_parallel_files, 16);

        // engine1 should have modified config
        let config1 = engine1.config.load();
        assert_eq!(config1.max_parallel_files, 100);
    }
}
