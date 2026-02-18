//! Profile registry and built-in profiles.
//!
//! This module provides the ProfileRegistry which manages available profiles
//! and resolves advertised profiles from clients to internal Profile definitions.

use std::collections::HashMap;
use std::sync::Arc;

use crate::types::profile::{FileQueryHint, Profile};
use crate::types::workspace::AdvertisedProfile;

mod builtin;

pub use builtin::register_builtin_profiles;

/// Registry of available profiles.
///
/// The ProfileRegistry manages all known profiles and provides methods to:
/// - Register new profiles
/// - Look up profiles by ID
/// - Resolve advertised profiles from clients
#[derive(Debug, Default, Clone)]
pub struct ProfileRegistry {
    profiles: HashMap<String, Arc<Profile>>,
}

impl ProfileRegistry {
    /// Create a new empty profile registry.
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    /// Create a registry with built-in profiles.
    pub fn with_builtin_profiles() -> Self {
        let mut registry = Self::new();
        register_builtin_profiles(&mut registry);
        registry
    }

    /// Register a profile.
    pub fn register(&mut self, profile: Profile) {
        self.profiles.insert(profile.id.clone(), Arc::new(profile));
    }

    /// Get a profile by ID.
    pub fn get(&self, id: &str) -> Option<Arc<Profile>> {
        self.profiles.get(id).cloned()
    }

    /// Get all registered profiles.
    pub fn all(&self) -> Vec<Arc<Profile>> {
        self.profiles.values().cloned().collect()
    }

    /// Get all profile IDs.
    pub fn ids(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a profile exists.
    pub fn contains(&self, id: &str) -> bool {
        self.profiles.contains_key(id)
    }

    /// Number of registered profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Resolve advertised profiles to internal profiles.
    ///
    /// Returns a list of resolved profiles, ordered by the client's confidence.
    /// Profiles that don't exist in the registry are skipped.
    pub fn resolve(&self, advertised: &[AdvertisedProfile]) -> Vec<Arc<Profile>> {
        let mut resolved: Vec<(f32, Arc<Profile>)> = advertised
            .iter()
            .filter_map(|ap| {
                self.profiles
                    .get(&ap.id)
                    .map(|p| (ap.confidence, Arc::clone(p)))
            })
            .collect();

        // Sort by confidence (highest first)
        resolved.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        resolved.into_iter().map(|(_, p)| p).collect()
    }

    /// Collect all rule IDs from the given profiles.
    ///
    /// Returns a deduplicated list of rule IDs.
    pub fn collect_rule_ids(&self, profiles: &[Arc<Profile>]) -> Vec<String> {
        let mut rule_ids: Vec<String> = profiles
            .iter()
            .flat_map(|p| p.rule_ids.iter().cloned())
            .collect();

        // Deduplicate while preserving order
        let mut seen = std::collections::HashSet::new();
        rule_ids.retain(|id| seen.insert(id.clone()));

        rule_ids
    }

    /// Collect all file hints from the given profiles.
    ///
    /// Returns a deduplicated list of file hints (by hint ID).
    pub fn collect_file_hints(&self, profiles: &[Arc<Profile>]) -> Vec<FileQueryHint> {
        let mut hints: Vec<FileQueryHint> = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        for profile in profiles {
            for hint in &profile.file_hints {
                if seen_ids.insert(hint.id.clone()) {
                    hints.push(hint.clone());
                }
            }
        }

        hints
    }
}

/// Result of resolving profiles for a session.
#[derive(Debug, Clone)]
pub struct ResolvedProfiles {
    /// The resolved profile IDs.
    pub profile_ids: Vec<String>,

    /// All rule IDs that should be active.
    pub rule_ids: Vec<String>,

    /// All file hints for the client.
    pub file_hints: Vec<FileQueryHint>,
}

impl ResolvedProfiles {
    /// Create from a list of resolved profiles.
    pub fn from_profiles(registry: &ProfileRegistry, profiles: &[Arc<Profile>]) -> Self {
        Self {
            profile_ids: profiles.iter().map(|p| p.id.clone()).collect(),
            rule_ids: registry.collect_rule_ids(profiles),
            file_hints: registry.collect_file_hints(profiles),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::context::Language;
    use crate::types::profile::FilePredicate;

    fn create_test_profile(id: &str) -> Profile {
        Profile::new(id, format!("Test {}", id))
            .with_language(Language::Python)
            .with_rule(format!("{}.rule1", id))
            .with_rule(format!("{}.rule2", id))
            .with_file_hint(
                FileQueryHint::new(format!("{}_hint", id))
                    .with_label(format!("{} files", id))
                    .include(FilePredicate::language("python")),
            )
    }

    // ==================== ProfileRegistry::new Tests ====================

    #[test]
    fn registry_new_is_empty() {
        let registry = ProfileRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    // ==================== ProfileRegistry::register Tests ====================

    #[test]
    fn registry_register_adds_profile() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("test"));

        assert_eq!(registry.len(), 1);
        assert!(registry.contains("test"));
    }

    #[test]
    fn registry_register_multiple_profiles() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("profile1"));
        registry.register(create_test_profile("profile2"));
        registry.register(create_test_profile("profile3"));

        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn registry_register_overwrites_existing() {
        let mut registry = ProfileRegistry::new();

        let profile1 = Profile::new("test", "Test 1").with_rule("rule1");
        let profile2 = Profile::new("test", "Test 2").with_rule("rule2");

        registry.register(profile1);
        registry.register(profile2);

        assert_eq!(registry.len(), 1);
        let profile = registry.get("test").unwrap();
        assert_eq!(profile.label, "Test 2");
        assert_eq!(profile.rule_ids, vec!["rule2"]);
    }

    // ==================== ProfileRegistry::get Tests ====================

    #[test]
    fn registry_get_existing_profile() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("test"));

        let profile = registry.get("test");
        assert!(profile.is_some());
        assert_eq!(profile.unwrap().id, "test");
    }

    #[test]
    fn registry_get_nonexistent_profile() {
        let registry = ProfileRegistry::new();
        assert!(registry.get("nonexistent").is_none());
    }

    // ==================== ProfileRegistry::all Tests ====================

    #[test]
    fn registry_all_returns_all_profiles() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("profile1"));
        registry.register(create_test_profile("profile2"));

        let all = registry.all();
        assert_eq!(all.len(), 2);
    }

    // ==================== ProfileRegistry::ids Tests ====================

    #[test]
    fn registry_ids_returns_all_ids() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("profile1"));
        registry.register(create_test_profile("profile2"));

        let ids = registry.ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"profile1"));
        assert!(ids.contains(&"profile2"));
    }

    // ==================== ProfileRegistry::resolve Tests ====================

    #[test]
    fn registry_resolve_empty_advertised() {
        let registry = ProfileRegistry::with_builtin_profiles();
        let resolved = registry.resolve(&[]);
        assert!(resolved.is_empty());
    }

    #[test]
    fn registry_resolve_existing_profiles() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("profile1"));
        registry.register(create_test_profile("profile2"));

        let advertised = vec![
            AdvertisedProfile::new("profile1", 0.9),
            AdvertisedProfile::new("profile2", 0.8),
        ];

        let resolved = registry.resolve(&advertised);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].id, "profile1"); // Higher confidence first
        assert_eq!(resolved[1].id, "profile2");
    }

    #[test]
    fn registry_resolve_skips_unknown_profiles() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("known"));

        let advertised = vec![
            AdvertisedProfile::new("known", 0.9),
            AdvertisedProfile::new("unknown", 0.8),
        ];

        let resolved = registry.resolve(&advertised);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, "known");
    }

    #[test]
    fn registry_resolve_orders_by_confidence() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("low"));
        registry.register(create_test_profile("high"));
        registry.register(create_test_profile("medium"));

        let advertised = vec![
            AdvertisedProfile::new("low", 0.3),
            AdvertisedProfile::new("high", 0.9),
            AdvertisedProfile::new("medium", 0.6),
        ];

        let resolved = registry.resolve(&advertised);
        assert_eq!(resolved[0].id, "high");
        assert_eq!(resolved[1].id, "medium");
        assert_eq!(resolved[2].id, "low");
    }

    // ==================== ProfileRegistry::collect_rule_ids Tests ====================

    #[test]
    fn registry_collect_rule_ids_empty() {
        let registry = ProfileRegistry::new();
        let rule_ids = registry.collect_rule_ids(&[]);
        assert!(rule_ids.is_empty());
    }

    #[test]
    fn registry_collect_rule_ids_from_profiles() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("profile1"));
        registry.register(create_test_profile("profile2"));

        let profiles = registry.all();
        let rule_ids = registry.collect_rule_ids(&profiles);

        assert!(rule_ids.contains(&"profile1.rule1".to_string()));
        assert!(rule_ids.contains(&"profile1.rule2".to_string()));
        assert!(rule_ids.contains(&"profile2.rule1".to_string()));
        assert!(rule_ids.contains(&"profile2.rule2".to_string()));
    }

    #[test]
    fn registry_collect_rule_ids_deduplicates() {
        let mut registry = ProfileRegistry::new();

        let profile1 = Profile::new("p1", "P1")
            .with_rule("shared_rule")
            .with_rule("unique1");
        let profile2 = Profile::new("p2", "P2")
            .with_rule("shared_rule")
            .with_rule("unique2");

        registry.register(profile1);
        registry.register(profile2);

        let profiles = registry.all();
        let rule_ids = registry.collect_rule_ids(&profiles);

        // shared_rule should appear only once
        let shared_count = rule_ids.iter().filter(|&id| id == "shared_rule").count();
        assert_eq!(shared_count, 1);
    }

    // ==================== ProfileRegistry::collect_file_hints Tests ====================

    #[test]
    fn registry_collect_file_hints_empty() {
        let registry = ProfileRegistry::new();
        let hints = registry.collect_file_hints(&[]);
        assert!(hints.is_empty());
    }

    #[test]
    fn registry_collect_file_hints_from_profiles() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("profile1"));
        registry.register(create_test_profile("profile2"));

        let profiles = registry.all();
        let hints = registry.collect_file_hints(&profiles);

        assert_eq!(hints.len(), 2);
    }

    #[test]
    fn registry_collect_file_hints_deduplicates_by_id() {
        let mut registry = ProfileRegistry::new();

        let hint = FileQueryHint::new("shared_hint");
        let profile1 = Profile::new("p1", "P1").with_file_hint(hint.clone());
        let profile2 = Profile::new("p2", "P2").with_file_hint(hint);

        registry.register(profile1);
        registry.register(profile2);

        let profiles = registry.all();
        let hints = registry.collect_file_hints(&profiles);

        // shared_hint should appear only once
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].id, "shared_hint");
    }

    // ==================== ResolvedProfiles Tests ====================

    #[test]
    fn resolved_profiles_from_profiles() {
        let mut registry = ProfileRegistry::new();
        registry.register(create_test_profile("profile1"));
        registry.register(create_test_profile("profile2"));

        let profiles = registry.all();
        let resolved = ResolvedProfiles::from_profiles(&registry, &profiles);

        assert_eq!(resolved.profile_ids.len(), 2);
        assert!(!resolved.rule_ids.is_empty());
        assert!(!resolved.file_hints.is_empty());
    }

    // ==================== ProfileRegistry::with_builtin_profiles Tests ====================

    #[test]
    fn registry_with_builtin_profiles_not_empty() {
        let registry = ProfileRegistry::with_builtin_profiles();
        assert!(!registry.is_empty());
    }

    #[test]
    fn registry_with_builtin_profiles_has_python_fastapi() {
        let registry = ProfileRegistry::with_builtin_profiles();
        assert!(registry.contains("python_fastapi_backend"));
    }
}
