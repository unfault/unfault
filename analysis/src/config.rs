use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Reserved for future tuning knobs (parallelism, timeouts, etc.).
    pub max_parallel_files: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_parallel_files: 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();
        assert_eq!(config.max_parallel_files, 16);
    }

    #[test]
    fn test_config_clone() {
        let config = EngineConfig {
            max_parallel_files: 32,
        };
        let cloned = config.clone();
        assert_eq!(cloned.max_parallel_files, 32);
    }

    #[test]
    fn test_config_debug() {
        let config = EngineConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("EngineConfig"));
        assert!(debug_str.contains("max_parallel_files"));
    }

    #[test]
    fn test_config_serialize_deserialize() {
        let config = EngineConfig {
            max_parallel_files: 64,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&config).expect("serialization should succeed");
        assert!(json.contains("64"));

        // Deserialize back
        let deserialized: EngineConfig =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(deserialized.max_parallel_files, 64);
    }

    #[test]
    fn test_config_deserialize_from_json() {
        let json = r#"{"max_parallel_files": 128}"#;
        let config: EngineConfig =
            serde_json::from_str(json).expect("deserialization should succeed");
        assert_eq!(config.max_parallel_files, 128);
    }

    #[test]
    fn test_config_custom_value() {
        let config = EngineConfig {
            max_parallel_files: 1,
        };
        assert_eq!(config.max_parallel_files, 1);
    }
}
