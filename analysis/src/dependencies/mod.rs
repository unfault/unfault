//! Runtime dependency extraction from semantics.
//!
//! This module provides functions to extract runtime dependencies from
//! source code semantics, such as HTTP calls, database connections, etc.

use std::sync::Arc;

use crate::parse::ast::FileId;
use crate::semantics::SourceSemantics;
use crate::types::dependency::{BlockType, RuntimeDependency};

mod extractor;
mod url_parser;

pub use extractor::extract_dependencies;
pub use url_parser::extract_url_from_call;

/// Extract all runtime dependencies from a collection of semantics.
///
/// This is the main entry point for dependency extraction.
pub fn extract_all_dependencies(
    semantics: &[(FileId, Arc<SourceSemantics>)],
) -> Vec<RuntimeDependency> {
    let mut all_deps = Vec::new();

    for (file_id, sem) in semantics {
        let deps = extract_dependencies(*file_id, sem.as_ref());
        all_deps.extend(deps);
    }

    all_deps
}

/// Convert an enclosing function name and context to BlockType.
pub fn determine_block_type(function_name: &Option<String>, is_method: bool) -> BlockType {
    match function_name {
        Some(name) if name.starts_with("lambda") => BlockType::Lambda,
        Some(_) if is_method => BlockType::Method,
        Some(_) => BlockType::Function,
        None => BlockType::Module,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_block_type_function() {
        assert_eq!(
            determine_block_type(&Some("my_function".to_string()), false),
            BlockType::Function
        );
    }

    #[test]
    fn test_determine_block_type_method() {
        assert_eq!(
            determine_block_type(&Some("my_method".to_string()), true),
            BlockType::Method
        );
    }

    #[test]
    fn test_determine_block_type_lambda() {
        assert_eq!(
            determine_block_type(&Some("lambda".to_string()), false),
            BlockType::Lambda
        );
    }

    #[test]
    fn test_determine_block_type_module() {
        assert_eq!(determine_block_type(&None, false), BlockType::Module);
    }
}