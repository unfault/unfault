//! Types module — re-exported from unfault-core.
//!
//! All shared type definitions live in `unfault-core`. This module re-exports
//! them so that existing `crate::types::*` import paths throughout the analysis
//! crate continue to work unchanged.

pub use unfault_core::types::context;
pub use unfault_core::types::dependency;
pub use unfault_core::types::finding;
pub use unfault_core::types::meta;
pub use unfault_core::types::patch;
pub use unfault_core::types::profile;
pub use unfault_core::types::session_result;
pub use unfault_core::types::workspace;

// Re-export the flat items that types/mod.rs used to provide
pub use dependency::{
    is_dynamic_uri, BlockType, DependencyProtocol, DependencySource, RuntimeDependency,
};
pub use patch::{apply_file_patch, make_unified_diff, FilePatch, PatchHunk, PatchRange};
pub use profile::{FilePredicate, FileQueryHint, Profile};
pub use workspace::{AdvertisedProfile, MetaFile, MetaFileKind, WorkspaceDescriptor};
