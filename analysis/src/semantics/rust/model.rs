//! Rust semantic model structures.
//!
//! This module defines the data structures that represent the semantic
//! understanding of Rust source files, including functions, types,
//! async operations, error handling patterns, and more.

use serde::{Deserialize, Serialize};

use crate::parse::ast::{AstLocation, FileId, ParsedFile};
use crate::semantics::common::{CommonLocation, calls::FunctionCall};
use crate::semantics::rust::frameworks::RustFrameworkSummary;
use crate::types::context::Language;

/// Semantic model for a single Rust file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustFileSemantics {
    pub file_id: FileId,
    pub path: String,
    pub language: Language,

    /// Module path (from mod statements or file path)
    pub mod_path: Vec<String>,

    /// Use statements (imports)
    pub uses: Vec<RustUse>,

    /// Function definitions
    pub functions: Vec<RustFunction>,

    /// Struct definitions
    pub structs: Vec<RustStruct>,

    /// Enum definitions
    pub enums: Vec<RustEnum>,

    /// Trait definitions
    pub traits: Vec<RustTrait>,

    /// Impl blocks
    pub impls: Vec<RustImpl>,

    /// Async-specific information
    pub async_info: AsyncInfo,

    /// Error handling patterns
    pub unwrap_calls: Vec<UnwrapCall>,
    pub expect_calls: Vec<ExpectCall>,
    pub result_ignores: Vec<ResultIgnore>,

    /// Unsafe blocks and functions
    pub unsafe_blocks: Vec<UnsafeBlock>,

    /// Macro invocations (println!, panic!, etc.)
    pub macro_invocations: Vec<MacroInvocation>,

    /// Channel operations
    pub channel_ops: Vec<ChannelOp>,

    /// Arc<Mutex<T>> and similar synchronization patterns
    pub sync_patterns: Vec<SyncPattern>,

    /// Static/const declarations
    pub statics: Vec<StaticDecl>,

    /// All call sites for analysis
    pub calls: Vec<RustCallSite>,

    /// Field accesses (e.g., `obj.field`)
    pub field_accesses: Vec<FieldAccess>,

    /// Variable bindings (let declarations and loop variables)
    pub variable_bindings: Vec<VariableBinding>,

    /// HTTP framework summary (Axum, Actix-web, Rocket, etc.)
    #[serde(default)]
    pub rust_framework: Option<RustFrameworkSummary>,
}

/// Use statement (import).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustUse {
    /// Full path, e.g., "std::collections::HashMap"
    pub path: String,
    /// Alias if renamed, e.g., "use std::io::Result as IoResult"
    pub alias: Option<String>,
    /// Whether this is a glob import (use foo::*)
    pub is_glob: bool,
    /// Whether this is pub use
    pub is_pub: bool,
    /// Items if grouped: use std::{io, fs}
    pub items: Vec<String>,
    /// Location in source
    pub location: AstLocation,
}

/// Function definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustFunction {
    pub name: String,
    /// Visibility: pub, pub(crate), pub(super), private
    pub visibility: Visibility,
    /// Whether this is an async function
    pub is_async: bool,
    /// Whether this is unsafe
    pub is_unsafe: bool,
    /// Whether this is const
    pub is_const: bool,
    /// Whether this is extern
    pub is_extern: bool,
    /// Generic parameters
    pub generics: Vec<String>,
    /// Parameters
    pub params: Vec<RustParam>,
    /// Return type as string
    pub return_type: Option<String>,
    /// Whether the return type is Result<_, _>
    pub returns_result: bool,
    /// Whether the return type is Option<_>
    pub returns_option: bool,
    /// Whether this function is in a #[cfg(test)] block
    pub is_test: bool,
    /// Whether this is the main function
    pub is_main: bool,
    /// Whether this has #[test] attribute
    pub has_test_attribute: bool,
    /// Attributes on the function
    pub attributes: Vec<String>,
    /// Location in source
    pub location: AstLocation,
    /// Start byte for patching
    pub start_byte: usize,
    /// End byte for patching
    pub end_byte: usize,
}

/// Function parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustParam {
    pub name: String,
    pub param_type: String,
    /// Whether this is &self, &mut self, or self
    pub is_self: bool,
    pub is_mut: bool,
    pub is_ref: bool,
}

/// Visibility modifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Visibility {
    Private,
    Pub,
    PubCrate,
    PubSuper,
    PubIn(String),
}

/// Struct definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustStruct {
    pub name: String,
    pub visibility: Visibility,
    pub generics: Vec<String>,
    pub fields: Vec<RustField>,
    /// Whether this is a tuple struct
    pub is_tuple: bool,
    /// Whether this is a unit struct
    pub is_unit: bool,
    /// Derive macros
    pub derives: Vec<String>,
    /// All attributes
    pub attributes: Vec<String>,
    pub location: AstLocation,
}

/// Struct field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustField {
    pub name: String,
    pub field_type: String,
    pub visibility: Visibility,
    pub attributes: Vec<String>,
}

/// Enum definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustEnum {
    pub name: String,
    pub visibility: Visibility,
    pub generics: Vec<String>,
    pub variants: Vec<EnumVariant>,
    pub derives: Vec<String>,
    pub attributes: Vec<String>,
    pub location: AstLocation,
}

/// Enum variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    /// Fields for tuple variants
    pub tuple_fields: Vec<String>,
    /// Fields for struct variants
    pub struct_fields: Vec<RustField>,
    /// Discriminant if specified
    pub discriminant: Option<String>,
}

/// Trait definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustTrait {
    pub name: String,
    pub visibility: Visibility,
    pub generics: Vec<String>,
    /// Super traits
    pub bounds: Vec<String>,
    /// Associated types
    pub associated_types: Vec<String>,
    /// Method signatures
    pub methods: Vec<String>,
    pub attributes: Vec<String>,
    pub location: AstLocation,
}

/// Impl block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustImpl {
    /// Type being implemented for
    pub self_type: String,
    /// Trait being implemented (if trait impl)
    pub trait_name: Option<String>,
    /// Generic parameters
    pub generics: Vec<String>,
    /// Methods in this impl
    pub methods: Vec<RustFunction>,
    /// Whether this is unsafe impl
    pub is_unsafe: bool,
    pub location: AstLocation,
}

/// Async-related information aggregated from the file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AsyncInfo {
    /// Number of async functions
    pub async_fn_count: usize,
    /// Spawn calls (tokio::spawn, async_std::spawn, etc.)
    pub spawn_calls: Vec<SpawnCall>,
    /// Await expressions
    pub await_points: Vec<AwaitPoint>,
    /// Select! macro usages
    pub select_usages: Vec<SelectUsage>,
    /// Whether file uses tokio
    pub uses_tokio: bool,
    /// Whether file uses async-std
    pub uses_async_std: bool,
}

/// Information about a spawn call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnCall {
    pub spawn_type: SpawnType,
    /// Whether the JoinHandle is captured
    pub handle_captured: bool,
    /// Whether there's error handling on the handle
    pub has_error_handling: bool,
    /// The spawned expression text
    pub spawned_expr: String,
    /// Enclosing function name
    pub function_name: Option<String>,
    pub location: AstLocation,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Type of spawn operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SpawnType {
    TokioSpawn,
    TokioSpawnBlocking,
    TokioSpawnLocal,
    AsyncStdSpawn,
    AsyncStdSpawnBlocking,
    AsyncStdSpawnLocal,
    Other(String),
}

/// Information about an await point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitPoint {
    /// Expression being awaited
    pub expr: String,
    /// Whether this is inside a loop
    pub in_loop: bool,
    /// Enclosing function name
    pub function_name: Option<String>,
    pub location: AstLocation,
}

/// Information about select! macro usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectUsage {
    /// Number of branches
    pub branch_count: usize,
    /// Whether there's a default/else branch
    pub has_default: bool,
    /// Whether there's a timeout branch
    pub has_timeout: bool,
    /// Enclosing function name
    pub function_name: Option<String>,
    pub location: AstLocation,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Information about an unwrap() call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwrapCall {
    /// Type being unwrapped: Result, Option, or Unknown
    pub on_type: UnwrapType,
    /// The method: unwrap, unwrap_or, unwrap_or_default, unwrap_or_else
    pub method: String,
    /// Whether this is in test code
    pub in_test: bool,
    /// Whether this is in main()
    pub in_main: bool,
    /// Whether this is in a closure
    pub in_closure: bool,
    /// Whether this is in a static initializer (LazyLock::new, OnceLock, etc.)
    /// Such patterns are the correct way to initialize compile-time constants.
    pub in_static_init: bool,
    /// Enclosing function name
    pub function_name: Option<String>,
    /// The full expression text
    pub expr_text: String,
    /// The receiver expression (what .unwrap() is called on)
    pub receiver_expr: String,
    /// Detected pattern for smart fixes
    pub pattern: UnwrapPattern,
    pub location: AstLocation,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Detected pattern for smart unwrap fix suggestions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum UnwrapPattern {
    /// `.starts_with(x)` guard followed by `.find(x).unwrap()` → use `strip_prefix`
    StartsWithFind {
        /// The pattern/needle being searched for
        needle: String,
        /// Start byte of the if-expression containing starts_with
        guard_start_byte: Option<usize>,
    },
    /// `.contains(x)` guard followed by `.find(x).unwrap()` → use `if let Some(pos) = find()`
    ContainsFind { needle: String },
    /// `is_some()` check followed by `.unwrap()` → use `if let Some(x)`
    IsSomeUnwrap,
    /// `is_ok()` check followed by `.unwrap()` → use `if let Ok(x)`
    IsOkUnwrap,
    /// `env::var().unwrap()` → suggest `.expect("VAR must be set")` with var name
    EnvVar { var_name: String },
    /// `.parse().unwrap()` → suggest `?` operator or `.parse().expect("...")`
    Parse {
        /// Type being parsed to, if detectable
        target_type: Option<String>,
    },
    /// `.get(idx).unwrap()` on collections → suggest indexing or `.get_or()`
    CollectionGet { index_expr: String },
    /// `Regex::new().unwrap()` → suggest `lazy_static!` or `OnceLock`
    RegexNew,
    /// `.first().unwrap()` / `.last().unwrap()` → suggest iterator patterns
    FirstOrLast { is_first: bool },
    /// `.lock().unwrap()` / `.read().unwrap()` / `.write().unwrap()` → handle poisoned lock
    LockUnwrap { lock_method: String },
    /// `.next().unwrap()` on iterator → suggest `if let Some` or `.next().expect()`
    IteratorNext,
    /// Generic pattern - no specific optimization available
    #[default]
    Generic,
}

/// Type of value being unwrapped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UnwrapType {
    Result,
    Option,
    Unknown,
}

/// Information about an expect() call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectCall {
    pub on_type: UnwrapType,
    /// The message passed to expect()
    pub message: String,
    /// Whether the message is meaningful (not just "should work")
    pub has_meaningful_message: bool,
    pub in_test: bool,
    pub in_main: bool,
    pub function_name: Option<String>,
    pub expr_text: String,
    pub location: AstLocation,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Information about ignored Result values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultIgnore {
    /// How the result is ignored: let _ = ..., or just expr;
    pub ignore_style: ResultIgnoreStyle,
    /// The expression returning Result
    pub expr_text: String,
    /// Whether this is in test code
    pub in_test: bool,
    pub function_name: Option<String>,
    pub location: AstLocation,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// How a Result is being ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResultIgnoreStyle {
    /// let _ = fallible();
    LetUnderscore,
    /// fallible(); (statement with no capture)
    Statement,
    /// _ = fallible(); (assignment to underscore)
    AssignUnderscore,
}

/// Information about an unsafe block or function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeBlock {
    pub kind: UnsafeKind,
    /// Whether there's a SAFETY comment
    pub has_safety_comment: bool,
    /// The safety comment text if present
    pub safety_comment: Option<String>,
    /// Enclosing function name
    pub function_name: Option<String>,
    /// Operations inside the unsafe block
    pub operations: Vec<UnsafeOp>,
    pub location: AstLocation,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Kind of unsafe construct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UnsafeKind {
    Block,
    Function,
    Trait,
    Impl,
}

/// Type of unsafe operation detected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UnsafeOp {
    RawPointerDeref,
    UnsafeFnCall,
    MutableStaticAccess,
    UnionFieldAccess,
    ExternCall,
    Transmute,
}

/// Macro invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroInvocation {
    pub name: String,
    /// Whether this is a potentially problematic macro in production
    pub is_debug_macro: bool,
    /// Whether this should be tracing instead
    pub should_be_tracing: bool,
    /// The arguments/content
    pub args: String,
    pub in_test: bool,
    pub function_name: Option<String>,
    pub location: AstLocation,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Channel operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelOp {
    pub channel_type: ChannelType,
    pub op_kind: ChannelOpKind,
    /// Whether the channel is bounded
    pub is_bounded: bool,
    /// Capacity if bounded
    pub capacity: Option<usize>,
    pub function_name: Option<String>,
    pub location: AstLocation,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Type of channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelType {
    StdMpsc,
    StdSyncMpsc,
    TokioMpsc,
    TokioBroadcast,
    TokioWatch,
    TokioOneshot,
    Crossbeam,
    Flume,
    Kanal,
    Other(String),
}

/// Kind of channel operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelOpKind {
    Create,
    Send,
    TrySend,
    Recv,
    TryRecv,
    Close,
}

/// Synchronization pattern usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPattern {
    pub pattern_type: SyncPatternType,
    /// Inner type if applicable
    pub inner_type: Option<String>,
    /// Whether this is used in a hot path (loop, handler, etc.)
    pub in_hot_path: bool,
    pub function_name: Option<String>,
    pub location: AstLocation,
}

/// Type of synchronization pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncPatternType {
    ArcMutex,
    ArcRwLock,
    Mutex,
    RwLock,
    Atomic,
    OnceCell,
    LazyStatic,
    OnceLock,
}

/// Static or const declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticDecl {
    pub name: String,
    pub decl_type: String,
    pub is_const: bool,
    pub is_mut: bool,
    pub visibility: Visibility,
    /// Whether this is thread-safe (using sync types)
    pub is_thread_safe: bool,
    pub location: AstLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustCallSite {
    /// Resolution information for this call site.
    pub function_call: FunctionCall,

    /// Arguments for the call as a best-effort string.
    ///
    /// Compatibility note: the client-side `core` crate includes this field.
    #[serde(default)]
    pub args_repr: String,

    /// Method name if method call
    #[serde(default)]
    pub method_name: Option<String>,
    /// Whether this is a method call (obj.method())
    ///
    /// Compatibility note: older/newer clients may omit this; default is `false`.
    #[serde(default)]
    pub is_method_call: bool,
    /// Whether this call is inside a loop
    #[serde(default)]
    pub in_loop: bool,
    /// Whether this is in an async context
    #[serde(default)]
    pub in_async: bool,
    /// Whether this is in a static initializer (LazyLock::new, OnceLock, etc.)
    /// Such patterns are the correct way to initialize compile-time constants.
    #[serde(default)]
    pub in_static_init: bool,
    /// Enclosing function name
    #[serde(default)]
    pub function_name: Option<String>,

    #[serde(default)]
    pub start_byte: usize,
    #[serde(default)]
    pub end_byte: usize,
}

/// Field access expression (e.g., `obj.field`).
///
/// This tracks when fields are accessed on variables, which is essential
/// for detecting patterns like clone-to-consume where we need to know
/// which fields are used after a consuming call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAccess {
    /// The receiver expression (e.g., "rf" in "rf.patch")
    pub receiver: String,
    /// The field being accessed (e.g., "patch" in "rf.patch")
    pub field: String,
    /// Full expression text (e.g., "rf.patch")
    pub full_expr: String,
    /// Whether this access is inside a loop
    pub in_loop: bool,
    /// Enclosing function name
    pub function_name: Option<String>,
    /// Location in source
    pub location: AstLocation,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Variable binding (let declaration or loop variable).
///
/// This tracks variable declarations and their scope, which is essential
/// for understanding variable lifetimes and clone patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableBinding {
    /// Variable name
    pub name: String,
    /// The initialization expression (RHS of `let x = expr`)
    pub init_expr: Option<String>,
    /// Whether this is a loop variable (e.g., `for x in items`)
    pub is_loop_variable: bool,
    /// Whether the variable is mutable
    pub is_mut: bool,
    /// Whether the initialization involves a clone call
    pub init_has_clone: bool,
    /// Whether the initialization is a consuming function call (From::from, Into::into, etc.)
    pub init_is_consuming_call: bool,
    /// The consumed variable if init_is_consuming_call is true (e.g., "rf" from "Finding::from(rf.clone())")
    pub consumed_variable: Option<String>,
    /// Enclosing function name
    pub function_name: Option<String>,
    /// Whether this binding is inside a loop
    pub in_loop: bool,
    /// Location in source
    pub location: AstLocation,
    /// Start byte of the binding scope (usually the let statement)
    pub scope_start_byte: usize,
    /// End byte of the binding scope (end of the enclosing block)
    pub scope_end_byte: usize,
}

impl RustFileSemantics {
    /// Create semantics from a parsed file.
    pub fn from_parsed(parsed: &ParsedFile) -> Self {
        let mut sem = RustFileSemantics {
            file_id: parsed.file_id,
            path: parsed.path.clone(),
            language: Language::Rust,
            mod_path: Vec::new(),
            uses: Vec::new(),
            functions: Vec::new(),
            structs: Vec::new(),
            enums: Vec::new(),
            traits: Vec::new(),
            impls: Vec::new(),
            async_info: AsyncInfo::default(),
            unwrap_calls: Vec::new(),
            expect_calls: Vec::new(),
            result_ignores: Vec::new(),
            unsafe_blocks: Vec::new(),
            macro_invocations: Vec::new(),
            channel_ops: Vec::new(),
            sync_patterns: Vec::new(),
            statics: Vec::new(),
            calls: Vec::new(),
            field_accesses: Vec::new(),
            variable_bindings: Vec::new(),
            rust_framework: None,
        };

        collect_semantics(parsed, &mut sem);

        sem
    }
}

/// Context for tracking state during AST traversal.
#[derive(Default, Clone)]
struct TraversalContext {
    in_loop: bool,
    current_function: Option<String>,
    current_qualified_name: Option<String>,
    current_impl_type: Option<String>,
}

/// Collect semantics by walking the tree-sitter AST.
fn collect_semantics(parsed: &ParsedFile, sem: &mut RustFileSemantics) {
    // Allow tests to re-run collection without duplicating entries.
    sem.calls.clear();

    let root = parsed.tree.root_node();
    let ctx = TraversalContext::default();
    walk_nodes_with_context(root, parsed, sem, ctx);
}

/// Walk nodes while tracking context.
fn walk_nodes_with_context(
    node: tree_sitter::Node,
    parsed: &ParsedFile,
    sem: &mut RustFileSemantics,
    ctx: TraversalContext,
) {
    let new_ctx = match node.kind() {
        "impl_item" => {
            let type_name = node
                .child_by_field_name("type")
                .map(|n| parsed.text_for_node(&n))
                .unwrap_or_default();
            TraversalContext {
                current_impl_type: Some(type_name),
                ..ctx.clone()
            }
        }
        "function_item" => {
            let func_name = node
                .child_by_field_name("name")
                .map(|n| parsed.text_for_node(&n))
                .unwrap_or_default();
            let qualified = if let Some(impl_type) = &ctx.current_impl_type {
                format!("{}.{}", impl_type, func_name)
            } else {
                func_name.clone()
            };
            TraversalContext {
                current_function: Some(func_name),
                current_qualified_name: Some(qualified),
                ..ctx.clone()
            }
        }
        "loop_expression" | "for_expression" | "while_expression" => TraversalContext {
            in_loop: true,
            ..ctx.clone()
        },
        _ => ctx.clone(),
    };

    match node.kind() {
        "call_expression" => {
            if let Some(call) = build_callsite(parsed, &node, &new_ctx, sem) {
                sem.calls.push(call);
            }
        }
        _ => {}
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            walk_nodes_with_context(child, parsed, sem, new_ctx.clone());
        }
    }
}

/// Build a RustCallSite from a call_expression node.
fn build_callsite(
    parsed: &ParsedFile,
    node: &tree_sitter::Node,
    ctx: &TraversalContext,
    sem: &RustFileSemantics,
) -> Option<RustCallSite> {
    let callee_node = node.child_by_field_name("function")?;
    let callee = parsed.text_for_node(&callee_node);

    // Parse callee into parts
    let callee_parts: Vec<String> = if callee.contains("::") {
        callee.split("::").map(|s| s.to_string()).collect()
    } else {
        callee.split('.').map(|s| s.to_string()).collect()
    };
    let first_part = callee_parts.first().cloned().unwrap_or_default();

    // In Rust, no 'self' like Python, but can check for &self patterns if needed
    let is_self_call = false;

    // Detect import call and alias
    let (is_import_call, import_alias) = sem
        .uses
        .iter()
        .find_map(|use_stmt| {
            if use_stmt.alias.as_ref() == Some(&first_part) {
                Some((true, use_stmt.alias.clone()))
            } else {
                // For non-aliased, check if first_part matches last segment of path
                let path_parts: Vec<&str> = use_stmt.path.split("::").collect();
                if path_parts.last() == Some(&first_part.as_str()) {
                    Some((true, None))
                } else {
                    None
                }
            }
        })
        .unwrap_or((false, None));

    let function_call = FunctionCall {
        callee_expr: callee.clone(),
        callee_parts,
        caller_function: ctx.current_function.clone().unwrap_or_default(),
        caller_qualified_name: ctx.current_qualified_name.clone().unwrap_or_default(),
        location: CommonLocation::from(&parsed.location_for_node(node)),
        is_self_call,
        is_import_call,
        import_alias,
    };

    // Placeholder for other fields
    Some(RustCallSite {
        function_call,
        args_repr: String::new(),
        method_name: None,
        is_method_call: false,
        in_loop: ctx.in_loop,
        in_async: false,
        in_static_init: false,
        function_name: ctx.current_function.clone(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::types::context::SourceFile;

    fn make_rust_source_file(content: &str) -> SourceFile {
        SourceFile {
            path: "test.rs".to_string(),
            language: Language::Rust,
            content: content.to_string(),
        }
    }

    #[test]
    fn from_parsed_creates_empty_semantics() {
        let sf = make_rust_source_file("fn main() {}");
        let parsed = parse_rust_file(FileId(1), &sf).unwrap();
        let sem = RustFileSemantics::from_parsed(&parsed);

        assert_eq!(sem.file_id, FileId(1));
        assert_eq!(sem.path, "test.rs");
        assert_eq!(sem.language, Language::Rust);
        assert!(sem.functions.is_empty());
        assert!(sem.unwrap_calls.is_empty());
    }

    #[test]
    fn visibility_equality() {
        assert_eq!(Visibility::Pub, Visibility::Pub);
        assert_ne!(Visibility::Pub, Visibility::Private);
        assert_eq!(Visibility::PubCrate, Visibility::PubCrate);
    }

    #[test]
    fn spawn_type_equality() {
        assert_eq!(SpawnType::TokioSpawn, SpawnType::TokioSpawn);
        assert_ne!(SpawnType::TokioSpawn, SpawnType::TokioSpawnBlocking);
    }

    #[test]
    fn unwrap_type_equality() {
        assert_eq!(UnwrapType::Result, UnwrapType::Result);
        assert_ne!(UnwrapType::Result, UnwrapType::Option);
    }

    #[test]
    fn channel_type_equality() {
        assert_eq!(ChannelType::TokioMpsc, ChannelType::TokioMpsc);
        assert_ne!(ChannelType::TokioMpsc, ChannelType::StdMpsc);
    }

    #[test]
    fn sync_pattern_type_equality() {
        assert_eq!(SyncPatternType::ArcMutex, SyncPatternType::ArcMutex);
        assert_ne!(SyncPatternType::ArcMutex, SyncPatternType::ArcRwLock);
    }

    #[test]
    fn call_site_tracks_enclosing_function() {
        let src = r#"
fn outer() {
    inner_call();
}
"#;
        let sf = SourceFile {
            path: "test.rs".to_string(),
            language: Language::Rust,
            content: src.to_string(),
        };
        let parsed = parse_rust_file(FileId(1), &sf).unwrap();
        let sem = RustFileSemantics::from_parsed(&parsed);
        assert_eq!(sem.calls.len(), 1);
        let call = &sem.calls[0];
        assert_eq!(call.function_call.caller_function, "outer");
        assert_eq!(call.function_call.caller_qualified_name, "outer");
    }

    #[test]
    fn call_site_tracks_qualified_name_in_impl() {
        let src = r#"
impl MyStruct {
    fn method(&self) {
        self.helper();
    }
}
"#;
        let sf = SourceFile {
            path: "test.rs".to_string(),
            language: Language::Rust,
            content: src.to_string(),
        };
        let parsed = parse_rust_file(FileId(1), &sf).unwrap();
        let sem = RustFileSemantics::from_parsed(&parsed);
        assert_eq!(sem.calls.len(), 1);
        let call = &sem.calls[0];
        assert_eq!(call.function_call.caller_function, "method");
        assert_eq!(call.function_call.caller_qualified_name, "MyStruct.method");
    }

    #[test]
    fn call_site_detects_use_call() {
        let src = r#"
use std::net::TcpStream;

fn connect() {
    TcpStream::connect("addr");
}
"#;
        let sf = SourceFile {
            path: "test.rs".to_string(),
            language: Language::Rust,
            content: src.to_string(),
        };
        let parsed = parse_rust_file(FileId(1), &sf).unwrap();
        let mut sem = RustFileSemantics::from_parsed(&parsed);
        // Manually add a use since collection not implemented
        sem.uses.push(RustUse {
            path: "std::net::TcpStream".to_string(),
            alias: None,
            is_glob: false,
            is_pub: false,
            items: vec![],
            location: AstLocation::default(),
        });
        // Re-run collection to include the use
        collect_semantics(&parsed, &mut sem);
        assert_eq!(sem.calls.len(), 1);
        let call = &sem.calls[0];
        assert!(call.function_call.is_import_call);
        assert_eq!(call.function_call.import_alias, None);
        assert_eq!(
            call.function_call.callee_parts,
            vec!["TcpStream".to_string(), "connect".to_string()]
        );
    }

    #[test]
    fn async_info_default() {
        let info = AsyncInfo::default();
        assert_eq!(info.async_fn_count, 0);
        assert!(info.spawn_calls.is_empty());
        assert!(!info.uses_tokio);
    }
}
