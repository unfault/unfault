// unfault-ignore: rust.println_in_lib
//! # Review Command
//!
//! Implements the code review/analysis command for the Unfault CLI.
//!
//! ## Architecture
//!
//! By default, the review command uses **client-side parsing**:
//! 1. Parse source files locally using tree-sitter (via unfault-core)
//! 2. Build an Intermediate Representation (IR) containing semantics and code graph
//! 3. Send serialized IR to the API (no source code over the wire)
//! 4. Receive findings and optionally apply patches locally
//!
//! Use `--server-parse` flag to fall back to legacy server-side parsing.
//!
//! ## Usage
//!
//! ```bash
//! unfault review               # Client-side parsing (default)
//! unfault review --fix         # Auto-apply all fixes
//! unfault review --dry-run     # Show what fixes would be applied
//! unfault review --server-parse # Legacy: send source to server
//! unfault review --output full
//! unfault review --output json
//! unfault review --output sarif
//! ```

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::exit_codes::*;
use crate::fmt::{COL_WIDTH, truncate, word_wrap};
use crate::output::{IrFinding, IrSystemHazard};
use crate::session::{
    PatchApplier, ScanProgress, WorkspaceScanner, build_ir_cached, compute_workspace_id,
    get_git_changed_files, get_git_commit_files, get_git_remote,
};

/// Arguments for the review command
pub struct ReviewArgs {
    /// Output format (text, json, or sarif)
    pub output_format: String,
    /// Output mode (concise or full)
    pub output_mode: String,
    /// Verbose mode (dump raw responses)
    pub verbose: bool,
    /// Override the detected profile
    pub profile: Option<String>,
    /// Dimensions to analyze (None = all from profile)
    pub dimensions: Option<Vec<String>>,
    /// Auto-apply all suggested fixes
    pub fix: bool,
    /// Show what fixes would be applied without actually applying them
    pub dry_run: bool,
    /// Show all findings in full (delegates to lint-style output)
    pub all: bool,
    /// Discard the enrichment cache and re-fetch SLOs and traces from providers
    pub refresh_cache: bool,
    /// Skip SLO and trace fetching entirely (useful in CI or pre-commit hooks)
    pub offline: bool,
    /// Analyze only files changed in this git commit ref (SHA, branch, HEAD~N, …).
    /// When combined with `files`, both sets are unioned and deduplicated.
    pub commit: Option<String>,
    /// Analyze only these specific files.
    /// When combined with `commit`, both sets are unioned and deduplicated.
    pub files: Vec<std::path::PathBuf>,
}

/// Execute the review command
///
/// Analyzes the current directory and displays findings.
///
/// # Arguments
///
/// * `args` - Review command arguments
///
/// # Returns
///
/// * `Ok(EXIT_SUCCESS)` - Analysis completed with no findings
/// * `Ok(EXIT_FINDINGS_FOUND)` - Analysis completed with findings
/// * `Ok(EXIT_CONFIG_ERROR)` - Configuration error
/// * `Ok(EXIT_AUTH_ERROR)` - Authentication error
/// * `Ok(EXIT_NETWORK_ERROR)` - Network error
///
/// State for progressive display during scanning.
struct ScanDisplayState {
    workspace_label: String,
    languages: Vec<String>,
    frameworks: Vec<String>,
    file_count: usize,
    lines_printed: usize,
}

impl ScanDisplayState {
    fn new(workspace_label: String) -> Self {
        Self {
            workspace_label,
            languages: Vec::new(),
            frameworks: Vec::new(),
            file_count: 0,
            lines_printed: 0,
        }
    }

    /// Update the display with new progress.
    fn update(&mut self, progress: &ScanProgress) {
        self.file_count = progress.file_count;
        self.languages = progress.languages.clone();
        self.frameworks = progress.frameworks.clone();
    }

    /// Render the current state to the terminal, overwriting previous lines.
    fn render(&mut self, dimensions: &[String], profile_override: Option<&str>) {
        // Move cursor up to overwrite previous lines
        if self.lines_printed > 0 {
            // Move up and clear each line
            for _ in 0..self.lines_printed {
                eprint!("\x1b[1A\x1b[2K");
            }
        }

        let mut lines = 0;

        // Header line with workspace name
        eprintln!(
            "{} Analyzing {}...",
            "→".cyan().bold(),
            self.workspace_label.bright_blue()
        );
        lines += 1;

        // Languages line
        if !self.languages.is_empty() {
            eprintln!("  Languages: {}", self.languages.join(", ").cyan());
            lines += 1;
        }

        // Frameworks line
        if !self.frameworks.is_empty() {
            eprintln!("  Frameworks: {}", self.frameworks.join(", ").cyan());
            lines += 1;
        }

        // Profile override line
        if let Some(profile) = profile_override {
            eprintln!("  Profile: {} (override)", profile.cyan());
            lines += 1;
        }

        // Dimensions line
        eprintln!(
            "  Dimensions: {}",
            format_list_dimmed(dimensions, ", ").cyan()
        );
        lines += 1;

        // File count line (always show, even if 0)
        let file_word = if self.file_count == 1 {
            "file"
        } else {
            "files"
        };
        eprintln!(
            "  Found {} matching source {}",
            self.file_count.to_string().bright_green(),
            file_word
        );
        lines += 1;

        self.lines_printed = lines;
        let _ = io::stderr().flush();
    }

    fn clear(&mut self) {
        if self.lines_printed == 0 {
            return;
        }
        for _ in 0..self.lines_printed {
            eprint!("\x1b[1A\x1b[2K");
        }
        self.lines_printed = 0;
        let _ = io::stderr().flush();
    }
}

fn format_list_dimmed(values: &[String], separator: &str) -> String {
    if values.is_empty() {
        "—".into()
    } else {
        values.join(separator)
    }
}

pub async fn execute(args: ReviewArgs) -> Result<i32> {
    // Generate a trace ID for this session
    let trace_id = uuid::Uuid::new_v4().simple().to_string();

    // Get current directory
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;

    // Start timing the session
    let session_start = Instant::now();

    // Get workspace label first (just the directory name)
    let workspace_label = current_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace")
        .to_string();

    // Determine dimensions to analyze (needed for display)
    let dimensions: Vec<String> = args.dimensions.clone().unwrap_or_else(|| {
        vec![
            "stability".to_string(),
            "correctness".to_string(),
            "performance".to_string(),
        ]
    });

    // Set up progressive display state
    let display_state = Arc::new(Mutex::new(ScanDisplayState::new(workspace_label.clone())));
    let display_state_clone = Arc::clone(&display_state);
    let dimensions_clone = dimensions.clone();
    let profile_clone = args.profile.clone();

    // Initial render with 0 files
    {
        let mut state = display_state.lock().unwrap();
        state.render(&dimensions, args.profile.as_deref());
    }

    // Step 1: Scan workspace with progress callback
    let mut scanner = WorkspaceScanner::new(&current_dir).with_progress(move |progress| {
        let mut state = display_state_clone.lock().unwrap();
        state.update(&progress);
        state.render(&dimensions_clone, profile_clone.as_deref());
    });

    let workspace_info = scanner.scan().context("Failed to scan workspace")?;

    // Final render with complete info
    {
        let mut state = display_state.lock().unwrap();
        state.file_count = workspace_info.source_files.len();
        state.languages = workspace_info.language_strings();
        state.frameworks = workspace_info.framework_strings();
        state.render(&dimensions, args.profile.as_deref());
        state.clear();
    }

    if workspace_info.source_files.is_empty() {
        eprintln!(
            "{} No source files found in the current directory.",
            "⚠".yellow().bold()
        );
        return Ok(EXIT_SUCCESS);
    }

    // Run local analysis (no API needed)
    execute_client_parse(
        &args,
        &trace_id,
        &current_dir,
        &workspace_label,
        &dimensions,
        &workspace_info,
        session_start,
    )
    .await
}

/// Raw result from the analysis pipeline, before any rendering.
pub struct AnalysisResult {
    pub response: crate::output::IrAnalyzeResponse,
    pub context: ReviewOutputContext,
    pub changed_files: Vec<String>,
    pub applied_patches: usize,
    pub finding_count: usize,
}

/// Execute review with client-side parsing (default mode).
///
/// 1. Parse source files locally using tree-sitter
/// 2. Build IR (semantics + graph)
/// 3. Serialize and send IR to API
/// 4. Receive findings and optionally apply patches
async fn execute_client_parse(
    args: &ReviewArgs,
    trace_id: &str,
    current_dir: &std::path::Path,
    workspace_label: &str,
    dimensions: &[String],
    workspace_info: &crate::session::WorkspaceInfo,
    session_start: Instant,
) -> Result<i32> {
    // Create progress bar for operations
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    // Step 1: Build IR locally (with caching)
    pb.set_message("Parsing source files locally...");

    // Resolve the file list when --commit or --files are provided.
    // If neither is set we pass None so build_ir_cached discovers all files.
    let explicit_files: Option<Vec<std::path::PathBuf>> =
        if args.commit.is_some() || !args.files.is_empty() {
            let mut paths: Vec<std::path::PathBuf> = args.files.clone();

            if let Some(ref commit_ref) = args.commit {
                match get_git_commit_files(current_dir, commit_ref) {
                    Ok(commit_paths) => paths.extend(commit_paths),
                    Err(e) => {
                        pb.finish_and_clear();
                        eprintln!(
                            "{} Could not resolve commit '{}': {}",
                            "✗".red().bold(),
                            commit_ref,
                            e
                        );
                        return Ok(EXIT_INVALID_INPUT);
                    }
                }
            }

            // Deduplicate (preserving order) and canonicalize to absolute paths.
            let mut seen = std::collections::HashSet::new();
            let deduped = paths
                .into_iter()
                .map(|p| {
                    if p.is_absolute() {
                        p
                    } else {
                        current_dir.join(&p)
                    }
                })
                .filter(|p| seen.insert(p.clone()))
                .collect::<Vec<_>>();
            Some(deduped)
        } else {
            None
        };

    let parse_start = Instant::now();
    let build_result = match build_ir_cached(current_dir, explicit_files.as_deref(), args.verbose) {
        Ok(result) => result,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!("{} Failed to parse source files: {}", "✗".red().bold(), e);
            return Ok(EXIT_CONFIG_ERROR);
        }
    };
    let parse_ms = parse_start.elapsed().as_millis() as u64;

    let mut ir = build_result.ir;
    let cache_stats = build_result.cache_stats;
    let file_count = ir.file_count();

    if args.verbose {
        let stats = ir.graph.stats();
        eprintln!(
            "\n{} Built IR: {} files, {} functions, {} imports ({}ms)",
            "DEBUG".yellow(),
            stats.file_count,
            stats.function_count,
            stats.import_edge_count,
            parse_ms
        );
        eprintln!(
            "{} Cache: {} hits, {} misses ({:.1}% hit rate)",
            "DEBUG".yellow(),
            cache_stats.hits,
            cache_stats.misses,
            cache_stats.hit_rate()
        );
    }

    // Step 1b: Opportunistically enrich graph with SLOs + distributed traces.
    // Skipped entirely when --offline is passed (CI, pre-commit, air-gapped).
    // Both passes are best-effort — missing credentials or API failures don't
    // abort the review.
    //
    // Results are cached at .unfault/cache/enrichment/ with a 5-minute TTL.
    // On a cache hit the fetch round-trips to the cloud are skipped entirely;
    // on a miss data is fetched, applied, and the cache is updated.
    let fetch_ms: Option<u64>;
    let mut fetch_from_cache = false;
    if args.offline {
        fetch_ms = None;
    } else {
        let fetch_start = Instant::now();
        let mut any_fetch_attempted = false;

        // Detect GCP credentials once — used for both SLO and trace providers.
        let gcp_creds = crate::integration::gcp::GcpCredentials::from_env();
        let project_id = gcp_creds
            .as_ref()
            .map(|c| c.project_id.clone())
            .unwrap_or_default();

        // Open the enrichment cache (workspace-local, 5-min TTL).
        let cache = crate::enrichment_cache::EnrichmentCache::open(
            current_dir,
            crate::enrichment_cache::DEFAULT_TTL_SECS,
        );

        // Bust the cache when --refresh-cache is passed, then load as normal.
        if args.refresh_cache
            && !project_id.is_empty()
            && let Ok(ref c) = cache
        {
            c.invalidate(&project_id, workspace_label);
        }

        // Attempt a cache load when we have a project ID.
        let cached = if !project_id.is_empty() {
            cache
                .as_ref()
                .ok()
                .and_then(|c| c.load(&project_id, workspace_label))
        } else {
            None
        };

        if let Some(snapshot) = cached {
            // ── Cache hit — apply without network calls ───────────────────
            fetch_from_cache = true;
            any_fetch_attempted = true;

            if args.verbose {
                eprintln!(
                    "\n{} Enrichment cache hit ({}s old, TTL {}s)",
                    "DEBUG".yellow(),
                    snapshot.age_secs(),
                    snapshot.ttl_secs,
                );
            }

            apply_enrichment(
                &mut ir.graph,
                &snapshot.slos,
                snapshot
                    .trace_patterns
                    .into_iter()
                    .map(crate::trace::RemoteCallPattern::from)
                    .collect(),
                workspace_label,
                args.verbose,
            );
        } else {
            // ── Cache miss — fetch from providers ─────────────────────────
            let mut fetched_slos: Vec<crate::slo::SloDefinition> = Vec::new();
            let mut fetched_patterns: Vec<crate::trace::RemoteCallPattern> = Vec::new();

            // ── SLO enrichment ────────────────────────────────────────────
            let enricher = crate::slo::SloEnricher::new(args.verbose);
            if enricher.any_provider_available() {
                any_fetch_attempted = true;
                pb.set_message("Fetching SLOs from observability provider...");
                if args.verbose {
                    let providers = enricher.available_providers();
                    eprintln!(
                        "\n{} Fetching SLOs from: {}",
                        "DEBUG".yellow(),
                        providers.join(", ")
                    );
                }
                match enricher.fetch_all().await {
                    Ok(fetch_result) => {
                        if fetch_result.credentials_expired {
                            eprintln!(
                                "{} SLO credentials appear expired — run `unfault config integrations verify`",
                                "warn:".yellow().bold()
                            );
                        }
                        fetched_slos = fetch_result.slos;
                    }
                    Err(e) => {
                        eprintln!(
                            "{} Could not fetch SLOs: {} — run `unfault config integrations verify`",
                            "warn:".yellow().bold(),
                            e
                        );
                    }
                }
            }

            // ── Trace enrichment (GCP Cloud Trace) ───────────────────────
            // Fetch both outbound-call patterns (for the World Model / review)
            // and inbound-route observations (for `unfault graph coverage`).
            // Both use the same HTTP client and the same paged trace window so
            // we only pay one set of network round-trips.
            let mut fetched_route_observations: Vec<crate::trace::ObservedRoute> = Vec::new();

            if let Some(trace_provider) = crate::trace::GcpTraceProvider::from_env() {
                any_fetch_attempted = true;
                pb.set_message("Fetching distributed traces from Cloud Trace...");
                if args.verbose {
                    eprintln!(
                        "\n{} Fetching recent traces from GCP Cloud Trace",
                        "DEBUG".yellow()
                    );
                }

                let http_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(20))
                    .build()
                    .unwrap_or_default();

                // Outbound call patterns — used by the World Model.
                match trace_provider
                    .fetch_remote_calls(&http_client, 60, 200)
                    .await
                {
                    Ok(patterns) => {
                        fetched_patterns = patterns;
                    }
                    Err(e) => {
                        eprintln!(
                            "{} Could not fetch Cloud Trace data: {} — run `unfault config integrations verify`",
                            "warn:".yellow().bold(),
                            e
                        );
                    }
                }

                // Inbound route observations — stored in the enrichment cache
                // so that `unfault graph coverage` can use them without an
                // extra network round-trip.
                match trace_provider
                    .fetch_route_observations(&http_client, 60, 200)
                    .await
                {
                    Ok(observations) => {
                        fetched_route_observations = observations;
                    }
                    Err(e) => {
                        if args.verbose {
                            eprintln!(
                                "\n{} Could not fetch route observations from Cloud Trace: {}",
                                "DEBUG".yellow(),
                                e
                            );
                        }
                    }
                }
            }

            // Apply fetched data to the graph
            if !fetched_slos.is_empty() || !fetched_patterns.is_empty() {
                apply_enrichment(
                    &mut ir.graph,
                    &fetched_slos,
                    fetched_patterns.clone(),
                    workspace_label,
                    args.verbose,
                );
            }

            // Persist to cache for next run (best-effort, never fatal)
            if any_fetch_attempted
                && !project_id.is_empty()
                && let Ok(c) = cache
            {
                let cached_patterns: Vec<_> = fetched_patterns
                    .iter()
                    .map(crate::enrichment_cache::CachedRemoteCallPattern::from)
                    .collect();
                let cached_route_obs: Vec<_> = fetched_route_observations
                    .iter()
                    .map(crate::enrichment_cache::CachedObservedRoute::from)
                    .collect();
                let _ = c.save(
                    &project_id,
                    workspace_label,
                    fetched_slos,
                    cached_patterns,
                    cached_route_obs,
                );
            }
        }

        fetch_ms = if any_fetch_attempted {
            Some(fetch_start.elapsed().as_millis() as u64)
        } else {
            None
        };
    }

    // Step 2: Serialize IR to JSON
    pb.set_message("Serializing code graph...");

    let serialize_start = Instant::now();
    let ir_json = match serde_json::to_string(&ir) {
        Ok(json) => json,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!("{} Failed to serialize IR: {}", "✗".red().bold(), e);
            return Ok(EXIT_CONFIG_ERROR);
        }
    };
    let serialize_ms = serialize_start.elapsed().as_millis() as u64;

    if args.verbose {
        eprintln!(
            "\n{} IR JSON size: {} bytes ({}ms)",
            "DEBUG".yellow(),
            ir_json.len(),
            serialize_ms
        );
    }

    // Step 3: Compute workspace ID
    let git_remote = get_git_remote(current_dir);
    let workspace_id_result = compute_workspace_id(
        git_remote.as_deref(),
        None, // No meta files in client-side parsing (could be added later)
        Some(workspace_label),
    );
    let _workspace_id = workspace_id_result
        .as_ref()
        .map(|r| r.id.clone())
        .unwrap_or_else(|| format!("wks_{}", uuid::Uuid::new_v4().simple()));

    if args.verbose
        && let Some(ref result) = workspace_id_result
    {
        eprintln!(
            "\n{} Workspace ID: {} (source: {:?})",
            "DEBUG".yellow(),
            result.id,
            result.source
        );
    }

    // Step 4: Run analysis locally
    pb.set_message("Analyzing code graph...");

    // Build profiles from detected frameworks (e.g., "python_fastapi_backend", "go_gin_service")
    let profiles: Vec<String> = workspace_info
        .to_workspace_descriptor()
        .profiles
        .iter()
        .map(|p| p.id.clone())
        .collect();

    if args.verbose {
        eprintln!("\n{} Detected profiles: {:?}", "DEBUG".yellow(), profiles);
    }

    let analysis_start = Instant::now();
    let response =
        match crate::analysis::analyze_ir_locally(ir_json, &profiles, Some(current_dir)).await {
            Ok(response) => response,
            Err(e) => {
                pb.finish_and_clear();
                eprintln!("{} Analysis failed: {}", "✗".red().bold(), e);
                return Ok(EXIT_CONFIG_ERROR);
            }
        };
    let _analysis_ms = analysis_start.elapsed().as_millis();

    pb.finish_and_clear();

    let elapsed_ms = session_start.elapsed().as_millis() as u64;
    let engine_ms = response.elapsed_ms as u64;
    let cache_rate_opt = if cache_stats.hits > 0 || cache_stats.misses > 0 {
        Some(cache_stats.hit_rate())
    } else {
        None
    };
    let finding_count = response.findings.len();

    if args.verbose {
        eprintln!(
            "\n{} Analysis response: {} findings from {} files",
            "DEBUG".yellow(),
            finding_count,
            response.file_count
        );
    }

    let applied_patches = if args.fix || args.dry_run {
        apply_ir_patches(args, current_dir, &response.findings)?
    } else {
        0
    };

    let changed_files = get_git_changed_files(current_dir);

    let context = ReviewOutputContext {
        workspace_label: workspace_label.to_string(),
        languages: workspace_info.language_strings(),
        frameworks: workspace_info.framework_strings(),
        dimensions: dimensions.to_vec(),
        file_count,
        elapsed_ms,
        parse_ms,
        engine_ms,
        fetch_ms,
        fetch_from_cache,
        cache_hit_rate: cache_rate_opt,
        trace_id: trace_id.chars().take(8).collect(),
        profile: args.profile.clone(),
    };

    let result = AnalysisResult {
        response,
        context,
        changed_files,
        applied_patches,
        finding_count,
    };

    display_ir_findings(args, &result);

    if result.finding_count > 0 {
        Ok(EXIT_FINDINGS_FOUND)
    } else {
        Ok(EXIT_SUCCESS)
    }
}

/// Apply patches from IR findings to local files.
pub fn apply_ir_patches(
    args: &ReviewArgs,
    workspace_path: &std::path::Path,
    findings: &[IrFinding],
) -> Result<usize> {
    let applier = PatchApplier::new(workspace_path);
    let stats = applier.apply_findings(findings, args.dry_run)?;

    if args.dry_run {
        if stats.applied > 0 {
            eprintln!();
            eprintln!(
                "{} Would apply {} patch{} to {} file{}",
                "→".cyan().bold(),
                stats.applied.to_string().bright_green(),
                if stats.applied == 1 { "" } else { "es" },
                stats.modified_files.len().to_string().bright_green(),
                if stats.modified_files.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
        }
    } else if stats.applied > 0 {
        eprintln!();
        eprintln!(
            "{} Applied {} patch{} to {} file{}",
            "✓".green().bold(),
            stats.applied.to_string().bright_green(),
            if stats.applied == 1 { "" } else { "es" },
            stats.modified_files.len().to_string().bright_green(),
            if stats.modified_files.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for file in &stats.modified_files {
            eprintln!("  {} {}", "→".dimmed(), file);
        }
    }

    if !stats.errors.is_empty() {
        eprintln!();
        eprintln!("{} Some patches failed:", "⚠".yellow().bold());
        for error in &stats.errors {
            eprintln!("  {} {}", "→".red(), error);
        }
    }

    Ok(stats.applied)
}

/// Display context for IR analysis output.
pub struct ReviewOutputContext {
    pub workspace_label: String,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub dimensions: Vec<String>,
    pub file_count: usize,
    pub elapsed_ms: u64,
    pub parse_ms: u64,
    pub engine_ms: u64,
    /// Time spent on enrichment (SLO + trace). None if no providers available.
    /// Shown separately so users can distinguish tool latency from cloud API latency.
    pub fetch_ms: Option<u64>,
    /// Whether the enrichment data came from the local cache rather than live fetches.
    pub fetch_from_cache: bool,
    pub cache_hit_rate: Option<f64>,
    pub trace_id: String,
    pub profile: Option<String>,
}

/// Severity breakdown for the summary line.
struct SeveritySummary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

fn compute_severity_summary(findings: &[IrFinding]) -> SeveritySummary {
    let mut summary = SeveritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    for finding in findings {
        match finding.severity.to_lowercase().as_str() {
            "critical" => summary.critical += 1,
            "high" => summary.high += 1,
            "medium" => summary.medium += 1,
            "low" => summary.low += 1,
            _ => {}
        }
    }

    summary
}

fn format_severity_breakdown(summary: &SeveritySummary) -> String {
    let mut parts: Vec<String> = Vec::new();

    if summary.critical > 0 {
        parts.push(format!(
            "{} critical",
            summary.critical.to_string().bright_red()
        ));
    }
    if summary.high > 0 {
        parts.push(format!("{} high", summary.high.to_string().bright_red()));
    }
    if summary.medium > 0 {
        parts.push(format!(
            "{} medium",
            summary.medium.to_string().bright_yellow()
        ));
    }
    if summary.low > 0 {
        parts.push(format!("{} low", summary.low.to_string().bright_blue()));
    }

    if parts.is_empty() {
        "—".into()
    } else {
        parts.join(&format!(" {} ", "·".dimmed()))
    }
}

/// Max width for terminal output (80 chars standard)
const MAX_WIDTH: usize = 80;

/// Wrap text to fit within max_width, continuing on the next line with the given indent.
/// Returns a Vec of lines to print.
fn wrap_text(s: &str, first_line_max: usize, continuation_indent: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let words: Vec<&str> = s.split_whitespace().collect();

    if words.is_empty() {
        return vec![String::new()];
    }

    let cont_max = MAX_WIDTH.saturating_sub(continuation_indent.len());

    let mut current_line = String::new();
    let mut current_max = first_line_max;

    for word in words {
        let word_len = word.len();
        let current_len = current_line.len();

        // Check if we need to start a new line
        let would_fit = if current_len == 0 {
            word_len <= current_max
        } else {
            current_len + 1 + word_len <= current_max
        };

        if !would_fit && current_len > 0 {
            // Push the current line
            lines.push(current_line);
            // Start a new continuation line
            current_line = String::new();
            current_max = cont_max;
        }

        // Add the word to the current line
        if current_line.is_empty() {
            // If word is longer than max width, we need to hard-break it
            if word_len > current_max {
                let mut remaining = word;
                while remaining.len() > current_max {
                    let (chunk, rest) = remaining.split_at(current_max);
                    lines.push(chunk.to_string());
                    remaining = rest;
                    current_max = cont_max;
                }
                current_line = remaining.to_string();
            } else {
                current_line = word.to_string();
            }
        } else {
            current_line.push(' ');
            current_line.push_str(word);
        }
    }

    // Don't forget the last line
    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

/// Quiet single-line footer printed after findings.
///
/// All context information in one compact dimmed line — workspace, languages,
/// file count, timing, trace ID. Not a header competing for attention,
/// just provenance for anyone who needs to know what ran.
pub fn render_session_footer(context: &ReviewOutputContext) {
    let file_word = if context.file_count == 1 {
        "file"
    } else {
        "files"
    };
    let sep = "  ·  ".dimmed().to_string();

    // ── Left pill: workspace name ─────────────────────────────────────────
    let workspace = format!(" {} ", context.workspace_label)
        .bright_white()
        .bold()
        .on_bright_black();

    // ── Centre: stack ─────────────────────────────────────────────────────
    let mut stack: Vec<String> = Vec::new();
    if !context.languages.is_empty() {
        stack.push(context.languages.join(", ").cyan().to_string());
    }
    if !context.frameworks.is_empty() {
        stack.push(context.frameworks.join(", ").cyan().dimmed().to_string());
    }
    stack.push(
        format!("{} {}", context.file_count, file_word)
            .white()
            .to_string(),
    );
    let centre = stack.join(&sep);

    // ── Right bracket: timing breakdown ──────────────────────────────────
    // Show parse + engine + fetch (when present) separately so users can
    // see where time was actually spent. Total is omitted — it's the sum.
    let mut timing_parts: Vec<String> = Vec::new();
    timing_parts.push(format!("parse {}ms", context.parse_ms).dimmed().to_string());
    timing_parts.push(
        format!("engine {}ms", context.engine_ms)
            .dimmed()
            .to_string(),
    );
    if let Some(fetch) = context.fetch_ms {
        if context.fetch_from_cache {
            timing_parts.push("cached".green().dimmed().to_string());
        } else {
            timing_parts.push(format!("fetch {}ms", fetch).yellow().dimmed().to_string());
        }
    }
    let timing = timing_parts.join("  ".dimmed().to_string().as_str());
    let right = format!("[ {} ]", timing);

    println!("{}  {}   {}", workspace, centre, right);
}

// Keep old name as alias so any external callers aren't broken
pub fn render_session_overview(context: &ReviewOutputContext) {
    render_session_footer(context);
}

fn display_ir_findings(args: &ReviewArgs, result: &AnalysisResult) {
    let findings = &result.response.findings;
    let hazards = &result.response.system_hazards;
    let changed_files = &result.changed_files;
    let context = &result.context;

    if args.output_format == "json" {
        let output = serde_json::json!({
            "findings_count": result.finding_count,
            "findings": findings,
            "system_hazards": hazards,
            "patches_applied": result.applied_patches,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    if result.finding_count == 0 && hazards.is_empty() {
        println!(
            "{} No issues found! Your code looks good.",
            "✓".bright_green().bold()
        );
        render_session_footer(context);
        return;
    }

    println!();

    // SRE Hazards — always shown first, uncapped when --all is set.
    if !hazards.is_empty() {
        render_sre_hazards_section(hazards, args.all);
    }

    // Diff-aware: show changed-file top-N when git diff is available.
    let file_matches = |fp: &str| -> bool {
        changed_files.iter().any(|c| {
            fp == c.as_str() || fp.ends_with(&format!("/{}", c)) || c.ends_with(&format!("/{}", fp))
        })
    };

    if !changed_files.is_empty() {
        display_changed_files_section(findings, changed_files, &file_matches);

        let unchanged: Vec<&IrFinding> = findings
            .iter()
            .filter(|f| !file_matches(&f.file_path))
            .collect();

        if !unchanged.is_empty() {
            println!("── {} ──", "Existing issues (unchanged files)".dimmed());
            println!();
            let summary = compute_severity_summary(
                &unchanged.iter().map(|f| (*f).clone()).collect::<Vec<_>>(),
            );
            println!("  {}", format_severity_breakdown(&summary));
            println!();
            println!("  {}", "Run unfault lint for per-line details.".dimmed());
        }
    }

    render_session_footer(context);
    // No diff and not --all: hazards only, no findings noise.
}

/// Render SRE hazards — always surfaced at the top of the output.
///
/// When `all` is true, every hazard is shown with no cap.
fn render_sre_hazards_section(hazards: &[IrSystemHazard], all: bool) {
    println!("{}", "Worth looking out for".bold().bright_white());
    println!();

    let cap = if all { hazards.len() } else { 3 };
    for hazard in hazards.iter().take(cap) {
        render_system_hazard(hazard);
    }
    if !all && hazards.len() > cap {
        println!(
            "  {} {} more hazard{} — run {}",
            "…".dimmed(),
            hazards.len() - cap,
            if hazards.len() - cap == 1 { "" } else { "s" },
            "unfault review --all".cyan()
        );
        println!();
    }
}

/// Render the changed-files section: top N findings by severity + overflow count.
fn display_changed_files_section(
    findings: &[IrFinding],
    changed_files: &[String],
    file_matches: &dyn Fn(&str) -> bool,
) {
    println!(
        "── {} ({} changed) ──",
        "Changed files".bold(),
        changed_files.len()
    );
    println!();

    let changed_findings: Vec<&IrFinding> = findings
        .iter()
        .filter(|f| file_matches(&f.file_path))
        .collect();

    if changed_findings.is_empty() {
        println!(
            "  {} No issues introduced in changed files.",
            "✓".bright_green().bold()
        );
        println!();
        return;
    }

    // Sort by severity (worst first), then file path + line for stability.
    let sev_order = |s: &str| -> u8 {
        match s.to_lowercase().as_str() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        }
    };
    let mut sorted = changed_findings.clone();
    sorted.sort_by(|a, b| {
        sev_order(&a.severity)
            .cmp(&sev_order(&b.severity))
            .then(a.file_path.cmp(&b.file_path))
            .then(a.line.cmp(&b.line))
    });

    let show_n = 5;
    for finding in sorted.iter().take(show_n) {
        render_plain_finding(finding);
    }
    let remaining = sorted.len().saturating_sub(show_n);
    if remaining > 0 {
        println!(
            "  {} {} more issue{} — run {}",
            "…".dimmed(),
            remaining,
            if remaining == 1 { "" } else { "s" },
            "unfault review --all".cyan()
        );
    }
    println!();
}

/// Render a SystemHazard with full SRE context, respecting 80-column width.
fn render_system_hazard(hazard: &IrSystemHazard) {
    let sev_icon = severity_icon(&hazard.effective_severity);
    let indent = "     ";

    // ── Line 1: severity  file:line  ·  aka ─────────────────────────────────
    //
    // "  🟡  app-a/main.py:12  ·  The Slow Death"
    //
    // The file:line is the developer's "you are here". The aka names the
    // hazard category. No glossary ID — the user doesn't need to read it here.
    let path_line = format!("{}:{}", hazard.file_path, hazard.line);
    let aka_sep = "·".dimmed();
    let icon_prefix_width = 6usize; // "  🟡  "
    let aka_width = 2 + hazard.aka.len(); // " · " + aka
    let path_budget = COL_WIDTH
        .saturating_sub(icon_prefix_width)
        .saturating_sub(aka_width);
    let path_display = if path_line.len() > path_budget {
        format!(
            "…{}",
            &path_line[path_line
                .len()
                .saturating_sub(path_budget.saturating_sub(1))..]
        )
    } else {
        path_line.clone()
    };
    println!(
        "  {}  {}  {} {}",
        sev_icon,
        path_display.cyan(),
        aka_sep,
        hazard.aka.bright_white().bold(),
    );

    // ── Line 2: finding title — the specific code observation ──────────────
    //
    // "     FastAPI app `app` has no request timeout middleware"
    //
    // This is the bridge from code to system: what exactly was found.
    // Shown only when we have it; the one_line_impact is the fallback.
    let code_observation = if !hazard.finding_title.is_empty() {
        hazard.finding_title.clone()
    } else {
        // Strip the "Propagation risk N% — reaches SLO '...'. " prefix if present
        if hazard.anchored_to_slo {
            hazard
                .one_line_impact
                .find("'. ")
                .map(|pos| hazard.one_line_impact[pos + 3..].to_string())
                .unwrap_or_else(|| hazard.one_line_impact.clone())
        } else {
            hazard.one_line_impact.clone()
        }
    };
    for line in word_wrap(&code_observation, indent, indent, COL_WIDTH) {
        println!("{}", line.dimmed());
    }

    // ── Line 3: system view — what is at stake ──────────────────────────────
    //
    // "     ↳ puts  App B Availability SLO  at risk  (100%)"
    //   or
    // "     ↳ propagates to  main.py  (entrypoint)"
    //
    // This is the zoom-out: code decision → system consequence.
    // Only shown when the World Model found a meaningful anchor.
    if hazard.aggregate_risk > 0.0
        && let Some(ref goal) = hazard.macro_goal
    {
        let anchor = goal.rsplit('/').next().unwrap_or(goal);
        if hazard.anchored_to_slo {
            println!(
                "{}{}  {}  {}",
                indent,
                "↳ puts".dimmed(),
                anchor.bright_white().bold(),
                format!("at risk  ({:.0}%)", hazard.aggregate_risk).yellow(),
            );
        } else {
            println!(
                "{}{}  {}  {}",
                indent,
                "↳ propagates to".dimmed(),
                anchor.white(),
                "(entrypoint)".dimmed(),
            );
        }
    }

    // ── Line 4: what the hazard means in plain language ─────────────────────
    //
    // The one_line_impact hazard sentence — stripped of any World Model prefix.
    // Skipped if the finding title already covers this ground (when they're
    // essentially the same sentence), otherwise adds the systemic framing.
    let hazard_sentence = if hazard.anchored_to_slo {
        hazard
            .one_line_impact
            .find("'. ")
            .map(|pos| hazard.one_line_impact[pos + 3..].to_string())
            .unwrap_or_else(|| hazard.one_line_impact.clone())
    } else {
        hazard.one_line_impact.clone()
    };
    // Only print if it adds something beyond the finding title
    if !hazard_sentence.is_empty() && hazard_sentence != code_observation {
        for line in word_wrap(&hazard_sentence, indent, indent, COL_WIDTH) {
            println!("{}", line.dimmed());
        }
    }

    // ── Lines 5-6: tradeoff — the why, stripped of gain/risk labels ─────────
    //
    // "     + no timeout overhead at call time"
    // "     - one slow upstream saturates the pool for every concurrent request"
    //
    // Labels removed — the +/- signs carry the valence. Text is trimmed to
    // remove the redundant "Simplicity: " / "Systemic availability: " prefixes
    // since the hazard sentence above already names the failure mode.
    if !hazard.tradeoff_gain.is_empty() {
        println!("     {}", "Tradeoff".bright_white());
        print_tradeoff_category_line(indent, &hazard.tradeoff_gain, COL_WIDTH);
        print_tradeoff_category_line(indent, &hazard.tradeoff_risk, COL_WIDTH);
    }

    println!();
}

/// Render a tradeoff line using the category label as the left-column anchor.
///
/// Input format: "Category: sentence about the tradeoff."
/// e.g. "Simplicity: no timeout means less code..."
///      "Systemic metastability: synchronized retries..."
///
/// Output:
///   "     simplicity        no timeout means less code..."
///   "     systemic metastab synchronized retries with no..."  (truncated label)
///
/// The category label is left-aligned in a fixed-width column (dimmed),
/// the sentence text wraps in the remaining space (plain dimmed white).
/// No +/- sigils — the category names carry the meaning directly.
fn print_tradeoff_category_line(indent: &str, s: &str, col: usize) {
    // "↳ " prefix before the label — 2 visible chars
    const ARROW: &str = "↳ ";
    const LABEL_COL: usize = 22; // fixed label column width (chars)
    // Total left margin for continuation lines:
    //   indent(5) + "↳ "(2) + label(22) + "  "(2) = 31 chars
    const ARROW_LEN: usize = 2;

    // Split at the first ": " to get label + body
    let (label_raw, body) = if let Some(pos) = s.find(": ") {
        let prefix = &s[..pos];
        let word_count = prefix.split_whitespace().count();
        if word_count <= 4 && !prefix.contains('.') && !prefix.contains(',') {
            (prefix, &s[pos + 2..])
        } else {
            ("", s)
        }
    } else {
        ("", s)
    };

    // Title-case: capitalize first letter of each word
    let label_titled: String = label_raw
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    // Pad to fixed column width for alignment
    let label_padded = if label_titled.len() > LABEL_COL {
        label_titled[..LABEL_COL].to_string()
    } else {
        format!("{:<width$}", label_titled, width = LABEL_COL)
    };

    // Continuation lines align under the body (past indent + arrow + label + gap)
    let cont_indent = format!("{}{}{}", indent, " ".repeat(ARROW_LEN + LABEL_COL), "  ");
    let first_prefix = format!("{}{}{}  ", indent, ARROW, label_padded);

    let lines = word_wrap(body, &first_prefix, &cont_indent, col);
    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            let body_part = line.strip_prefix(&first_prefix).unwrap_or(line);
            println!(
                "{}{}{}  {}",
                indent,
                ARROW.dimmed(),
                label_padded.bright_white(),
                body_part.dimmed(),
            );
        } else {
            println!("{}", line.dimmed());
        }
    }
}

/// Render a plain finding in compact one-line form, respecting 80-column width.
fn render_plain_finding(finding: &IrFinding) {
    let icon = severity_icon(&finding.severity);
    let title = if !finding.title.is_empty() {
        finding.title.as_str()
    } else {
        finding.rule_id.as_str()
    };

    // Visible prefix: "  " + icon(2) + "  " = 6 chars, then "path:line  ".
    let icon_prefix_width = 6usize;
    let path_line = format!("{}:{}", finding.file_path, finding.line);
    // separator between path:line and title = 2 chars ("  ")
    let title_budget = COL_WIDTH
        .saturating_sub(icon_prefix_width)
        .saturating_sub(path_line.len())
        .saturating_sub(2);
    let title_display = truncate(title, title_budget);

    println!(
        "  {}  {}  {}",
        icon,
        path_line.cyan(),
        title_display.dimmed()
    );
}

fn severity_icon(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🔵",
        _ => "⚪",
    }
}

/// Display IR findings grouped by severity and rule_id (basic mode).
/// Format matches the landing page TerminalDemo.
pub fn display_ir_findings_grouped(findings: &[IrFinding]) {
    use std::collections::BTreeMap;

    let severity_order = |s: &str| -> u8 {
        match s.to_lowercase().as_str() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        }
    };

    let mut grouped: BTreeMap<u8, BTreeMap<String, Vec<&IrFinding>>> = BTreeMap::new();

    for finding in findings {
        let sev_key = severity_order(&finding.severity);
        grouped
            .entry(sev_key)
            .or_default()
            .entry(finding.rule_id.clone())
            .or_default()
            .push(finding);
    }

    let mut first_severity = true;
    for (sev_key, rules_by_id) in &grouped {
        if !first_severity {
            println!();
        }
        first_severity = false;

        let severity_name = match sev_key {
            0 => "Critical",
            1 => "High",
            2 => "Medium",
            3 => "Low",
            _ => "Other",
        };

        let severity_icon = match sev_key {
            0 => "🔴",
            1 => "🟠",
            2 => "🟡",
            3 => "🔵",
            _ => "⚪",
        };

        let severity_color = match sev_key {
            0 | 1 => "red",
            2 => "yellow",
            3 => "blue",
            _ => "white",
        };

        let severity_count: usize = rules_by_id.values().map(|v| v.len()).sum();
        println!(
            "{} {} ({} issue{})",
            severity_icon,
            severity_name.color(severity_color).bold(),
            severity_count,
            if severity_count == 1 { "" } else { "s" }
        );

        // Display each rule as: [rule_id] title (matches landing page)
        // Format: "   [rule_id] title" - wrap to fit 80 chars
        for (rule_id, rule_findings) in rules_by_id {
            let sample = rule_findings[0];
            let title = if !sample.title.is_empty() {
                sample.title.clone()
            } else if !sample.message.is_empty() {
                sample.message.clone()
            } else {
                sample.rule_id.clone()
            };

            // Calculate available space: 80 - "   [" - rule_id - "] " = 80 - 5 - rule_id.len()
            let prefix_len = 5 + rule_id.len(); // "   [" + rule_id + "] "
            let first_line_max = MAX_WIDTH.saturating_sub(prefix_len);
            let continuation_indent = "      "; // 6 spaces for continuation lines

            let wrapped_lines = wrap_text(&title, first_line_max, continuation_indent);

            // Print first line with the rule_id prefix
            if let Some(first_line) = wrapped_lines.first() {
                println!("   [{}] {}", rule_id.cyan(), first_line.dimmed());
            }

            // Print continuation lines with indent
            for line in wrapped_lines.iter().skip(1) {
                println!("{}{}", continuation_indent, line.dimmed());
            }
        }
    }
}

// ── Enrichment helpers ────────────────────────────────────────────────────────

/// Apply SLOs and trace patterns to the code graph.
///
/// Extracted so both the cache-hit and cache-miss paths share identical logic.
fn apply_enrichment(
    graph: &mut unfault_core::CodeGraph,
    slos: &[crate::slo::SloDefinition],
    trace_patterns: Vec<crate::trace::RemoteCallPattern>,
    workspace_label: &str,
    verbose: bool,
) {
    // SLO enrichment
    if !slos.is_empty() {
        let enricher = crate::slo::SloEnricher::new(verbose);
        match enricher.enrich_graph(graph, slos) {
            Ok(added) => {
                if verbose || added > 0 {
                    eprintln!(
                        "\n{} Linked {} SLO(s) to code graph as Macro-Goals",
                        "✓".green(),
                        added
                    );
                }
            }
            Err(e) => {
                if verbose {
                    eprintln!("{} SLO enrichment failed: {}", "warn:".yellow().bold(), e);
                }
            }
        }

        // Service-level SLOs link to all routes of the matching local service
        for slo in crate::slo::get_service_level_slos(slos) {
            if slo.matches_local_service(workspace_label) {
                enricher.link_service_slo_to_all_routes(graph, slo);
            } else if verbose {
                eprintln!(
                    "  Skipping SLO '{}' — belongs to a different service",
                    slo.name
                );
            }
        }
    }

    // Trace enrichment
    if !trace_patterns.is_empty() {
        let http_caller_files = collect_http_caller_files(graph);
        match crate::trace::enrich_graph(graph, &trace_patterns, &http_caller_files, verbose) {
            Ok(result) => {
                if verbose || result.edges_added > 0 {
                    eprintln!(
                        "\n{} Trace enrichment: {} remote service(s), {} cross-service edge(s)",
                        "✓".green(),
                        result.remote_services_added,
                        result.edges_added,
                    );
                    if verbose && !result.linked_services.is_empty() {
                        eprintln!("   Remote services: {}", result.linked_services.join(", "));
                    }
                }
            }
            Err(e) => {
                if verbose {
                    eprintln!("{} Trace enrichment failed: {}", "warn:".yellow().bold(), e);
                }
            }
        }
    }
}

// ── Graph enrichment helpers ──────────────────────────────────────────────────

/// Collect file paths that make outbound HTTP/RPC calls, by inspecting
/// `UsesLibrary` edges to `HttpClient`-category external modules.
///
/// These files are the candidates to link to `RemoteService` nodes via
/// `RemoteCall` edges during trace enrichment.
fn collect_http_caller_files(graph: &unfault_core::CodeGraph) -> Vec<String> {
    use petgraph::Direction;
    use petgraph::visit::EdgeRef as _;
    use unfault_core::graph::{GraphEdgeKind, GraphNode, ModuleCategory};

    let mut files: std::collections::HashSet<String> = std::collections::HashSet::new();

    for idx in graph.graph.node_indices() {
        // Only look at HttpClient external modules
        if !matches!(
            &graph.graph[idx],
            GraphNode::ExternalModule {
                category: ModuleCategory::HttpClient,
                ..
            }
        ) {
            continue;
        }

        // Walk incoming UsesLibrary edges to find callers
        for edge in graph.graph.edges_directed(idx, Direction::Incoming) {
            if !matches!(edge.weight(), GraphEdgeKind::UsesLibrary) {
                continue;
            }
            if let GraphNode::File { path, .. } = &graph.graph[edge.source()] {
                files.insert(path.clone());
            }
        }
    }

    files.into_iter().collect()
}
