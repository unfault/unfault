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

use crate::api::graph::IrFinding;
use crate::exit_codes::*;
use crate::session::{
    PatchApplier, ScanProgress, WorkspaceScanner, build_ir_cached,
    compute_workspace_id, get_git_remote,
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
        let file_word = if self.file_count == 1 { "file" } else { "files" };
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

    let parse_start = Instant::now();
    let build_result = match build_ir_cached(current_dir, None, args.verbose) {
        Ok(result) => result,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!("{} Failed to parse source files: {}", "✗".red().bold(), e);
            return Ok(EXIT_CONFIG_ERROR);
        }
    };
    let parse_ms = parse_start.elapsed().as_millis() as u64;

    let ir = build_result.ir;
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
    let workspace_id = workspace_id_result
        .as_ref()
        .map(|r| r.id.clone())
        .unwrap_or_else(|| format!("wks_{}", uuid::Uuid::new_v4().simple()));

    if args.verbose {
        if let Some(ref result) = workspace_id_result {
            eprintln!(
                "\n{} Workspace ID: {} (source: {:?})",
                "DEBUG".yellow(),
                result.id,
                result.source
            );
        }
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
    let response = match crate::analysis::analyze_ir_locally(ir_json, &profiles).await {
        Ok(response) => response,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!("{} Analysis failed: {}", "✗".red().bold(), e);
            return Ok(EXIT_CONFIG_ERROR);
        }
    };
    let _analysis_ms = analysis_start.elapsed().as_millis();

    pb.finish_and_clear();

    // Calculate elapsed time
    let elapsed = session_start.elapsed();
    let elapsed_ms = elapsed.as_millis() as u64;
    let engine_ms = response.elapsed_ms as u64;

    // Get cache hit rate for display context
    let cache_hit_rate = cache_stats.hit_rate();
    let cache_rate_opt = if cache_stats.hits > 0 || cache_stats.misses > 0 {
        Some(cache_hit_rate)
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

    // Handle fix/dry-run mode
    let applied_patches = if args.fix || args.dry_run {
        apply_ir_patches(args, current_dir, &response.findings)?
    } else {
        0
    };

    // Display results
    let display_context = ReviewOutputContext {
        workspace_label: workspace_label.to_string(),
        languages: workspace_info.language_strings(),
        frameworks: workspace_info.framework_strings(),
        dimensions: dimensions.to_vec(),
        file_count,
        elapsed_ms,
        parse_ms,
        engine_ms,
        cache_hit_rate: cache_rate_opt,
        trace_id: trace_id.chars().take(8).collect(),
        profile: args.profile.clone(),
    };

    display_ir_findings(args, &response.findings, applied_patches, &display_context);

    if finding_count > 0 {
        Ok(EXIT_FINDINGS_FOUND)
    } else {
        Ok(EXIT_SUCCESS)
    }
}

/// Apply patches from IR findings to local files.
fn apply_ir_patches(
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
struct ReviewOutputContext {
    workspace_label: String,
    languages: Vec<String>,
    frameworks: Vec<String>,
    dimensions: Vec<String>,
    file_count: usize,
    elapsed_ms: u64,
    parse_ms: u64,
    engine_ms: u64,
    cache_hit_rate: Option<f64>,
    trace_id: String,
    profile: Option<String>,
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

fn render_session_overview(context: &ReviewOutputContext) {
    // Line 1: Header with workspace name and total time
    println!(
        "{} Analyzing {}... {}",
        "→".cyan().bold(),
        context.workspace_label.bright_white(),
        format!("{}ms", context.elapsed_ms).dimmed()
    );

    // Line 2: Languages
    let langs = format_list(&context.languages, ", ");
    println!("  {}: {}", "Languages".dimmed(), langs.cyan());

    // Line 3: Frameworks
    let frameworks = format_list(&context.frameworks, ", ");
    println!("  {}: {}", "Frameworks".dimmed(), frameworks.cyan());

    // Line 4: Dimensions
    let dims = format_list(&context.dimensions, " · ");
    println!("  {}: {}", "Dimensions".dimmed(), dims.cyan());

    // Line 5: Profile (if overridden)
    if let Some(profile) = &context.profile {
        println!("  {}: {}", "Profile".dimmed(), profile.cyan());
    }

    // Line 6: Files reviewed with timing
    let file_word = if context.file_count == 1 { "file" } else { "files" };
    println!(
        "  {}: {} {} · parse {}ms · engine {}ms",
        "Reviewed".dimmed(),
        context.file_count.to_string().bright_green(),
        file_word,
        context.parse_ms,
        context.engine_ms
    );

    // Line 7: Cache and trace info
    let cache_str = match context.cache_hit_rate {
        Some(rate) => format!("{:.0}%", rate),
        None => "—".to_string(),
    };
    println!(
        "  {}: {}  {}: {}",
        "Cache".dimmed(),
        cache_str.dimmed(),
        "Trace".dimmed(),
        context.trace_id.dimmed()
    );
}

fn format_list(values: &[String], separator: &str) -> String {
    if values.is_empty() {
        "—".into()
    } else {
        values.join(separator)
    }
}

fn display_ir_findings(
    args: &ReviewArgs,
    findings: &[IrFinding],
    applied_patches: usize,
    context: &ReviewOutputContext,
) {
    let total_findings = findings.len();

    if args.output_format == "json" {
        let output = serde_json::json!({
            "findings_count": total_findings,
            "findings": findings,
            "patches_applied": applied_patches,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    // Text output
    println!();

    render_session_overview(context);

    if total_findings == 0 {
        println!(
            "{} No issues found! Your code looks good.",
            "✓".bright_green().bold()
        );
        return;
    }

    // Blank line before the summary (matches landing page)
    println!();

    // Summary line with issue count and fix hint on the right
    let fix_hint = if !args.fix && !args.dry_run {
        format!("{}", "run with --fix to apply patches".dimmed())
    } else {
        String::new()
    };
    
    // Find terminal width for right-alignment (default to 80)
    let found_text = format!(
        "{} Found {} issue{}",
        "⚠",
        total_findings,
        if total_findings == 1 { "" } else { "s" }
    );
    
    if fix_hint.is_empty() {
        println!(
            "{} Found {} issue{}",
            "⚠".yellow().bold(),
            total_findings.to_string().bright_yellow(),
            if total_findings == 1 { "" } else { "s" }
        );
    } else {
        // Print summary with fix hint on the right
        let padding = 50_usize.saturating_sub(found_text.len());
        println!(
            "{} Found {} issue{}{:>width$}{}",
            "⚠".yellow().bold(),
            total_findings.to_string().bright_yellow(),
            if total_findings == 1 { "" } else { "s" },
            "",
            fix_hint,
            width = padding
        );
    }
    
    // Severity breakdown line (like landing page: "4 high · 10 medium · 5 low")
    let summary = compute_severity_summary(findings);
    println!("{}", format_severity_breakdown(&summary));

    if applied_patches > 0 {
        let verb = if args.dry_run {
            "Would apply"
        } else {
            "Applied"
        };
        println!(
            "  {} {} {} patch{}",
            if args.dry_run {
                "→".cyan().bold()
            } else {
                "✓".green().bold()
            },
            verb,
            applied_patches.to_string().bright_green(),
            if applied_patches == 1 { "" } else { "es" }
        );
    }

    println!();

    if args.output_mode == "full" {
        for finding in findings {
            display_ir_finding(finding);
        }
    } else {
        // Basic mode: grouped display (matches landing page style)
        display_ir_findings_grouped(findings);
    }
}

/// Display a single IR finding (full mode).
fn display_ir_finding(finding: &IrFinding) {
    let severity_color = match finding.severity.as_str() {
        "critical" | "Critical" => "red",
        "high" | "High" => "red",
        "medium" | "Medium" => "yellow",
        "low" | "Low" => "blue",
        _ => "white",
    };

    let severity_icon = match finding.severity.to_lowercase().as_str() {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🔵",
        _ => "⚪",
    };

    println!(
        "{} {} [{}]",
        severity_icon,
        finding.rule_id.bold(),
        finding.severity.color(severity_color)
    );

    println!("   {}", finding.message.dimmed());
    println!(
        "   File: {}:{}:{}",
        finding.file_path.cyan(),
        finding.line,
        finding.column
    );

    if let Some(patch) = &finding.patch {
        println!();
        println!("   {}", "Suggested fix:".green().bold());
        for line in patch.lines() {
            if line.starts_with('+') && !line.starts_with("+++") {
                println!("   {}", line.green());
            } else if line.starts_with('-') && !line.starts_with("---") {
                println!("   {}", line.red());
            } else {
                println!("   {}", line.dimmed());
            }
        }
    }
    println!();
}

/// Display IR findings grouped by severity and rule_id (basic mode).
/// Format matches the landing page TerminalDemo.
fn display_ir_findings_grouped(findings: &[IrFinding]) {
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
                println!(
                    "   [{}] {}",
                    rule_id.cyan(),
                    first_line.dimmed()
                );
            }
            
            // Print continuation lines with indent
            for line in wrapped_lines.iter().skip(1) {
                println!("{}{}", continuation_indent, line.dimmed());
            }
        }
    }
}

