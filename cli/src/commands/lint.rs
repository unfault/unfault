// unfault-ignore: rust.println_in_lib
//! # Lint Command
//!
//! Line-level findings: every rule hit, grouped by severity and rule ID,
//! with fix hints. This is the detailed companion to `unfault review`.
//!
//! ```bash
//! unfault lint              # all findings, grouped
//! unfault lint --fix        # auto-apply patches
//! unfault lint --output json
//! ```

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::exit_codes::*;
use crate::output::IrFinding;
use crate::session::{
    WorkspaceScanner, build_ir_cached, get_git_changed_files, get_git_commit_files,
};

use super::review::{AnalysisResult, ReviewOutputContext};

pub struct LintArgs {
    pub output_format: String,
    pub verbose: bool,
    pub profile: Option<String>,
    pub dimensions: Option<Vec<String>>,
    pub fix: bool,
    pub dry_run: bool,
    /// Analyze only files changed in this git commit ref (SHA, branch, HEAD~N, …).
    /// When combined with `files`, both sets are unioned and deduplicated.
    pub commit: Option<String>,
    /// Analyze only these specific files.
    /// When combined with `commit`, both sets are unioned and deduplicated.
    pub files: Vec<std::path::PathBuf>,
}

pub async fn execute(args: LintArgs) -> Result<i32> {
    let trace_id = uuid::Uuid::new_v4().simple().to_string();
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;
    let session_start = Instant::now();

    let workspace_label = current_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace")
        .to_string();

    let dimensions: Vec<String> = args.dimensions.clone().unwrap_or_else(|| {
        vec![
            "stability".to_string(),
            "correctness".to_string(),
            "performance".to_string(),
        ]
    });

    // Progressive scan display (same as review).
    let display_state = Arc::new(Mutex::new(LintScanState::new(workspace_label.clone())));
    let display_state_clone = Arc::clone(&display_state);
    let dimensions_clone = dimensions.clone();
    let profile_clone = args.profile.clone();

    {
        let mut state = display_state.lock().unwrap();
        state.render(&dimensions, args.profile.as_deref());
    }

    let mut scanner = WorkspaceScanner::new(&current_dir).with_progress(move |progress| {
        let mut state = display_state_clone.lock().unwrap();
        state.file_count = progress.file_count;
        state.languages = progress.languages.clone();
        state.frameworks = progress.frameworks.clone();
        state.render(&dimensions_clone, profile_clone.as_deref());
    });

    let workspace_info = scanner.scan().context("Failed to scan workspace")?;

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

    // Build IR.
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_message("Parsing source files...");

    // Resolve the file list when --commit or --files are provided.
    let explicit_files: Option<Vec<std::path::PathBuf>> =
        if args.commit.is_some() || !args.files.is_empty() {
            let mut paths: Vec<std::path::PathBuf> = args.files.clone();

            if let Some(ref commit_ref) = args.commit {
                match get_git_commit_files(&current_dir, commit_ref) {
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
    let build_result = match build_ir_cached(&current_dir, explicit_files.as_deref(), args.verbose)
    {
        Ok(r) => r,
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

    pb.set_message("Analyzing...");

    let ir_json = match serde_json::to_string(&ir) {
        Ok(j) => j,
        Err(e) => {
            pb.finish_and_clear();
            eprintln!("{} Failed to serialize IR: {}", "✗".red().bold(), e);
            return Ok(EXIT_CONFIG_ERROR);
        }
    };

    let profiles: Vec<String> = workspace_info
        .to_workspace_descriptor()
        .profiles
        .iter()
        .map(|p| p.id.clone())
        .collect();

    let response =
        match crate::analysis::analyze_ir_locally(ir_json, &profiles, Some(&current_dir)).await {
            Ok(r) => r,
            Err(e) => {
                pb.finish_and_clear();
                eprintln!("{} Analysis failed: {}", "✗".red().bold(), e);
                return Ok(EXIT_CONFIG_ERROR);
            }
        };

    pb.finish_and_clear();

    let elapsed_ms = session_start.elapsed().as_millis() as u64;
    let engine_ms = response.elapsed_ms as u64;
    let cache_rate_opt = if cache_stats.hits > 0 || cache_stats.misses > 0 {
        Some(cache_stats.hit_rate())
    } else {
        None
    };
    let finding_count = response.findings.len();

    // Apply patches if requested.
    let applied_patches = if args.fix || args.dry_run {
        apply_lint_patches(&args, &current_dir, &response.findings)?
    } else {
        0
    };

    let changed_files = get_git_changed_files(&current_dir);

    let context = ReviewOutputContext {
        workspace_label: workspace_label.clone(),
        languages: workspace_info.language_strings(),
        frameworks: workspace_info.framework_strings(),
        dimensions: dimensions.clone(),
        file_count,
        elapsed_ms,
        parse_ms,
        engine_ms,
        fetch_ms: None,
        fetch_from_cache: false,
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

    display_lint_findings(&args, &result);

    if finding_count > 0 {
        Ok(EXIT_FINDINGS_FOUND)
    } else {
        Ok(EXIT_SUCCESS)
    }
}

fn display_lint_findings(args: &LintArgs, result: &AnalysisResult) {
    let findings = &result.response.findings;

    if args.output_format == "json" {
        let output = serde_json::json!({
            "findings_count": result.finding_count,
            "findings": findings,
            "patches_applied": result.applied_patches,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    println!();
    super::review::render_session_overview(&result.context);

    if result.finding_count == 0 {
        println!(
            "{} No issues found! Your code looks good.",
            "✓".bright_green().bold()
        );
        return;
    }

    println!();

    // Summary line.
    let fix_hint = if !args.fix && !args.dry_run {
        format!("{}", "run with --fix to apply patches".dimmed())
    } else {
        String::new()
    };

    let total = result.finding_count;
    let found_text = format!(
        "⚠ Found {} issue{}",
        total,
        if total == 1 { "" } else { "s" }
    );
    if fix_hint.is_empty() {
        println!(
            "{} Found {} issue{}",
            "⚠".yellow().bold(),
            total.to_string().bright_yellow(),
            if total == 1 { "" } else { "s" }
        );
    } else {
        let padding = 50_usize.saturating_sub(found_text.len());
        println!(
            "{} Found {} issue{}{:>width$}{}",
            "⚠".yellow().bold(),
            total.to_string().bright_yellow(),
            if total == 1 { "" } else { "s" },
            "",
            fix_hint,
            width = padding
        );
    }

    if result.applied_patches > 0 {
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
            result.applied_patches.to_string().bright_green(),
            if result.applied_patches == 1 {
                ""
            } else {
                "es"
            }
        );
    }

    println!();
    super::review::display_ir_findings_grouped(findings);
}

fn apply_lint_patches(
    args: &LintArgs,
    workspace_path: &std::path::Path,
    findings: &[IrFinding],
) -> Result<usize> {
    let review_args = super::review::ReviewArgs {
        output_format: args.output_format.clone(),
        output_mode: "full".to_string(),
        verbose: args.verbose,
        profile: args.profile.clone(),
        dimensions: args.dimensions.clone(),
        fix: args.fix,
        dry_run: args.dry_run,
        all: false,
        refresh_cache: false,
        offline: false,
        commit: args.commit.clone(),
        files: args.files.clone(),
    };
    super::review::apply_ir_patches(&review_args, workspace_path, findings)
}

/// Minimal scan-state display for lint (mirrors review's ScanDisplayState).
struct LintScanState {
    workspace_label: String,
    languages: Vec<String>,
    frameworks: Vec<String>,
    file_count: usize,
    lines_printed: usize,
}

impl LintScanState {
    fn new(workspace_label: String) -> Self {
        Self {
            workspace_label,
            languages: Vec::new(),
            frameworks: Vec::new(),
            file_count: 0,
            lines_printed: 0,
        }
    }

    fn render(&mut self, dimensions: &[String], _profile: Option<&str>) {
        if self.lines_printed > 0 {
            for _ in 0..self.lines_printed {
                eprint!("\x1b[1A\x1b[2K");
            }
        }
        let mut lines = 0;

        eprintln!("→ Linting {}...", self.workspace_label.bold());
        lines += 1;

        if !self.languages.is_empty() {
            eprintln!("  Languages: {}", self.languages.join(", ").dimmed());
            lines += 1;
        }
        if !self.frameworks.is_empty() {
            eprintln!("  Frameworks: {}", self.frameworks.join(", ").dimmed());
            lines += 1;
        }

        eprintln!("  Dimensions: {}", dimensions.join(", ").dimmed());
        lines += 1;

        if self.file_count > 0 {
            eprintln!(
                "  Found {} matching source {}",
                self.file_count.to_string().bright_green(),
                if self.file_count == 1 {
                    "file"
                } else {
                    "files"
                }
            );
            lines += 1;
        }

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
