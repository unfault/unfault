//! # Ask Command
//!
//! Implements the ask command for querying project health via RAG.
//!
//! ## Usage
//!
//! ```bash
//! # Ask a question about your project
//! unfault ask "How is my service doing?"
//!
//! # Ask with a specific workspace filter
//! unfault ask "What are the main stability concerns?" --workspace wks_abc123
//!
//! # Get JSON output
//! unfault ask "Show performance issues" --json
//! ```

use anyhow::Result;
use colored::Colorize;

use crate::config::Config;
use crate::exit_codes::*;

/// Arguments for the ask command
pub struct AskArgs {
    /// The question to ask
    pub query: String,
    /// Workspace ID (optional)
    pub workspace_id: Option<String>,
    /// Workspace path (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Maximum sessions to search
    pub max_sessions: Option<i32>,
    /// Maximum findings to return
    pub max_findings: Option<i32>,
    /// Similarity threshold
    pub similarity_threshold: Option<f32>,
    /// Output as JSON
    pub json: bool,
    /// Disable LLM
    pub no_llm: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Execute the ask command
///
/// * `Ok(EXIT_SUCCESS)` - Query completed successfully
/// * `Ok(EXIT_CONFIG_ERROR)` - Not logged in or configuration error
/// * `Ok(EXIT_AUTH_ERROR)` - API key is invalid
/// * `Ok(EXIT_NETWORK_ERROR)` - Cannot reach the API
/// * `Ok(EXIT_SERVICE_UNAVAILABLE)` - Embedding service not available
pub async fn execute(args: AskArgs) -> Result<i32> {
    // Load configuration (needed for LLM config)
    let config = Config::load().ok();

    // Resolve workspace path
    let workspace_path = match args.workspace_path.as_ref() {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!("{} Querying: {}", "→".cyan(), args.query);
    }

    // Build local graph for the query
    let graph = match crate::local_graph::build_analysis_graph(&workspace_path, args.verbose) {
        Ok(g) => Some(g),
        Err(e) => {
            if args.verbose {
                eprintln!("  {} Failed to build graph: {}", "⚠".yellow(), e);
            }
            None
        }
    };

    // Execute RAG query locally
    let query_config = unfault_rag::QueryConfig {
        max_depth: 10,
        max_findings: args.max_findings.unwrap_or(10) as usize,
        top_n_centrality: 10,
        workspace_id: args.workspace_id.clone(),
    };

    let response = unfault_rag::execute_query(
        &args.query,
        graph.as_ref(),
        None, // No vector store yet (will be added when embeddings are configured)
        None, // No embedding provider yet
        &query_config,
    )
    .await
    .map_err(|e| anyhow::anyhow!("RAG query failed: {}", e))?;

    // Check if LLM is configured for generating AI response (unless --no-llm)
    let llm_ready = config.as_ref().map(|c| c.llm_ready()).unwrap_or(false);
    let llm_response = if !args.no_llm && llm_ready {
        let llm_config = config.as_ref().unwrap().llm.as_ref().unwrap();

        if args.verbose {
            eprintln!(
                "{} Using {} ({}) for AI response...",
                "→".cyan(),
                llm_config.provider,
                llm_config.model
            );
        }

        // Build context for LLM from the local RAG response
        let llm_context = format!(
            "Context: {}\n\nFindings:\n{}",
            response.context_summary,
            response
                .findings
                .iter()
                .map(|f| format!(
                    "- [{}] {} in {} ({})",
                    f.finding.severity, f.finding.title, f.finding.file_path, f.finding.rule_id
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );

        // Create LLM client and generate response with streaming
        match crate::api::llm::LlmClient::new_with_options(llm_config, args.verbose) {
            Ok(client) => {
                println!();
                println!(
                    "{} {} {}",
                    "🤖".green(),
                    "AI Analysis".bold().underline(),
                    format!("({})", llm_config.model).dimmed()
                );
                println!();

                match client.generate_streaming(&args.query, &llm_context).await {
                    Ok(text) => {
                        let trimmed = text.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed.to_string())
                        }
                    }
                    Err(e) => {
                        if args.verbose {
                            eprintln!("{} LLM error: {}", "⚠".yellow(), e);
                        }
                        None
                    }
                }
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("{} LLM client error: {}", "⚠".yellow(), e);
                }
                None
            }
        }
    } else {
        None
    };

    // Output results
    let streamed = llm_response.is_some();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        // Print context summary
        if !streamed {
            println!();
            println!("{} {}", "→".cyan(), response.context_summary);
        }

        // Print flow context
        if let Some(ref flow) = response.flow_context {
            println!();
            println!("{} {}", "🔗".cyan(), "Call Flow:".bold());
            for path in &flow.paths {
                for node in path {
                    let indent = "  ".repeat(node.depth + 1);
                    let file_info = node.file_path.as_deref().unwrap_or("");
                    println!(
                        "{}→ {} {}",
                        indent,
                        node.name.bright_white(),
                        file_info.dimmed()
                    );
                }
            }
        }

        // Print graph context
        if let Some(ref ctx) = response.graph_context {
            if !ctx.affected_files.is_empty() {
                println!();
                println!("{} {}", "📊".cyan(), "Affected files:".bold());
                for f in &ctx.affected_files {
                    println!("  {}", f);
                }
            }
            if !ctx.central_files.is_empty() {
                println!();
                println!("{} {}", "📊".cyan(), "Central files:".bold());
                for (f, score) in &ctx.central_files {
                    println!("  {} (score: {:.0})", f, score);
                }
            }
        }

        // Print enumerate context
        if let Some(ref ctx) = response.enumerate_context {
            println!();
            println!(
                "{} Found {} {}",
                "📋".cyan(),
                ctx.count.to_string().yellow(),
                ctx.entity_type
            );
            for item in ctx.items.iter().take(20) {
                println!("  {}", item);
            }
            if ctx.items.len() > 20 {
                println!("  ... and {} more", ctx.items.len() - 20);
            }
        }

        // Print workspace context
        if let Some(ref ws) = response.workspace_context {
            println!();
            println!("{} {}", "🏗️".cyan(), "Workspace Overview:".bold());
            println!("  Files:      {}", ws.file_count);
            println!("  Functions:  {}", ws.function_count);
            println!("  Languages:  {}", ws.languages.join(", "));
            if !ws.frameworks.is_empty() {
                println!("  Frameworks: {}", ws.frameworks.join(", "));
            }
        }

        // Print findings
        if !response.findings.is_empty() && !streamed {
            println!();
            println!("{} {}", "🔍".cyan(), "Relevant findings:".bold());
            for sf in &response.findings {
                println!(
                    "  [{}] {} ({}) - {}:{}",
                    sf.finding.severity,
                    sf.finding.title,
                    sf.finding.rule_id,
                    sf.finding.file_path,
                    sf.finding.line.unwrap_or(0)
                );
            }
        }

        // LLM hint
        if !llm_ready && !streamed {
            println!();
            println!(
                "  {} Configure an LLM with `unfault config llm set` for AI-powered responses.",
                "Tip:".dimmed()
            );
        }

        println!();
    }

    Ok(EXIT_SUCCESS)
}
