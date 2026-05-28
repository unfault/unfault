//! # Unfault CLI
//!
//! Unfault — a calm reviewer for thoughtful engineers
//!
//! Unfault analyzes your code for clarity, boundaries, and behavior,
//! highlighting places where decisions matter — before reality does.
//!
//! You write the code. Unfault helps you build it right.
//!
//! ## Usage
//!
//! ```bash
//! # Authenticate
//! unfault login
//!
//! # Analyze code
//! unfault review
//!
//! ```

use clap::{Parser, Subcommand, ValueEnum};
use unfault::commands;

/// Initialize logger based on verbose flag
fn init_logger(verbose: bool) {
    let mut log_builder = env_logger::Builder::from_default_env();
    if verbose {
        log_builder.filter_level(log::LevelFilter::Debug);
    } else {
        log_builder.filter_level(log::LevelFilter::Info);
    }
    log_builder.init();
}

/// Output format options for commands
#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    /// Basic output showing only header and summary line (default)
    Basic,
    /// Concise output with just summary statistics
    Concise,
    /// Full output with detailed analysis and findings
    Full,
    /// JSON output format
    Json,
    /// SARIF output format for GitHub Code Scanning / IDE integration
    Sarif,
}

/// Main CLI structure
#[derive(Parser)]
#[command(name = "unfault")]
#[command(about = "Unfault — a calm reviewer for thoughtful engineers", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
/// Available CLI commands
#[derive(Subcommand)]
enum Commands {
    /// Manage CLI configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Query the code graph for impact analysis, dependencies, and critical files
    Graph {
        #[command(subcommand)]
        command: GraphCommands,
    },
    /// Generate fault injection scenario commands for endpoints reachable from a function
    Fault {
        /// Function to target in format file:function or just function_name
        #[arg(value_name = "FUNCTION")]
        function: String,
        /// Fault scenario template (omit to list all 12 templates)
        #[arg(long, short = 't', value_name = "TEMPLATE")]
        template: Option<String>,
        /// Injection mode: ingress (inbound to your app) or egress (outbound to dependencies)
        #[arg(long, short = 'm', value_name = "MODE", default_value = "ingress")]
        mode: String,
        /// Target URL.
        /// Ingress: local app base URL (default: http://127.0.0.1:8000).
        /// Egress: remote dependency base URL (required).
        #[arg(long, short = 'u', value_name = "URL")]
        url: Option<String>,
        /// Local proxy port for the fault proxy (default: 9090)
        #[arg(long, short = 'p', value_name = "PORT", default_value = "9090")]
        port: u16,
        /// Injection duration (default: 2m)
        #[arg(long, short = 'd', value_name = "DURATION", default_value = "2m")]
        duration: String,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Start the LSP server for IDE integration
    Lsp {
        /// Enable verbose logging to stderr
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Use stdio transport (default, added for compatibility with language clients)
        #[arg(long, hide = true)]
        stdio: bool,
    },
    /// Analyze code and get recommendations
    Review {
        /// Output format (basic: header + summary, concise: brief findings, full: detailed analysis)
        #[arg(long, value_name = "OUTPUT", default_value = "basic")]
        output: OutputFormat,
        /// Enable verbose output (dumps raw API responses)
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Override the detected profile (e.g., python_fastapi_backend)
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
        /// Dimensions to analyze (can be specified multiple times)
        /// Available: stability, correctness, performance, scalability
        /// Default: all dimensions from the profile
        #[arg(long, short = 'd', value_name = "DIMENSION")]
        dimension: Vec<String>,
        /// Auto-apply all suggested fixes
        #[arg(long)]
        fix: bool,
        /// Show what fixes would be applied without actually applying them
        #[arg(long)]
        dry_run: bool,
        /// Show all findings in full (same as unfault lint)
        #[arg(long)]
        all: bool,
        /// Discard the enrichment cache and re-fetch SLOs and traces from providers
        #[arg(long)]
        refresh_cache: bool,
        /// Skip SLO and trace fetching entirely — useful in CI or pre-commit hooks
        #[arg(long)]
        offline: bool,
        /// Analyze only files changed in a specific git commit (SHA, branch, tag, or HEAD~N).
        /// Useful for incremental cache warming: only changed files are parsed, the rest
        /// are served from cache. Can be combined with --files.
        #[arg(long, value_name = "REF")]
        commit: Option<String>,
        /// Analyze only these specific files (can be repeated or space-separated).
        /// Can be combined with --commit; duplicates are deduplicated automatically.
        #[arg(long, value_name = "FILE", num_args = 1..)]
        files: Vec<std::path::PathBuf>,
    },
    /// Show all findings grouped by severity and rule — the detailed linter view
    Lint {
        /// Output format (text or json)
        #[arg(long, value_name = "OUTPUT", default_value = "basic")]
        output: OutputFormat,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Override the detected profile
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
        /// Dimensions to analyze
        #[arg(long, short = 'd', value_name = "DIMENSION")]
        dimension: Vec<String>,
        /// Auto-apply all suggested fixes
        #[arg(long)]
        fix: bool,
        /// Show what fixes would be applied without actually applying them
        #[arg(long)]
        dry_run: bool,
        /// Analyze only files changed in a specific git commit (SHA, branch, tag, or HEAD~N).
        /// Useful for incremental cache warming: only changed files are parsed, the rest
        /// are served from cache. Can be combined with --files.
        #[arg(long, value_name = "REF")]
        commit: Option<String>,
        /// Analyze only these specific files (can be repeated or space-separated).
        /// Can be combined with --commit; duplicates are deduplicated automatically.
        #[arg(long, value_name = "FILE", num_args = 1..)]
        files: Vec<std::path::PathBuf>,
    },
    /// Show SRE glossary entry for a failure mode (e.g. SLO-001)
    Info {
        /// Glossary ID to look up (e.g. SLO-001, SLO-002)
        #[arg(value_name = "ID")]
        id: String,
    },
}

/// Graph subcommands
#[derive(Subcommand)]
enum GraphCommands {
    /// Analyze impact: "What breaks if I change this file?"
    Impact {
        /// File path to analyze
        #[arg(value_name = "FILE")]
        file_path: String,
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Maximum depth for transitive analysis (1-10)
        #[arg(long, value_name = "DEPTH", default_value = "5")]
        max_depth: i32,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Analyze function impact: "What breaks if I change this function?"
    FunctionImpact {
        /// Function in format file:function
        #[arg(value_name = "FUNCTION")]
        function: String,
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Maximum depth for transitive analysis (1-10)
        #[arg(long, value_name = "DEPTH", default_value = "5")]
        max_depth: i32,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Find files that use a specific library
    Library {
        /// Library name to search for (e.g., "requests", "fastapi")
        #[arg(value_name = "LIBRARY")]
        library_name: String,
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Find external dependencies of a file
    Deps {
        /// File path to analyze
        #[arg(value_name = "FILE")]
        file_path: String,
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Find the most critical/hub files in the codebase
    Critical {
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Maximum number of files to return (1-50)
        #[arg(long, short = 'n', value_name = "COUNT", default_value = "10")]
        limit: i32,
        /// Metric to sort by
        #[arg(long, value_name = "METRIC", default_value = "in_degree")]
        sort_by: SortMetric,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Get code graph statistics
    Stats {
        /// Analysis session ID (advanced: overrides workspace auto-detection)
        #[arg(long, short = 's', value_name = "SESSION_ID")]
        session: Option<String>,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Build and dump the local code graph (for debugging)
    Dump {
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Output only call edges (useful for debugging call graph issues)
        #[arg(long)]
        calls_only: bool,
        /// Output only specific file's information
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Trace who calls a function — "you are here" inbound call chain up to HTTP routes
    Callers {
        /// Function to trace in format file:function or just function_name
        #[arg(value_name = "FUNCTION")]
        function: String,
        /// Workspace path to analyze (defaults to current directory)
        #[arg(long, short = 'w', value_name = "PATH")]
        workspace: Option<String>,
        /// Maximum depth for reverse call chain traversal (1-10)
        #[arg(long, value_name = "DEPTH", default_value = "5")]
        max_depth: i32,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
}

/// Centrality sort metric options
#[derive(Clone, Debug, ValueEnum)]
pub enum SortMetric {
    /// Sort by number of files that import this file (most critical dependencies)
    InDegree,
    /// Sort by number of files this file imports
    OutDegree,
    /// Sort by total connectivity (in + out)
    TotalDegree,
    /// Sort by number of external libraries used
    LibraryUsage,
    /// Sort by weighted importance score
    ImportanceScore,
}

impl SortMetric {
    fn as_str(&self) -> &'static str {
        match self {
            SortMetric::InDegree => "in_degree",
            SortMetric::OutDegree => "out_degree",
            SortMetric::TotalDegree => "total_degree",
            SortMetric::LibraryUsage => "library_usage",
            SortMetric::ImportanceScore => "importance_score",
        }
    }
}

/// Config subcommands
#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show {
        /// Show full secrets instead of masked values
        #[arg(long)]
        show_secrets: bool,
    },
    /// Manage LLM configuration for AI-powered insights
    Llm {
        #[command(subcommand)]
        command: LlmCommands,
    },
    /// Inspect and verify observability integrations (SLOs, traces)
    Integrations {
        #[command(subcommand)]
        command: IntegrationsCommands,
    },
    /// Generate agent skill files for Claude Code or OpenCode
    Agent {
        /// Agent tool to configure skills for
        #[command(subcommand)]
        tool: AgentTool,
    },
}

/// Integrations subcommands
#[derive(Subcommand)]
enum IntegrationsCommands {
    /// Show detected integrations and their credential status (no network calls)
    Show,
    /// Verify integrations by making live API calls to confirm auth works
    Verify,
}

/// Agent tool targets for skill generation
#[derive(Subcommand, Clone, Debug)]
pub enum AgentTool {
    /// Generate skills for Claude Code (.claude/skills/)
    Claude {
        /// Write to ~/.claude/skills/ instead of .claude/skills/ in the project
        #[arg(long)]
        global: bool,
        /// Print what would be created without writing files
        #[arg(long)]
        dry_run: bool,
    },
    /// Generate skills for OpenCode (.opencode/skills/)
    Opencode {
        /// Write to ~/.config/opencode/skills/ instead of .opencode/skills/ in the project
        #[arg(long)]
        global: bool,
        /// Print what would be created without writing files
        #[arg(long)]
        dry_run: bool,
    },
}

/// LLM subcommands
#[derive(Subcommand)]
enum LlmCommands {
    /// Configure OpenAI as LLM provider
    Openai {
        /// Model name (e.g., gpt-4, gpt-4o, gpt-3.5-turbo)
        #[arg(long, short = 'm', default_value = "gpt-4")]
        model: String,
        /// API key (optional, prefers OPENAI_API_KEY env var)
        #[arg(long, short = 'k')]
        api_key: Option<String>,
    },
    /// Configure Anthropic as LLM provider
    Anthropic {
        /// Model name (e.g., claude-3-5-sonnet-latest, claude-3-opus)
        #[arg(long, short = 'm', default_value = "claude-3-5-sonnet-latest")]
        model: String,
        /// API key (optional, prefers ANTHROPIC_API_KEY env var)
        #[arg(long, short = 'k')]
        api_key: Option<String>,
    },
    /// Configure local Ollama as LLM provider
    Ollama {
        /// Ollama API endpoint
        #[arg(long, short = 'e', default_value = "http://localhost:11434")]
        endpoint: String,
        /// Model name (e.g., llama3.2, mistral, codellama)
        #[arg(long, short = 'm', default_value = "llama3.2")]
        model: String,
    },
    /// Configure custom OpenAI-compatible endpoint
    Custom {
        /// API endpoint URL
        #[arg(long, short = 'e')]
        endpoint: String,
        /// Model name
        #[arg(long, short = 'm')]
        model: String,
        /// API key (optional)
        #[arg(long, short = 'k')]
        api_key: Option<String>,
    },
    /// Show current LLM configuration
    Show {
        /// Show full secrets instead of masked values
        #[arg(long)]
        show_secrets: bool,
    },
    /// Remove LLM configuration
    Remove,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let exit_code = run_command(cli.command).await;
    std::process::exit(exit_code);
}

async fn run_command(command: Commands) -> i32 {
    use unfault::exit_codes::*;

    match command {
        Commands::Config { command } => run_config_command(command).await,
        Commands::Graph { command } => run_graph_command(command).await,
        Commands::Fault {
            function,
            template,
            mode,
            url,
            port,
            duration,
            workspace,
            verbose,
        } => {
            let args = commands::fault::FaultArgs {
                function,
                template,
                mode,
                url,
                port,
                duration,
                workspace_path: workspace,
                verbose,
            };
            match commands::fault::execute(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Fault error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        Commands::Info { id } => commands::info::execute(&id),
        Commands::Lint {
            output,
            verbose,
            profile,
            dimension,
            fix,
            dry_run,
            commit,
            files,
        } => {
            init_logger(verbose);
            let output_format = match output {
                OutputFormat::Json => "json".to_string(),
                _ => "text".to_string(),
            };
            let args = commands::lint::LintArgs {
                output_format,
                verbose,
                profile,
                dimensions: if dimension.is_empty() {
                    None
                } else {
                    Some(dimension)
                },
                fix,
                dry_run,
                commit,
                files,
            };
            match commands::lint::execute(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Lint error: {}", e);
                    EXIT_CONFIG_ERROR
                }
            }
        }
        Commands::Lsp { verbose, stdio: _ } => {
            init_logger(verbose);
            // stdio flag is just for compatibility with language clients, we always use stdio
            let args = commands::lsp::LspArgs { verbose };
            match commands::lsp::execute(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("LSP error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        Commands::Review {
            output,
            verbose,
            profile,
            dimension,
            fix,
            dry_run,
            all,
            refresh_cache,
            offline,
            commit,
            files,
        } => {
            init_logger(verbose);
            // Convert OutputFormat to string for backward compatibility
            let output_format = match output {
                OutputFormat::Json => "json".to_string(),
                OutputFormat::Sarif => "sarif".to_string(),
                OutputFormat::Basic => "text".to_string(),
                OutputFormat::Concise => "text".to_string(),
                OutputFormat::Full => "text".to_string(),
            };

            // Determine output mode
            let output_mode = match output {
                OutputFormat::Basic => "basic".to_string(),
                OutputFormat::Concise => "concise".to_string(),
                OutputFormat::Full => "full".to_string(),
                OutputFormat::Json => "full".to_string(), // JSON is always full
                OutputFormat::Sarif => "full".to_string(), // SARIF is always full
            };

            let args = commands::review::ReviewArgs {
                output_format,
                output_mode,
                verbose,
                profile,
                dimensions: if dimension.is_empty() {
                    None
                } else {
                    Some(dimension)
                },
                fix,
                dry_run,
                all,
                refresh_cache,
                offline,
                commit,
                files,
            };
            match commands::review::execute(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Review error: {}", e);
                    EXIT_CONFIG_ERROR
                }
            }
        }
    }
}

async fn run_config_command(command: ConfigCommands) -> i32 {
    use unfault::exit_codes::*;

    match command {
        ConfigCommands::Show { show_secrets } => {
            let args = commands::config::ConfigShowArgs { show_secrets };
            match commands::config::execute_show(args) {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Config error: {}", e);
                    EXIT_CONFIG_ERROR
                }
            }
        }
        ConfigCommands::Llm { command } => run_llm_command(command),
        ConfigCommands::Integrations { command } => run_integrations_command(command).await,
        ConfigCommands::Agent { tool } => {
            let (agent_tool, global, dry_run) = match tool {
                AgentTool::Claude { global, dry_run } => {
                    (commands::agent_skills::AgentTool::Claude, global, dry_run)
                }
                AgentTool::Opencode { global, dry_run } => {
                    (commands::agent_skills::AgentTool::Opencode, global, dry_run)
                }
            };
            let args = commands::agent_skills::AgentSkillsArgs {
                tool: agent_tool,
                global,
                dry_run,
            };
            match commands::agent_skills::execute(args) {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Agent skills error: {}", e);
                    EXIT_ERROR
                }
            }
        }
    }
}

fn run_llm_command(command: LlmCommands) -> i32 {
    use commands::config::{ConfigLlmArgs, LlmProvider};
    use unfault::exit_codes::*;

    let args = match command {
        LlmCommands::Openai { model, api_key } => {
            ConfigLlmArgs::Set(LlmProvider::OpenAI { model, api_key })
        }
        LlmCommands::Anthropic { model, api_key } => {
            ConfigLlmArgs::Set(LlmProvider::Anthropic { model, api_key })
        }
        LlmCommands::Ollama { endpoint, model } => {
            ConfigLlmArgs::Set(LlmProvider::Ollama { endpoint, model })
        }
        LlmCommands::Custom {
            endpoint,
            model,
            api_key,
        } => ConfigLlmArgs::Set(LlmProvider::Custom {
            endpoint,
            model,
            api_key,
        }),
        LlmCommands::Show { show_secrets } => ConfigLlmArgs::Show { show_secrets },
        LlmCommands::Remove => ConfigLlmArgs::Remove,
    };

    match commands::config::execute_llm(args) {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("Config LLM error: {}", e);
            EXIT_CONFIG_ERROR
        }
    }
}

async fn run_integrations_command(command: IntegrationsCommands) -> i32 {
    use unfault::exit_codes::*;

    match command {
        IntegrationsCommands::Show => match commands::integrations::execute_show() {
            Ok(exit_code) => exit_code,
            Err(e) => {
                eprintln!("Integrations error: {}", e);
                EXIT_ERROR
            }
        },
        IntegrationsCommands::Verify => match commands::integrations::execute_verify().await {
            Ok(exit_code) => exit_code,
            Err(e) => {
                eprintln!("Integrations verify error: {}", e);
                EXIT_ERROR
            }
        },
    }
}

async fn run_graph_command(command: GraphCommands) -> i32 {
    use unfault::exit_codes::*;

    match command {
        GraphCommands::Impact {
            file_path,
            session,
            workspace,
            max_depth,
            json,
            verbose,
        } => {
            let args = commands::graph::ImpactArgs {
                session_id: session,
                workspace_path: workspace,
                file_path,
                max_depth,
                json,
                verbose,
            };
            match commands::graph::execute_impact(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph impact error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::FunctionImpact {
            function,
            session,
            workspace,
            max_depth,
            json,
            verbose,
        } => {
            let args = commands::graph::FunctionImpactArgs {
                session_id: session,
                workspace_path: workspace,
                function,
                max_depth,
                json,
                verbose,
            };
            match commands::graph::execute_function_impact(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph function impact error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Library {
            library_name,
            session,
            workspace,
            json,
            verbose,
        } => {
            let args = commands::graph::LibraryArgs {
                session_id: session,
                workspace_path: workspace,
                library_name,
                json,
                verbose,
            };
            match commands::graph::execute_library(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph library error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Deps {
            file_path,
            session,
            workspace,
            json,
            verbose,
        } => {
            let args = commands::graph::DepsArgs {
                session_id: session,
                workspace_path: workspace,
                file_path,
                json,
                verbose,
            };
            match commands::graph::execute_deps(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph deps error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Critical {
            session,
            workspace,
            limit,
            sort_by,
            json,
            verbose,
        } => {
            let args = commands::graph::CriticalArgs {
                session_id: session,
                workspace_path: workspace,
                limit,
                sort_by: sort_by.as_str().to_string(),
                json,
                verbose,
            };
            match commands::graph::execute_critical(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph critical error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Stats {
            session,
            workspace,
            json,
            verbose,
        } => {
            let args = commands::graph::StatsArgs {
                session_id: session,
                workspace_path: workspace,
                json,
                verbose,
            };
            match commands::graph::execute_stats(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph stats error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Dump {
            workspace,
            calls_only,
            file,
            verbose,
        } => {
            let args = commands::graph::DumpArgs {
                workspace_path: workspace,
                calls_only,
                file,
                verbose,
            };
            match commands::graph::execute_dump(args) {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph dump error: {}", e);
                    EXIT_ERROR
                }
            }
        }
        GraphCommands::Callers {
            function,
            workspace,
            max_depth,
            json,
            verbose,
        } => {
            let args = commands::graph::CallersArgs {
                workspace_path: workspace,
                function,
                max_depth,
                json,
                verbose,
            };
            match commands::graph::execute_callers(args).await {
                Ok(exit_code) => exit_code,
                Err(e) => {
                    eprintln!("Graph callers error: {}", e);
                    EXIT_ERROR
                }
            }
        }
    }
}
