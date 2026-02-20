// unfault-ignore: rust.println_in_lib
//! # Agent Skills Command
//!
//! Generates SKILL.md files for Claude Code or OpenCode so that AI agents can
//! use unfault commands natively within their tool.
//!
//! ## Usage
//!
//! ```bash
//! # Write skills to .claude/skills/ in the current project
//! unfault config agent claude
//!
//! # Write skills to .opencode/skills/ in the current project
//! unfault config agent opencode
//!
//! # Write to global ~/.claude/skills/
//! unfault config agent claude --global
//!
//! # Preview without writing
//! unfault config agent opencode --dry-run
//! ```

use anyhow::Result;
use colored::Colorize;
use std::path::PathBuf;

use crate::exit_codes::*;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Which agent tool to generate skills for.
#[derive(Clone, Debug)]
pub enum AgentTool {
    /// Claude Code — skills go in `.claude/skills/` or `~/.claude/skills/`
    Claude,
    /// OpenCode — skills go in `.opencode/skills/` or `~/.config/opencode/skills/`
    Opencode,
}

/// Arguments for the `unfault config agent` command.
#[derive(Debug)]
pub struct AgentSkillsArgs {
    pub tool: AgentTool,
    pub global: bool,
    pub dry_run: bool,
}

// ---------------------------------------------------------------------------
// Skill definitions
// ---------------------------------------------------------------------------

struct SkillDef {
    name: &'static str,
    description: &'static str,
    /// When true, only the user can invoke this skill (not the agent automatically).
    disable_model_invocation: bool,
    content: &'static str,
}

fn skill_defs() -> Vec<SkillDef> {
    vec![
        SkillDef {
            name: "unfault-review",
            description: "Run unfault review to analyze this codebase for production-readiness \
                issues: missing error handling, scalability bottlenecks, correctness bugs, and \
                stability risks. Use when asked to review code, check for issues, or prepare a \
                PR review. NOTE: this command calls an external LLM and may take 30-60 seconds.",
            disable_model_invocation: true,
            content: SKILL_REVIEW,
        },
        SkillDef {
            name: "unfault-graph-impact",
            description: "Analyze the blast radius of a code change using the local code graph. \
                Use when assessing what breaks if a file or function is changed, refactored, \
                renamed, or deleted. Fast — runs locally with no LLM.",
            disable_model_invocation: false,
            content: SKILL_GRAPH_IMPACT,
        },
        SkillDef {
            name: "unfault-graph-explore",
            description: "Explore the code graph: find which files use a library, list \
                dependencies of a file, identify the most critical hub files, or get graph \
                statistics. Use when understanding codebase structure or dependency topology. \
                Fast — runs locally with no LLM.",
            disable_model_invocation: false,
            content: SKILL_GRAPH_EXPLORE,
        },
        SkillDef {
            name: "unfault-config",
            description: "Show or change unfault's configuration, including the LLM provider \
                used for AI-powered insights (unfault review). Use when asked about unfault \
                setup, to switch models, or to check API key status.",
            disable_model_invocation: true,
            content: SKILL_CONFIG,
        },
    ]
}

// ---------------------------------------------------------------------------
// Skill content
// ---------------------------------------------------------------------------

static SKILL_REVIEW: &str = r#"
## unfault review — production-readiness analysis

Run a full static analysis of the current workspace for production-readiness issues.

### Command

```bash
unfault review
```

### Common flags

| Flag | Description |
|------|-------------|
| `--output basic` | Header + summary only (default) |
| `--output concise` | Brief findings list |
| `--output full` | Detailed analysis with explanations |
| `--output json` | Machine-readable JSON |
| `--output sarif` | SARIF for GitHub Code Scanning |
| `--dimension <DIM>` | Limit to: `stability`, `correctness`, `performance`, `scalability` |
| `--profile <PROFILE>` | Override auto-detected profile (e.g. `python_fastapi_backend`) |
| `--fix` | Auto-apply all suggested fixes |
| `--dry-run` | Preview fixes without applying them |

### Supported profiles

`python_fastapi_backend`, `python_django_backend`, `python_flask_backend`,
`python_generic_backend`, `go_gin_service`, `go_generic_service`,
`rust_axum_service`, `rust_actix_service`, `typescript_express_backend`,
`typescript_nextjs_app`

### Examples

```bash
# Full analysis with detailed output
unfault review --output full

# Check only correctness issues
unfault review --dimension correctness --output full

# Get JSON findings for programmatic processing
unfault review --output json

# Preview auto-fixes
unfault review --dry-run

# Apply all fixes
unfault review --fix
```

### Interpreting output

Findings include a **severity** (error / warning / info) and a **dimension**:

- **correctness** — logic bugs, improper error handling, unsafe assumptions
- **stability** — missing retries, poor fault-tolerance, crash-prone patterns
- **performance** — N+1 queries, blocking calls, inefficient algorithms
- **scalability** — shared mutable state, unbounded growth, missing pagination

**How to act on findings:**

1. Prioritize `error`-level findings first — these indicate likely bugs in production.
2. Group `warning`-level findings by dimension and address the most impactful ones.
3. Use `--fix` for mechanical fixes (missing null checks, unused imports, etc.).
4. For architectural findings, discuss trade-offs with the developer before applying changes.
5. Cross-reference high-severity findings with the files identified as critical by
   `unfault graph critical` — issues in hub files have the highest blast radius.
"#;

static SKILL_GRAPH_IMPACT: &str = r#"
## unfault graph impact — blast radius analysis

Determine what else in the codebase would be affected if a specific file or function changes.
Runs locally using a pre-built code graph — no LLM, no network, results in milliseconds.

### Commands

```bash
# File-level impact
unfault graph impact <FILE>

# Function-level impact (format: file:function_name)
unfault graph function-impact <FILE:FUNCTION>
```

### Common flags

| Flag | Description |
|------|-------------|
| `--max-depth <N>` | Transitive analysis depth, 1–10 (default: 5) |
| `--json` | Machine-readable JSON output |
| `--workspace <PATH>` | Override workspace root |

### Examples

```bash
# What breaks if I change this file?
unfault graph impact src/auth/middleware.rs

# What breaks if I change a specific function?
unfault graph function-impact src/db/queries.py:get_user_by_id

# Deep transitive analysis
unfault graph impact src/core/config.go --max-depth 10

# JSON output for programmatic processing
unfault graph impact src/api/router.ts --json
```

### Interpreting output

The output lists files and functions that **transitively depend** on the changed file/function,
grouped by depth (direct dependents at depth 1, transitive at depth 2+).

**How to act on impact analysis:**

- **High fan-out (many dependents):** The change is risky. Consider backward-compatible refactors,
  feature flags, or staged rollouts.
- **Deep transitive chains:** A change here can cause failures far from the source.
  Run `unfault review` on the most critical dependents before merging.
- **Zero dependents:** Safe to change freely — nothing else calls this code.
- **Cross-module dependents:** Impact crosses architectural boundaries. Treat as a breaking change
  and notify owners of those modules.
"#;

static SKILL_GRAPH_EXPLORE: &str = r#"
## unfault graph explore — code graph queries

Query the codebase's dependency graph to understand structure, find library usage,
list file dependencies, or identify the most critical hub files.
All commands run locally — no LLM, no network.

### Commands

```bash
# Find all files that use a specific library
unfault graph library <LIBRARY_NAME>

# List all external dependencies of a file
unfault graph deps <FILE>

# Find the most critical (most-imported) hub files
unfault graph critical

# Show overall graph statistics
unfault graph stats
```

### Common flags

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable JSON output |
| `--workspace <PATH>` | Override workspace root |

### Flags for `graph critical`

| Flag | Description |
|------|-------------|
| `-n <COUNT>` | Number of files to return (default: 10, max: 50) |
| `--sort-by <METRIC>` | `in_degree` (default), `out_degree`, `total_degree`, `library_usage`, `importance_score` |

### Examples

```bash
# Which files use the "requests" library?
unfault graph library requests

# What does this file depend on?
unfault graph deps src/api/handlers.py

# Top 20 most-imported files (highest change risk)
unfault graph critical -n 20

# Sort by overall connectivity
unfault graph critical --sort-by importance_score

# Graph health overview
unfault graph stats
```

### Interpreting output

**`graph library`** — shows all files importing the given library. Useful before upgrading
a dependency to understand blast radius.

**`graph deps`** — lists external packages and internal files that a given file depends on.
Use before moving or deleting a file.

**`graph critical`** — ranks files by centrality. Files with high `in_degree` are imported
by many others; changing them carries high risk. These are your architectural load-bearing walls.
Cross-reference with `unfault review` findings on these files for maximum impact.

**`graph stats`** — summary of nodes, edges, and graph density. A high density may indicate
tight coupling; very low density may indicate isolated modules not sharing utilities.
"#;

static SKILL_CONFIG: &str = r#"
## unfault config — manage configuration

Show the current unfault configuration or set up the LLM provider used by
`unfault review` for AI-powered insights.

### Commands

```bash
# Show all current configuration
unfault config show

# Show with unmasked API keys
unfault config show --show-secrets

# Configure OpenAI
unfault config llm openai --model gpt-4 --api-key <KEY>

# Configure Anthropic (Claude)
unfault config llm anthropic --model claude-3-5-sonnet-latest --api-key <KEY>

# Configure local Ollama
unfault config llm ollama --endpoint http://localhost:11434 --model llama3.2

# Configure a custom OpenAI-compatible endpoint
unfault config llm custom --endpoint https://api.example.com/v1 --model my-model --api-key <KEY>

# Show LLM configuration only
unfault config llm show

# Remove LLM configuration
unfault config llm remove
```

### LLM providers

| Provider | Default model | API key env var |
|----------|--------------|-----------------|
| `openai` | `gpt-4` | `OPENAI_API_KEY` |
| `anthropic` | `claude-3-5-sonnet-latest` | `ANTHROPIC_API_KEY` |
| `ollama` | `llama3.2` | *(none required)* |
| `custom` | *(required)* | *(optional)* |

### Notes

- API keys can be passed via `--api-key` or set as environment variables (preferred).
- The LLM is only used by `unfault review`. Graph commands (`graph impact`, `graph critical`,
  etc.) are fully local and do not require any LLM configuration.
- Configuration is stored at `~/.config/unfault/config.json`.
"#;

// ---------------------------------------------------------------------------
// Directory resolution
// ---------------------------------------------------------------------------

fn skills_base_dir(tool: &AgentTool, global: bool) -> Result<PathBuf> {
    if global {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
            .map_err(|_| anyhow::anyhow!("Cannot determine home directory"))?;
        Ok(match tool {
            AgentTool::Claude => home.join(".claude").join("skills"),
            AgentTool::Opencode => home.join(".config").join("opencode").join("skills"),
        })
    } else {
        let cwd = std::env::current_dir()?;
        Ok(match tool {
            AgentTool::Claude => cwd.join(".claude").join("skills"),
            AgentTool::Opencode => cwd.join(".opencode").join("skills"),
        })
    }
}

// ---------------------------------------------------------------------------
// SKILL.md rendering
// ---------------------------------------------------------------------------

fn render_skill_md(skill: &SkillDef) -> String {
    let mut frontmatter = format!(
        "---\nname: {}\ndescription: >-\n  {}\n",
        skill.name,
        // Wrap long description lines cleanly in YAML block scalar
        skill.description.replace('\n', "\n  "),
    );
    if skill.disable_model_invocation {
        frontmatter.push_str("disable-model-invocation: true\n");
    }
    frontmatter.push_str("---\n");
    format!("{}{}", frontmatter, skill.content)
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

/// Execute the `unfault config agent` command.
pub fn execute(args: AgentSkillsArgs) -> Result<i32> {
    let base_dir = skills_base_dir(&args.tool, args.global)?;

    let tool_label = match &args.tool {
        AgentTool::Claude => "Claude Code",
        AgentTool::Opencode => "OpenCode",
    };
    let scope_label = if args.global {
        "global"
    } else {
        "project-local"
    };

    println!();

    let skills = skill_defs();
    let mut written = 0usize;

    for skill in &skills {
        let skill_dir = base_dir.join(skill.name);
        let skill_file = skill_dir.join("SKILL.md");
        let content = render_skill_md(skill);

        if args.dry_run {
            println!(
                "  {} {}",
                "Would create".dimmed(),
                skill_file.display().to_string().cyan()
            );
        } else {
            std::fs::create_dir_all(&skill_dir)?;
            std::fs::write(&skill_file, &content)?;
            println!(
                "  {} {}",
                "Created".green(),
                skill_file.display().to_string().cyan()
            );
            written += 1;
        }
    }

    println!();

    if args.dry_run {
        println!(
            "{} {} skills would be written for {} ({}).",
            "dry-run:".yellow().bold(),
            skills.len(),
            tool_label,
            scope_label
        );
        println!("  Run without {} to write the files.", "--dry-run".bold());
    } else {
        println!(
            "{} {} skills written for {} ({}).",
            "✓".green().bold(),
            written,
            tool_label,
            scope_label
        );
        println!();

        let example_slash = format!("/{}", skills[0].name);
        match &args.tool {
            AgentTool::Claude => println!(
                "  {} Type {} or ask Claude to analyze impact of a change.",
                "→".cyan(),
                example_slash.bold()
            ),
            AgentTool::Opencode => println!(
                "  {} Type {} or ask OpenCode to analyze impact of a change.",
                "→".cyan(),
                example_slash.bold()
            ),
        }
    }

    println!();
    Ok(EXIT_SUCCESS)
}
