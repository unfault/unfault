---
name: unfault-review
description: >-
  Run unfault review to analyze this codebase for production-readiness issues: missing error handling, scalability bottlenecks, correctness bugs, and stability risks. Use when asked to review code, check for issues, or prepare a PR review. NOTE: this command calls an external LLM and may take 30-60 seconds.
disable-model-invocation: true
---

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
