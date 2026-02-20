---
name: unfault-graph-impact
description: >-
  Analyze the blast radius of a code change using the local code graph. Use when assessing what breaks if a file or function is changed, refactored, renamed, or deleted. Fast — runs locally with no LLM.
---

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
