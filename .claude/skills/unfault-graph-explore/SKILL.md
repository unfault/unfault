---
name: unfault-graph-explore
description: >-
  Explore the code graph: find which files use a library, list dependencies of a file, identify the most critical hub files, or get graph statistics. Use when understanding codebase structure or dependency topology. Fast — runs locally with no LLM.
---

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
