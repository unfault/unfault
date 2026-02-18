# unfault

A cognitive context engine for thoughtful engineers. Helps you understand what
your code means and does, while you're writing it.

**Fully standalone.** No API server, no authentication, no billing. All analysis
runs locally.

## Features

- **196 built-in rules** across Python, Go, Rust, and TypeScript
- **Impact analysis** — "what breaks if I change this file?"
- **Centrality analysis** — find your most critical files
- **RAG-powered queries** — ask questions about your codebase
- **LSP server** — real-time diagnostics in your editor
- **Auto-fix** — apply suggested patches automatically

## Quick Start

```bash
# Install
cargo install unfault

# Analyze your project
cd /path/to/your/project
unfault review

# Ask questions about your code
unfault ask "what are the main stability concerns?"

# Impact analysis
unfault graph impact src/auth.py

# Find critical files
unfault graph critical

# Start the LSP server (for IDE integration)
unfault lsp
```

## Configuration

Configuration is stored at `~/.config/unfault/config.json`.

### LLM (for AI-powered `ask` responses)

```bash
# Use Ollama (local, no API key needed)
unfault config llm ollama --endpoint http://localhost:11434 --model llama3.2

# Use OpenAI
unfault config llm openai --model gpt-4o

# Use Anthropic
unfault config llm anthropic --model claude-sonnet-4-20250514
```

### Embeddings (for semantic search in `ask`)

Configure via `~/.config/unfault/config.json`:

```json
{
  "embeddings": {
    "provider": "ollama",
    "endpoint": "http://localhost:11434",
    "model": "nomic-embed-text",
    "dimensions": 768
  }
}
```

## Workspace Structure

This is a Cargo workspace containing 4 publishable crates:

| Crate | Package | Description |
|-------|---------|-------------|
| `core` | `unfault-core` | Parsing, semantics, graph construction |
| `analysis` | `unfault-analysis` | 196 rules, profiles, rule evaluation engine |
| `rag` | `unfault-rag` | LanceDB vector store, embeddings, query routing |
| `cli` | `unfault` | CLI commands, LSP server |

### Dependency Chain

```
core ← analysis ← rag ← cli
```

## Building

```bash
cargo build --workspace
```

## Testing

```bash
cargo test --workspace
```

## Publishing

Crates must be published in dependency order:

```bash
cargo publish -p unfault-core
cargo publish -p unfault-analysis
cargo publish -p unfault-rag
cargo publish -p unfault
```

## License

MIT
