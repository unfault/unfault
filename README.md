# unfault

A cognitive context engine for thoughtful engineers.

## Workspace Structure

This is a Cargo workspace containing the following crates:

| Crate | Package | Description |
|-------|---------|-------------|
| `core` | `unfault-core` | Parsing, semantics extraction, and graph building |
| `analysis` | `unfault-analysis` | Rule evaluation and analysis engine |
| `rag` | `unfault-rag` | RAG (Retrieval-Augmented Generation) with LanceDB |
| `cli` | `unfault` | CLI and LSP server |

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
