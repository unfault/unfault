# unfault

Static analysis tool that connects code findings to their system-level consequences.

When a missing timeout is found in `payments/client.py`, unfault traces it through
the call graph to the HTTP handler it belongs to, checks whether that handler is
covered by an SLO, and tells you the propagation risk, rather than just reporting
a rule violation.

---

## Install

Download the binary for your platform from
[github.com/unfault/unfault/releases](https://github.com/unfault/unfault/releases).

**macOS / Linux:**
```bash
# macOS arm64 (Apple Silicon)
curl -Lo unfault https://github.com/unfault/unfault/releases/latest/download/unfault-latest-macos-arm64
chmod +x unfault && mv unfault /usr/local/bin/

# macOS x86_64
curl -Lo unfault https://github.com/unfault/unfault/releases/latest/download/unfault-latest-macos-x86_64
chmod +x unfault && mv unfault /usr/local/bin/

# Linux x86_64
curl -Lo unfault https://github.com/unfault/unfault/releases/latest/download/unfault-latest-linux-x86_64
chmod +x unfault && mv unfault /usr/local/bin/

# Linux arm64
curl -Lo unfault https://github.com/unfault/unfault/releases/latest/download/unfault-latest-linux-arm64
chmod +x unfault && mv unfault /usr/local/bin/
```

**Windows:** download `unfault-latest-windows-x86_64.exe` from the releases page,
rename it to `unfault.exe`, and add it to your `PATH`.

**From source** (requires Rust):
```bash
cargo install unfault
```

---

## Usage

```bash
unfault review              # analyze the current directory
unfault lint                # all findings, grouped by severity and rule
unfault graph impact FILE   # what breaks if this file changes
unfault graph critical      # most imported files in the codebase
unfault info SLO-002        # explain a failure mode
```

---

## review

Runs static analysis and enriches findings with graph context. If observability
credentials are present, SLOs and distributed traces are pulled in to anchor
findings to actual business objectives.

```
  🟡  main.py:36  · The Retry Storm
     HTTP call via `httpx`.AsyncClient has no retry policy
     ↳ puts  Checkout API (99.9%)  at risk  (100%)
     During an outage your service retries failures instantly, preventing
     the downstream service from ever recovering.
     Tradeoff
     ↳ Local Availability      retries mask transient failures from the caller
     ↳ Systemic Metastability  synchronized retries prevent downstream recovery

 app-a   python · fastapi · 1 file   [ parse 4ms  engine 0ms  cached ]
```

**Flags:**

```
--offline         skip SLO and trace fetching (useful in CI, pre-commit)
--refresh-cache   discard the enrichment cache and re-fetch from providers
--all             show all findings, not just the top hazards
--output json     machine-readable output
--fix             apply suggested patches
--dry-run         preview patches without applying
```

---

## Observability integrations

All optional. If credentials are absent the review runs on static analysis alone.

**GCP Cloud Monitoring + Cloud Trace:**
```bash
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=my-project
```
Fetches SLOs from Cloud Monitoring and cross-service call patterns from Cloud
Trace. The workspace directory name is matched against GCP service slugs to
avoid linking sibling services' SLOs to the wrong codebase.

**Datadog:**
```bash
export DD_API_KEY=...
export DD_APP_KEY=...
export DD_SITE=datadoghq.com   # optional, defaults to datadoghq.com
```

**Dynatrace:**
```bash
export DT_API_TOKEN=...         # requires slo.read scope
export DT_ENVIRONMENT_URL=https://<env-id>.live.dynatrace.com
```

**Check what's detected:**
```bash
unfault config integrations show    # credential detection, no network calls
unfault config integrations verify  # live API probe, confirms auth works
```

**Enrichment cache:** SLO and trace data is cached at `.unfault/cache/enrichment/`
with a 5-minute TTL. The review footer shows `cached` or `fetch Xms` accordingly.

---

## Failure modes

| ID | Name | What it flags |
|----|------|---------------|
| SLO-001 | The Slow Death | missing timeout on outbound call |
| SLO-002 | The Retry Storm | retry without backoff or jitter |
| SLO-003 | The Zombie Process | blocking call in async context |
| SLO-004 | The Thundering Herd | cache miss without singleflight |
| SLO-005 | The Blackhole | hardcoded IP or expired credential |
| SLO-006 | The Cascade | missing circuit breaker |

Run `unfault info <ID>` for the full explanation and tradeoff analysis.

---

## CI / pre-commit

```bash
unfault review --offline
```

Exits non-zero when hazards are found. No network calls, no credential
requirements. Suitable for pre-commit hooks and air-gapped environments.

---

## LLM configuration (for `unfault ask`)

```bash
unfault config llm anthropic --model claude-sonnet-4-20250514
unfault config llm openai --model gpt-4o
unfault config llm ollama --endpoint http://localhost:11434 --model llama3.2
```

---

## IDE

```bash
unfault lsp   # LSP server: diagnostics, code actions, file centrality
```

Agent skill files for Claude Code and OpenCode:
```bash
unfault config agent claude
unfault config agent opencode
```

---

## Workspace

```
core/      unfault-core     0.3.0   parsing, semantics, code graph
analysis/  unfault-analysis 0.2.0   rules, profiles, world model
cli/       unfault          0.8.0   commands, LSP, integrations
```

```bash
cargo build --workspace
cargo test --workspace
```

---

## License

MIT
