# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.32] - 2026-06-27

### Added

- Auto-instrumentation detection: `unfault graph coverage` now detects global
  OTel/ddtrace/sentry instrumentation (FastAPIInstrumentor.instrument_app,
  ddtrace.patch_all, etc.) from the code graph and shows the handler's span
  signal as `◐ server span from fastapi auto-instrumentation` instead of
  incorrectly flagging it as uninstrumented.

## [1.0.31] - 2026-06-27

### Fixed

- `unfault graph coverage` now correctly classifies `db_session.get()`,
  `.commit()`, `.execute()`, etc. as Database calls. Previously a SKIP list
  silenced these as "noise" before any classification ran.
- Display names for boundary calls use the full expression (`db_session.get`)
  rather than just the last segment.

## [1.0.30] - 2026-06-27

### Fixed

- Coverage role classification now per-function (raw_calls patterns), not
  per-file. Fixes false db classification for response-builder functions.
- `unfault graph coverage <function>` now shows "Reached by N routes" by
  scanning route handlers' raw_calls for the anchor name.

### Changed

- Coverage header colours: method magenta bold, path bright yellow.

## [1.0.29] - 2026-06-27

### Fixed

- `unfault graph coverage` on a FastAPI / Flask / Express / Go / Rust route
  handler now shows the handler's actual callees instead of "No calls
  detected". Root cause: framework route handler nodes were created with
  `raw_calls: vec![]` instead of being populated from the language-specific
  call-site list.

## [1.0.28] - 2026-06-27

### Removed

- Old coverage renderer (legend, call tree, summary line, tree drawing
  helpers) fully deleted. `unfault graph coverage` now prints only the
  header and the category breakdown.

## [1.0.27] - 2026-06-27

### Changed

- Coverage breakdown by category with actionable hints.

### Fixed

- Coverage query cache busts on binary upgrade via CARGO_PKG_VERSION in key.

## [1.0.26] - 2026-06-27

### Fixed

- Bumped all three crates in lockstep for clean publish.

## [1.0.25] - 2026-06-27

### Fixed

- Coverage query cache now includes binary version in its key, so upgrading
  the binary automatically busts stale cached results.

## [1.0.24] - 2026-06-27

### Changed

- **Category-based coverage breakdown** — coverage is now grouped by
  `db queries`, `remote calls`, `http-client calls`, `auth / middleware`,
  and `business logic`. Each group shows a ratio, an optional inline name
  list (when ≤ 3), and a plain-English hint when coverage is 0% or partial.

## [1.0.23] - 2026-06-27

### Changed

- **Coverage blind-spot messaging** — for each call the handler makes, the
  output now explicitly says which calls are NOT covered ("if X fails or is
  slow, you will not see it in traces") and which ARE ("2 calls already
  covered: ● build_output  ● validate_run sdk:ddtrace").

## [1.0.22] - 2026-06-27

### Fixed

- Re-release of v1.0.21 with all three crates bumped in lockstep for a clean
  crates.io publish.

## [1.0.21] - 2026-06-27

### Fixed

- **`with tracer.start_span()` now detected as a span signal** — Python
  context-manager tracing calls inside function bodies are synthesised as
  `DecoratorSemantic::Tracing` at graph-build time, so `unfault graph coverage`
  shows `●` with the extracted span name instead of `○`.

- **Coverage callee tree was empty for most handlers** — `GraphNode::Function`
  now stores `raw_calls` (all call-site expressions extracted from the body).
  When no resolved `Calls` edges exist in the graph, the coverage command falls
  back to these raw names and synthesises stub callee nodes, so gaps in the
  call tree are always visible.

- **"✓ All functions carry span signal" fired incorrectly at 0%** — success
  message now only appears when every node in the tree carries a non-`None`
  span signal.

- **`ModuleCategory::Observability` added** — OTel, ddtrace, sentry-sdk,
  opentracing, jaeger, zipkin, and AWS X-Ray are now their own category,
  enabling the `◑ sdk:…` signal in `unfault graph coverage`.

## [1.0.20] - 2026-06-27

### Changed

- **`unfault graph coverage` redesigned** — now walks the full call tree
  bidirectionally from any route path or function name. Each node is
  annotated with its span signal (`●` decorator, `◑` SDK imported, `○` none)
  and its boundary role (`db`, `http-client`, `remote:<svc>`).

  Callers appear above the anchor (oldest ancestor at top), callees as a
  box-drawing tree below. The nudge section at the bottom lists every
  uninstrumented boundary (`db`/`http-client`/`remote`) — the exact functions
  where adding a span would make failures visible in production traces.

- **`ModuleCategory::Observability` added** — OTel, ddtrace, sentry-sdk,
  opentracing, jaeger, zipkin, AWS X-Ray are now in their own category,
  enabling the `◑` SDK-imported signal.

## [1.0.18] - 2026-06-27

### Added

- **`unfault graph coverage <route>`** — walk an HTTP route subtree and report
  OpenTelemetry trace and SLO/metrics coverage for every matched handler.

  Usage:
  ```
  unfault graph coverage /api
  unfault graph coverage "/api/**" --method POST
  unfault graph coverage /checkout --offline
  unfault graph coverage /api --refresh-cache --json
  ```

  Each route receives an independent trace status (`observed`, `instrumented_only`,
  `missing`, `unknown`) and metrics status (`covered`, `missing`, `unknown`),
  which roll up to an overall status of `full`, `partial`, `missing`, or `unknown`.

  Human output renders a path-prefix tree so coverage gaps are visible at a
  glance. `--json` emits a fully structured `CoverageContext` document suitable
  for CI diffing or dashboarding.

  Results are stored in the query cache (keyed on route + method + git commit
  SHA) so repeated calls in the same session are instant.

- **Route observations cached during `unfault review`** — the review enrichment
  pass now co-fetches inbound HTTP route observations from GCP Cloud Trace
  alongside the existing outbound call patterns. These are stored in the
  enrichment cache so that `unfault graph coverage` can serve results without
  an extra network round-trip after a `review` run.

### Fixed

- **45-second outer timeout on live observability fetches** — SLO and Cloud
  Trace fetches in `unfault graph coverage` are now guarded by a
  `tokio::time::timeout(45s)` deadline. A clear warning is printed if the
  deadline fires rather than hanging the command indefinitely.

- **`normalize_route_path` deduplicated** — the SLO matcher's implementation
  is now the single canonical source (`slo::matcher::normalize_route_path`),
  removing a prior duplication in the coverage command.

## [0.8.2] - 2026-05-28

### Added

- **Test file exclusion** — test files are now silently excluded from analysis at
  parse time, eliminating false positives caused by unfault tracing cross-file
  references back into test callers. Patterns covered per language:
  - **Python:** `test_*.py`, `*_test.py`, `*_tests.py`, `conftest.py`, any file
    under a `tests/` or `test/` directory.
  - **Go:** `*_test.go`, files under `testdata/` or `test/` directories.
  - **TypeScript / JavaScript:** `*.test.{ts,tsx,js}`, `*.spec.{ts,tsx,js}`,
    files under `__tests__/`, `test/`, or `tests/` directories.
  - **Rust:** `test_*.rs`, `*_test.rs`, files under a `tests/` directory
    (in-file `#[cfg(test)]` blocks continue to be suppressed by the analysis
    layer as before).

- **`--commit <REF>` flag** (`review` and `lint`) — analyze only the files
  touched by a specific git commit. Accepts any git revision: full SHA, short
  SHA, branch name, tag, or symbolic ref (`HEAD`, `HEAD~2`, …). Only added and
  modified files are included (deleted files are skipped). Ideal for incremental
  cache warming in CI: parse just what changed, serve everything else from cache.

- **`--files <FILE>...` flag** (`review` and `lint`) — restrict analysis to an
  explicit list of files. Accepts one or more paths, can be repeated, and
  composes with `--commit` (the two sets are unioned and deduplicated). Useful
  for editor integrations or shell pipelines:
  ```
  unfault review --files src/auth.py src/router.py
  git diff-tree --no-commit-id -r --name-only HEAD | xargs unfault review --files
  ```

## [0.8.1] - 2026-04-16

### Fixed

- Applied `cargo fmt --all` across the workspace. No functional changes.
- Release workflow: `publish` job now depends on `release` (which depends on
  `build`), so crates.io is never published before binaries are confirmed good.

## [0.8.0] - 2026-04-16

### Added

- **Hierarchical World Model** — `unfault review` now reasons at three tiers: code
  primitives (findings), sub-goals (call chains), and macro-goals (SLOs). Every hazard
  shows a propagation path with an aggregate risk score and the business objective at stake.

- **SLO integration** — GCP Cloud Monitoring, Datadog, and Dynatrace SLOs are fetched
  automatically when credentials are present and linked to HTTP route handlers in the code
  graph as `MonitoredBy` edges. Service-level SLOs are scoped to the local workspace by
  matching the GCP service slug against the directory name, preventing sibling services from
  appearing as false anchors.

- **GCP Cloud Trace integration** — `RPC_CLIENT` spans (and outbound HTTP spans where `kind`
  is absent, as on Cloud Run) are fetched from Cloud Trace v1 and injected as
  `GraphNode::RemoteService` + `GraphEdgeKind::RemoteCall` edges. The World Model propagates
  risk across service boundaries at weight 0.90 (higher than local calls, since there is no
  local recovery path). Service name extraction handles Kubernetes FQDNs, Cloud Run URLs, and
  gRPC `Sent.<Service>` span names.

- **Enrichment cache** — SLO and trace data is cached at `.unfault/cache/enrichment/` with a
  5-minute TTL. Warm runs show `cached` in the footer; the first cold run shows `fetch Xms`
  so users can distinguish tool latency from cloud API latency. Pass `--refresh-cache` to
  bust the cache on demand.

- **`--offline` flag** — skips SLO and trace fetching entirely (no network calls, no
  credential detection). Intended for CI pipelines and pre-commit hooks where cloud
  credentials are absent or startup time is critical.

- **`--refresh-cache` flag** — invalidates the enrichment cache and forces a live re-fetch
  from all configured providers.

- **Ranker** — `unfault graph critical --sort-by importance_score` now uses a composite
  importance score: centrality × 0.5 + library risk (outbound HTTP/DB usage) × 0.3 +
  finding density × 0.2. Scores and sub-components are shown in the output.

- **Tradeoff awareness** — every hazard block now shows a `Tradeoff` section with two named
  dimensions (e.g. `Simplicity` / `Systemic Availability`, `Local Availability` /
  `Systemic Metastability`). The category label is the left-column anchor; the body text
  is the explanatory sentence.

- **SLO-006: The Cascade** — new failure mode for missing circuit breakers, mapped to
  `*.missing_circuit_breaker` rule family.

- **`unfault config integrations show`** — detects credential availability for GCP, Datadog,
  and Dynatrace without making any network calls. Prints a status table with setup hints for
  missing providers.

- **`unfault config integrations verify`** — fires a lightweight API probe for each detected
  integration to confirm credentials work end-to-end. Exits non-zero if any verified
  integration fails — useful in CI. Error messages include provider-specific fix hints (e.g.
  `gcloud auth application-default login`).

- **`unfault config agent claude` / `opencode`** — generate per-command `SKILL.md` files so
  Claude Code and OpenCode agents can use unfault natively (carried forward from the
  previous unreleased entry).

### Changed

- **Review output redesigned** — the hazard block now reads as a zoom-out from code to
  system: `file:line · Aka Name` (where you are) → finding title (what the code is missing)
  → `↳ puts SLO at risk (100%)` (what breaks) → hazard sentence (why it matters) → Tradeoff
  section (the engineering tension). The SLO name is rendered in bright white. The `↳`
  character runs consistently through the block — once for the system consequence, twice for
  the tradeoff dimensions.

- **Footer replaces header** — session metadata (workspace, language, file count, timing
  breakdown, cache status) moved from a multi-line header before findings to a single compact
  line after them. The workspace name is rendered as a filled pill. Timing is broken down as
  `parse Xms  engine Xms  fetch Xms` so the source of latency is visible. `fetch` is shown
  in yellow (network, outside the tool's control); `cached` is shown in green.

- **Silent failure fix** — expired GCP credentials and SLO/trace fetch errors now always
  surface a `warn:` line pointing to `unfault config integrations verify`, regardless of
  `--verbose`. Previously these failures were silently swallowed.

- **Dependency updates** — 88 packages updated to latest compatible versions including
  `clap 4.6`, `anstream 1.0`, `hyper 1.9`, `uuid 1.23`, `hashbrown 0.17`.

### Fixed

- `span_id: u64` in the Cloud Trace wire type caused a parse failure on real API responses,
  where `spanId` is a decimal string. Changed to `String`.

- Cloud Trace `ListTracesResponse` returned `{}` (no `traces` key) when no traces matched
  the time window, causing a deserialization error. Fixed with `#[serde(default)]`.

- `kind == RPC_CLIENT` filter dropped all spans from Cloud Run's OTEL exporter, which omits
  `kind` entirely. Replaced with a two-tier strategy: explicit `RPC_CLIENT`/`CLIENT` kind,
  then host-based inference (span's `/http/host` is external to the service).

- `host_to_service_name` stripped `api.github.com` to `"api"` by taking the first DNS label.
  Fixed with a public TLD allowlist.

- World Model propagation returned `aggregate_risk: 0.0` for all single-file projects because
  the BFS started from a `File` node and never reached the `MonitoredBy` edges on `Function`
  nodes inside it. Fixed by traversing `Contains` edges (weight 0.0) in the forward pass.

- Service-level SLOs from sibling services in the same GCP project were incorrectly linked
  to the local codebase. Fixed by matching the GCP service slug from the SLO resource name
  against the workspace directory name before linking.

- `one_line_impact` prefixed hazard sentences with "Traced to cli.py, which has no callers —
  a root of the call tree." The `↳` line in the renderer already surfaces this information;
  the prefix was removed.

### Internal

- `cli/src/integration/` directory introduced: GCP auth, SLO, and trace providers are now
  grouped by vendor (`integration/gcp/`, `integration/datadog/`, `integration/dynatrace/`)
  rather than by feature (`slo/gcp.rs`, `trace/gcp.rs`).

- `cli/src/enrichment_cache.rs` — new TTL-based file cache for enrichment snapshots.

- `analysis/src/sre/ranker.rs` — composite importance scorer.

- `analysis/src/sre/world_model.rs` — weighted BFS propagation engine across static +
  runtime graph edges.

- `core/src/graph/mod.rs` — `GraphNode::RemoteService`, `GraphNode::Slo`,
  `GraphEdgeKind::RemoteCall`, `GraphEdgeKind::MonitoredBy`, `SloProvider` added to both
  `unfault-core` and `unfault-analysis` graph types.

- `unfault-core` bumped to `0.3.0`, `unfault-analysis` to `0.2.0`.

## [0.7.0] - 2025-12-23

### Added

- `unfault config agent claude` and `unfault config agent opencode` generate per-command
  `SKILL.md` files so Claude Code and OpenCode agents can use unfault natively.
  Four skills are created: `unfault-review`, `unfault-graph-impact`, `unfault-graph-explore`,
  and `unfault-config`. Graph skills auto-trigger in context (fast, local); the review skill
  requires explicit invocation (`disable-model-invocation: true`) because it calls an external
  LLM. Skills are written project-local by default; pass `--global` to write to the user's
  home config directory. Pass `--dry-run` to preview paths without writing files.

## [0.6.0] - 2025-12-23

### Added

- `unfault ask` now builds a local code graph and sends it with your RAG question, enabling flow-aware answers without uploading sources. Responses surface the HTTP route, call stack, and external dependency usage that shape the answer, so you can see exactly how a behavior is implemented.
- Flow responses now highlight graph impact details, topic labels, and hints, making it easier to decide the next question or code change straight from the CLI.
- Added the `UNFAULT_DUMP_IR` environment variable to persist the serialized IR produced during `unfault review`, which simplifies reproducing tricky analysis issues.

### Fixed

- `unfault ask` now auto-detects the workspace ID using the same heuristics as `graph` and `review`, ensuring queries are scoped to the current repo even when the flag is omitted.
- Local graph building now runs framework analysis for TypeScript/Express projects and properly builds Rust semantics before serialization, so the flow context remains accurate across languages.
- Flow path rendering now preserves the tree hierarchy of nested function calls, producing readable call stacks in the CLI output.

## [0.5.1] - 2025-12-21

### Fixed

- Fixed LSP server advertising pull diagnostics capability which caused "Method not found" errors
- Added hidden `--stdio` flag for compatibility with vscode-languageclient
- LSP now uses push diagnostics model via `publishDiagnostics` notifications

## [0.5.0] - 2025-12-21

### Added

- **LSP Server**: New `unfault lsp` command that starts a Language Server Protocol server for IDE integration
  - Provides real-time diagnostics as you code
  - Supports code actions with quick fixes from patches
  - Custom `unfault/fileCentrality` notification for status bar file importance display
  - Client-side parsing using tree-sitter (via unfault-core) for privacy and performance
  - Supports `--verbose` flag for debug logging
- New dependencies: `tower-lsp`, `dashmap`, `async-trait` for LSP implementation
- New `unfault graph refresh` command to build/refresh the code graph on-demand
- Graph building is now decoupled from review sessions for faster performance
- Improved hint messages in `unfault ask` when no graph data is available

### Changed

- Graph building no longer happens automatically during `unfault review`
- Users must now run `unfault graph refresh` before using graph-based features

## [0.4.0] - 2025-12-12

### Fixed

- Dimension filtering now correctly sends separate analysis contexts for each requested dimension
- Improved validation error handling with user-friendly messages for API errors

## [0.3.0] - 2025-12-10

### Added

- renamed `unfault.toml` to `.unfault.toml` for consistency with other tools

## [0.2.0] - 2025-12-10

### Added

- Code of conduct
- Installation note for pre-built releases in README
- SARIF support for review command output

## [0.1.1] - 2025-12-09

### Added

- Missing `license` field to Cargo.toml

## [0.1.0] - 2025-12-09

### Added

- Initial release of Unfault CLI — a calm reviewer for thoughtful engineers

[0.6.0]: https://github.com/unfault/cli/releases/tag/v0.6.0
[0.5.1]: https://github.com/unfault/cli/releases/tag/v0.5.1
[0.5.0]: https://github.com/unfault/cli/releases/tag/v0.5.0
[0.4.0]: https://github.com/unfault/cli/releases/tag/v0.4.0
[0.3.0]: https://github.com/unfault/cli/releases/tag/v0.3.0
[0.2.0]: https://github.com/unfault/cli/releases/tag/v0.2.0
[0.1.1]: https://github.com/unfault/cli/releases/tag/v0.1.1
[0.1.0]: https://github.com/unfault/cli/releases/tag/v0.1.0
