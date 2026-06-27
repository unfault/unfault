# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

### Fixed

## [1.0.23] — 2026-06-27

### Changed

- **`unfault graph coverage` blind-spot messaging** — the nudge section now
  answers the question "which calls from this handler will I NOT see in traces
  if they fail?" for each direct callee:

  ```
  ⚠ 2 of 4 calls from get_run_structured_output have no span coverage:

    ○ get_final_assistant_structured_output
      → if get_final_assistant_structured_output fails or is slow,
        you will not see it in traces
        server/queries/output.py:44

    ○ get_session_or_404
      → if get_session_or_404 fails or is slow,
        you will not see it in traces
        server/utils.py:12

  ✓ 2 calls already covered:
    ● _build_structured_output_response  "build-output"
    ● validate_run  sdk:ddtrace
  ```

  Previously the section listed gap function names with no explanation of
  consequence. Now it explicitly names the blind spot ("you will not see it
  in traces") and separately confirms what IS covered.

## [1.0.22] — 2026-06-27

### Fixed

- Re-release of v1.0.21 with all three crates (`unfault-core` 0.5.22,
  `unfault-analysis` 0.4.22, `unfault` 1.0.22) bumped together for a clean
  crates.io publish.

## [1.0.21] — 2026-06-27

### Added

- **`GraphNode::Function` now carries `raw_calls`** — the list of call-site
  expressions extracted from the function body is now stored on the graph node
  itself. Used by `unfault graph coverage` as a fallback when cross-file
  `Calls` edges were not resolved, so the callee tree is never empty.

- **`ModuleCategory::Observability`** — `opentelemetry`, `ddtrace`,
  `sentry-sdk`, `opentracing`, `jaeger`, `zipkin`, `aws_xray`, and `otel.*`
  are now classified as `Observability` instead of `Other`, powering the
  `◑ sdk:…` signal in coverage output.

### Fixed

- **`with tracer.start_span()` context managers now detected as span signal**
  — Python `with` statements wrapping tracer calls (`start_span`,
  `start_as_current_span`, `start_active_span`, etc.) inside a function body
  are now synthesised as a `DecoratorSemantic::Tracing` on the function graph
  node, so `unfault graph coverage` correctly shows `●` (with the extracted
  span name) rather than `○` for instrumented handlers.

- **Coverage "✓ All functions carry span signal" fired at 0%** — the success
  condition now checks whether any node in the full tree has
  `SpanSignal::None`; it only fires when every single node carries a signal.

- **`unused import: AstLocation`** (analysis) and
  **`value assigned to content_hashes is never read`** (cli) warnings
  eliminated.

- **`raw_calls: vec![]` added to all `GraphNode::Function` initialisers**
  across `core`, `analysis`, and `cli` to keep builds clean after the new
  field was introduced.

- **Query cache was never used on warm runs** — all `unfault graph` subcommands
  (routes, impact, callers, stats, deps, critical, path, handlers, coverage,
  function-impact, brief) rebuilt the full code graph on every invocation even
  when nothing had changed. Root cause: `rmp_serde` serialises structs as
  positional arrays by default, but structs with `#[serde(skip_serializing_if)]`
  fields write a shorter array than expected, causing silent deserialization
  failures. Fixed by switching the query cache to struct-map encoding
  (`Serializer::with_struct_map()`), which writes field names so absent
  optional/default fields round-trip correctly. Cache version bumped to v2 to
  invalidate existing broken entries. On a warm cache most commands now return
  in under 50ms instead of 4–5 seconds.

### Performance

- **Git SHA lookup eliminated on cached runs** — `current_commit_sha()` now
  reads `.unfault/cache/commit_sha` instead of spawning `git rev-parse` on
  every command invocation. The file is invalidated when `.git/HEAD` or
  `.git/packed-refs` is newer than the cached file.

- **Semantics index no longer rescans the cache directory on every run** —
  `SemanticsCache::open()` now reads a single persisted `index.msgpack` file
  (one syscall) instead of walking every filename in `.unfault/cache/semantics/`
  to reconstruct the in-memory index. The index is written on first run and
  updated incrementally on cache misses. On a 366-file workspace this dropped
  cache open time from ~34ms to ~5ms.

## [1.0.20] — 2026-06-27

### Changed

- **`unfault graph coverage` redesigned** — the command now takes a route path
  (`/api/orders`) *or* a function name (`validate_order`) and walks the call
  tree in both directions to answer: "which functions in this path carry span
  instrumentation, and where are the gaps?"

  **What each node shows:**
  - `●` — function has a tracing decorator (`@trace`, `@instrument`, `@span`,
    `with tracer.start_as_current_span(…)`). Span name is extracted and shown
    in green when detectable.
  - `◑` — function's file imports an OTel/tracing SDK (opentelemetry, ddtrace,
    sentry-sdk, zipkin, jaeger, …) but no explicit decorator was found.
  - `○` — no instrumentation signal.

  **Role badges** next to each node reveal what kind of work is done:
  `db`, `http-client`, `remote:<service>`, or `GET /path` for entry handlers.
  These are derived from `UsesLibrary` edges to `ModuleCategory` nodes —
  no heuristics, pure graph edges.

  **Callers section** (above the anchor): all functions that reach this point,
  deepest ancestor first, indented to show ancestry distance.

  **Callees section** (below the anchor): full box-drawing tree of everything
  called from this function, stopping at library boundaries (db/http/remote).

  **Nudge section** at the bottom: lists every uninstrumented boundary
  (`○ db/http-client/remote`) — these are the specific functions where adding
  a span would make failures visible in traces. Logic functions without spans
  are listed separately on small trees (≤15 nodes) to avoid noise.

  **Summary line**: `N% of M functions carry span signal · K boundaries`.

  `--json` emits the full `CoverageContext` document including the anchor,
  callers list, callee tree, per-node span/role data, and summary counts.

- **`ModuleCategory::Observability` added** — opentelemetry, ddtrace,
  sentry-sdk, opentracing, jaeger, zipkin, AWS X-Ray, and `otel.*` are now
  categorised as `Observability` rather than `Other`. This powers the `◑`
  SDK-imported signal in coverage output.

## [1.0.18] — 2026-06-27

### Added

- **`unfault graph coverage <route>`** — new subcommand that walks an HTTP
  route subtree and reports OpenTelemetry trace and metrics coverage for every
  matched handler.

  Each route is evaluated on two independent dimensions:

  - **Traces** — inbound `SERVER`/`AppServer` spans fetched from GCP Cloud
    Trace are matched against route handlers. A handler is `observed` when
    recent real traffic spans match its path, `instrumented_only` when tracing
    decorators are present in code but no span evidence exists, `missing` when
    a trace source is configured but nothing was seen, and `unknown` when no
    trace source is configured at all (avoids false "missing" reports).

  - **Metrics** — SLOs from GCP Cloud Monitoring, Datadog, and Dynatrace are
    matched to routes via path patterns. A route is `covered` when at least
    one SLO targets it, `missing` when a metrics source is configured but no
    SLO matches, and `unknown` when no source is available.

  The overall per-route status rolls up to `full` (both covered), `partial`
  (one covered), `missing` (neither, sources available), or `unknown`.

  Human output renders routes as a path-prefix tree so gaps are obvious at a
  glance. `--json` emits a fully structured `CoverageContext` document.

  Accepts a route prefix (`/api`) or wildcard pattern (`/api/**`,
  `/users/*`). Supports `--method` to filter by HTTP verb, `--offline` to
  skip live fetches, `--refresh-cache` to force a fresh snapshot, and `--json`
  for machine-readable output.

  After a `unfault review` run the command is instant: review now co-fetches
  inbound route observations from Cloud Trace alongside the existing outbound
  call patterns and caches them in the enrichment cache. Coverage results are
  also stored in the query cache (keyed on route + method + commit SHA) so
  repeated calls within a session are free.

- **Inbound route observations in the enrichment cache** — `unfault review`
  now calls `fetch_route_observations` on the GCP Cloud Trace provider during
  its enrichment pass, storing the observed inbound HTTP routes alongside SLOs
  and remote-call patterns in `.unfault/cache/enrichment/`. This lets
  `unfault graph coverage` serve results from the enrichment cache without an
  extra Cloud Trace round-trip.

- **`slo::matcher::normalize_route_path` is now `pub`** — promoted to the
  single canonical implementation shared by the SLO matcher and the coverage
  command. Eliminates a prior duplication.

### Fixed

- **45-second outer timeout on live observability fetches** — `load_observability_data`
  (used by `unfault graph coverage`) now wraps SLO and Cloud Trace fetches in a
  `tokio::time::timeout(45s)` guard. Previously, a hanging API call would stall
  the command indefinitely. A clear warning is printed when the deadline fires.

## [1.0.17] — 2026-06-23

### Fixed

- **Semantics cache version bump to 5** — forces a full reparse of all files on
  next run, flushing stale cached import names that were parsed before the
  v1.0.15 `# noqa` comment-stripping fix. Files that had `# noqa`-commented
  multi-line imports would continue to produce corrupt `ImportsFrom` symbol
  names from the on-disk cache even after the parser was fixed, because the
  cache is keyed on file content hash and the file content had not changed.

## [1.0.16] — 2026-06-23

### Fixed

- **Graph cache now saved after every build, not only on all-cache-hit runs**
  `build_ir_cached` previously only wrote `graph.msgpack` when every file was
  a semantics cache hit (`all_cache_hits`). Any run with even one changed file
  skipped the save, causing the expensive petgraph rebuild (~1–3s) on every
  subsequent run until a fully clean warm run occurred. The graph cache key is
  the aggregate xxh3 hash of all file content hashes, which already guarantees
  correctness — a stale cache is rejected by hash mismatch. Removed the
  `all_cache_hits` gate; the graph cache is now saved unconditionally after
  every build, so the second run is fast regardless of what changed in the first.

## [1.0.15] — 2026-06-23

### Fixed

- **Import name parsing: inline `# noqa` comments on multi-line imports**
  `build_import` in `core/src/semantics/python/model.rs` splits `from x import
  (a, b,  # noqa ALN045\n    c)` on commas.  The element after the comment
  comma was `"  # noqa ALN045\n    c"`, which trimmed to `"# noqa ALN045\n    c"`.
  This leaked into `ImportsFrom { items }` edges and from there into
  `outgoing_exports[].name` in `graph brief` output.

  The fix strips everything from `#` onwards on each line of each comma-delimited
  token before trimming, so `"  # noqa ALN045\n    function_name"` → `"function_name"`.

  The v1.0.14 fix to `clean_schema_name` in `flask.rs` was a symptom treatment;
  this is the root cause fix in the import parser.

## [1.0.14] — 2026-06-23

### Fixed

- **Flask-smorest schema extraction: `# noqa` comments in decorator args**
  `extract_first_identifier_arg` and `extract_second_identifier_arg` were
  returning raw node text that could include a leading `# noqa …` comment
  when tree-sitter's byte range for the identifier node spanned the comment
  (e.g. `"# noqa ALN045\n     SomeSchema"`).
  Added `clean_schema_name()` which strips comment lines and leading whitespace
  before returning the identifier, and validates the result looks like a valid
  Python name (`[a-zA-Z0-9_.]+`). Both extractors now route through it.

## [1.0.13] — 2026-06-23

### Fixed

- `cargo fmt` — 24 formatting violations across `analysis/src/graph/traversal.rs`,
  `cli/src/commands/graph.rs`, `cli/src/commands/lsp.rs`, `core/src/graph/mod.rs`,
  `core/src/semantics/python/flask.rs`. No logic changes.

## [1.0.12] — 2026-06-23

### Added

- **`unfault graph brief <path>`** — structural brief for any subtree or component

  Pass any path prefix or bare component name; all files whose path contains
  the string are included.  Returns five sections, all derived from the static
  graph with no convention knowledge:

  - **routes** — HTTP handlers inside the subtree, with the same decorator
    badges, schema, and line-number annotations as `graph routes`.
  - **outgoing_exports** — symbols defined inside the subtree that are imported
    by code outside it (the de-facto public API regardless of folder layout).
    Uses `ImportsFrom { items }` edges; whole-module imports are recorded as
    `*`.  Grouped by defining file with a list of importers.
  - **incoming_imports** — external packages and internal files imported into
    the subtree.  Covers `ImportsFrom`, `Imports`, and `UsesLibrary` edges.
    Named symbols are listed when available.
  - **internal_entry_points** — functions inside the subtree that are called
    exclusively from outside (`external_callers_only`), exported but never
    called (`exported_unused`), or are HTTP handlers (`http_handler`).
    Naturally surfaces the boundary without any folder conventions.
  - **size** — file and function counts for the subtree.

  Result is query-cached keyed on `(path, HEAD SHA)`.
  `--json` emits the full `BriefContext` struct.

  New types in `core/src/types/graph_query.rs`:
  `BriefContext`, `BriefRoute`, `ExportedSymbol`, `IncomingImport`,
  `EntryPoint`, `EntryPointReason`, `BriefSize`.

  New traversal function: `get_brief()` in `analysis/src/graph/traversal.rs`.

## [1.0.11] — 2026-06-23

### Added

- **Decorator badges and writer flag in `routes` / `handlers` human output**
  Route and handler lines now show an annotation row with coloured badges for
  every recognised decorator (`[auth]` `[permission]` `[rate-limit]` `[cache]`
  `[retry]` `[tracing]` `[validation]` `[transaction]` `[feature-flag]`
  `[deprecated]`) and `[writes-db]` when the handler contains ORM writes.
  The row is omitted when there are no annotations — plain routes are unaffected.
  `RouteEntry` and `HandlerInfo` now carry `decorators`, `is_writer`, and `line`
  in JSON output as well.

- **Flask-smorest / webargs schema extraction**
  `FlaskRoute` gains `request_schema: Option<String>` and
  `response_schema: Option<String>` populated from the handler's decorator stack:
  - `@blp.arguments(SchemaX, ...)` / `@use_args(SchemaX)` → `request_schema`
  - `@blp.response(200, SchemaY)` / `@marshal_with(SchemaY)` → `response_schema`
  Recognised on plain function routes, Flask-smorest `MethodView` methods, and
  the custom `@ClassName.action_route(...)` pattern.
  Only the bare class name is captured (e.g. `"PetSchema"`).
  Both fields flow through `GraphNode::Function`, `HandlerInfo`, and `RouteEntry`
  and appear in JSON output. Human output renders them as `in:SchemaX  out:SchemaY`
  on the annotation row beneath the route line.

## [1.0.9] — 2026-06-23

### Added

- **Caller classification** — every entry in `callers[]` now carries a `kind` field
  (`business_logic` | `blueprint_wiring` | `app_factory` | `app_entrypoint`).
  Wiring-only callers (blueprint registration, `create_app`, `__init__.py` entry-points,
  bootstrap files) are labelled so they can be skipped during triage.
  `--exclude-wiring` flag on `graph callers` strips them from both human and JSON output.

- **Decorator semantics on functions** — `GraphNode::Function` now carries a
  `decorators: Vec<DecoratorSemantic>` field populated from the AST decorator list.
  `DecoratorSemantic` is a tagged enum with 11 variants:
  `auth | permission | rate_limit | cache | retry | tracing | validation |
  transaction | feature_flag | deprecated | other`.
  Decorators are surfaced on `HandlerInfo` (routes output) and on `CallerInfo`.
  Routing decorators (`@router.get`, `@app.route`, …) are filtered out — only
  cross-cutting decorators are kept.

- **`is_writer` flag on functions** — `GraphNode::Function`, `CallerInfo`, and
  `HandlerInfo` carry `is_writer: bool`. Set when the function's file contains at
  least one ORM write call (INSERT / UPDATE / DELETE via SQLAlchemy, Django ORM,
  Tortoise, Peewee). Omitted from JSON when false.

- **Siblings in callers output** — `CallersContext` now includes `siblings[]`, a
  list of all other functions defined in the same file as the queried target.
  Each entry carries `name`, optional `http_method`, and optional `http_path`.
  Visible in JSON and rendered under the call tree in human output.

- **`target_line` / `target_column`** on `CallersContext` — 1-based source
  location of the target function definition, when available.  Human output
  renders it as `file.py:42:5` so no separate grep is needed to open the file.

- **Caveats field on `CallersContext`** — `caveats: Vec<String>` surfaces known
  static-analysis blind spots inline with results:
  - Event-pipeline consumers not traced: emitted when the target file imports from
    `events_pipeline*`, `kafka`, `celery`, `dramatiq`, `rq`, or `huey`.
  - Disambiguation warning: emitted when multiple functions share the queried name
    and no `file:function` hint was given, with instructions to disambiguate.

### Fixed

- **`graph function-impact` file hint silently discarded** — the `file` part of
  `file.py:function_name` was parsed but never forwarded to the graph traversal,
  meaning `function-impact` always searched all files regardless of hint.
  `extract_flow` now accepts an `Option<&str>` file hint and uses
  `find_nodes_by_name_in_file` for disambiguation.

## [1.0.8] — 2026-05-30

### Added

- **`unfault graph path <from> <to>`** — find the shortest call path between two functions
  - Uses BFS over `Calls` edges from `from` to `to`; returns the exact chain of
    function calls that connects them in order
  - Also resolves any HTTP routes that can trigger `from` (via reverse BFS, depth 1)
    so the full ingress → chain is visible in one command
  - `from` and `to` accept plain function names or `file.py:function` to disambiguate
  - Reports clearly when no path exists
  - Result is query-cached keyed on `(from, to, HEAD SHA)` — instant on repeat runs
  - `--json` output includes `found`, `path[]`, and `entry_routes[]`

- **`unfault graph handlers <pattern>`** — find all HTTP route handlers matching a path pattern
  - Pattern rules: plain string = substring match; `*` = within one segment;
    `**` = across segment boundaries
  - Examples: `/users`, `/users/*`, `/api/**`, `invite_email`
  - Output grouped by source file, showing method, path, handler name, and async marker
  - Result is query-cached keyed on `(pattern, HEAD SHA)`
  - `--json` emits `handlers[]` with `{ method, path, handler, file, is_async }`

- `PathContext` and `HandlersContext`/`HandlerInfo` added to `core/src/types/graph_query.rs`
- `find_path` and `find_handlers` added to `analysis/src/graph/traversal.rs`

## [1.0.7] — 2026-05-30

### Added

- **Query cache extended to all graph commands**
  The query cache introduced in v1.0.6 for `callers` now covers every graph
  command that does a BFS/traversal query:
  - `impact` — `GraphContext` keyed on file_path + max_depth + HEAD
  - `function-impact` — `FlowContext` keyed on function + max_depth + HEAD
  - `deps` — `GraphContext` keyed on file_path + HEAD
  - `library` — `GraphContext` keyed on library_name + HEAD
  - `stats` — `WorkspaceContext` keyed on HEAD only (workspace-level result)
  - `critical` — `GraphContext` keyed on sort_metric + limit + HEAD
  - `routes` — `Vec<RouteEntry>` keyed on method_filter + file_filter + HEAD

  All commands skip graph loading entirely on a cache hit (~100ms vs ~2.7s).
  `--verbose` bypasses the cache on all commands. `unfault graph refresh`
  clears all cached results.

  `query_cache` module generalised: `get<T>` and `set<T>` accept any
  `Serialize + DeserializeOwned` type; typed convenience wrappers for each
  command keep call sites concise.

  `RouteEntry` now derives `Deserialize` (was `Serialize` only).

## [1.0.6] — 2026-05-30

### Added

- **`unfault graph callers` query cache — near-instant repeat queries**
  - BFS results (`CallersContext`) are cached to `.unfault/cache/query/` keyed
    on `xxh3(function_name + file_hint) + "_" + git-HEAD-sha`
  - On a cache hit the graph is never loaded — the result is served directly
    from a tiny msgpack file (~100ms total vs ~2.7s)
  - Cache is automatically invalidated whenever `git HEAD` changes (commit,
    reset, branch switch) — no manual intervention needed
  - `--debug` and `--verbose` bypass the cache and always run the full pipeline
  - Suggestions (`suggest_callers_candidates`) are skipped on cache hits since
    the graph is not loaded; this is fine because suggestions only appear when
    `callers` is empty, and cached results are only stored when callers were found

- **`unfault graph refresh`** — explicit cache reset + rebuild
  - Deletes the query cache (`.unfault/cache/query/`)
  - Deletes the graph cache (`graph.msgpack`)
  - Rebuilds the full graph immediately with a spinner
  - Reports the new HEAD commit SHA on completion
  - Use after major refactors, branch switches, or any time you want a
    guaranteed-fresh baseline before running `callers` or `routes`

## [1.0.5] — 2026-05-30

### Changed

- **`unfault fault` is now interactive** — replacing the flat wall of commands with a two-step selection flow powered by `dialoguer`:

  **Step 1 — target:** choose Ingress (the detected HTTP route) or any auto-detected Egress target (outbound HTTP call or DB query discovered by walking the call graph forward).

  **Step 2 — scenario:** pick from the 12 templates; each item shows the template name alongside a "why would I use this?" rationale so you can make an informed choice without already knowing the template names.

  **Output:** a single `fault run` command + the expected learning ("what will I confirm?") + the `curl` or `export` hint to wire the proxy, then exit.

  - `--template <name>` still works non-interactively for scripting/CI
  - Escape or `q` exits cleanly at either prompt
  - `FaultTemplate::why()` and `FaultTemplate::expected_learning()` methods added with full descriptions for all 12 scenarios

## [1.0.4] — 2026-05-30

### Added

- **`unfault fault` — automatic egress fault scenario generation**
  - After the existing ingress section, the command now walks **forward** through
    `Calls` edges from the target function, inspects `http_calls` and `orm_queries`
    on every reachable function, and emits a separate egress `fault run` block for
    each discovered outbound dependency
  - For HTTP calls with a statically-determinable string literal URL (e.g.
    `requests.get("https://payments.internal/charge", ...)`), the origin
    (`https://payments.internal`) is extracted and used as `--upstream`
  - For HTTP calls with a dynamic URL (env var, variable), a placeholder is
    shown so the user knows a call exists even without a concrete URL
  - For ORM queries (SQLAlchemy, Django ORM, Tortoise, Peewee, etc.), a
    `fault run` targeting the default database port is generated
    (`postgresql://localhost:5432` for Postgres-family ORMs, `mysql://localhost:3306`
    for Peewee)
  - Egress proxies are assigned ports starting at `--port + 1` so all ingress
    and egress `fault run` commands can be run simultaneously without conflicts
  - The `--mode egress` flag still works for manual override (e.g. when the URL
    is not statically determinable)

- **Spinner on `unfault fault` while the graph is loading**
  - Same braille spinner as `unfault graph` commands; cleared before output,
    suppressed in `--verbose`

- **`HttpClientKind::as_str()`** added to `unfault-core` for use in labels

## [1.0.3] — 2026-05-30

### Added

- **Spinner on all `unfault graph` commands while the graph is loading**
  A braille spinner (`⠋⠙⠹…`) with "Building graph…" is shown on stderr
  while `build_analysis_graph` runs (~2.7s on large workspaces). The spinner
  is cleared before any output is printed, so it never interleaves with
  results. Suppressed automatically in `--verbose` (TIMING lines already give
  feedback) and `--json` (stdout must stay clean for piping).

## [1.0.2] — 2026-05-30

### Fixed

- `cargo fmt` cleanup of indentation inside `io_pool.install` closure (missed in v1.0.1)

## [1.0.1] — 2026-05-30

### Performance

- **Dedicated I/O thread pool for cache reads (up to 64 threads)**
  The `par_iter` over 27k files uses Rayon's global pool which defaults to
  `num_cpus` threads — optimal for CPU-bound work but leaves threads idle
  while waiting on filesystem I/O. The cache read phase (stat + msgpack read
  per file) is now run in a dedicated `rayon::ThreadPool` with up to 64
  threads, allowing more concurrent I/O operations and better utilisation of
  SSD queue depth.

## [1.0.0] — 2026-05-30

### Changed (breaking internal architecture — no CLI API changes)

- **Unified type system: analysis crate is now a thin façade over unfault-core**

  The analysis crate previously maintained ~5000 lines of near-duplicate type
  definitions that diverged from core over time, causing JSON round-trip failures,
  missing bug fixes, and silent data loss. All shared types are now re-exported
  from core. Specific changes:

  **`analysis/src/semantics/python/model.rs`** (2771 lines → 24 lines)
  - `PyFileSemantics`, `PyFunction`, `PyImport`, `PyCallSite`, `PyParam`,
    `PyClass`, `PyAssignment`, `ImportInsertionType`, `ImportCategory`,
    `ImportStyle`, `BareExceptClause`, `AsyncOperation`, `AsyncOperationType`,
    `Decorator` are now `pub use unfault_core::semantics::python::model::*`
  - Analysis `PyFileSemantics` gains the three previously missing fields:
    `django`, `async_operations`, `decorators`
  - `PyFunction` gains `start_byte` and `end_byte`
  - `analyze_frameworks` now runs all seven analyzers (was four)
  - Multi-line parenthesised import parsing fix (`from pkg import (\n    foo,\n)`)
    now applies automatically (was only fixed in core)

  **`analysis/src/semantics/python/http.rs`** (901 lines → 5 lines)
  - `HttpCallSite`, `HttpClientKind`, `RetrySource`, `summarize_http_clients`
    re-exported from core; non-HTTP method filter fix ported to core first

  **`analysis/src/semantics/python/orm.rs`** (763 lines → 7 lines)
  - All ORM types re-exported from core

  **`analysis/src/semantics/common/calls.rs`** (33 lines → 2 lines)
  **`analysis/src/semantics/common/imports.rs`** (771 lines → 6 lines)
  **`analysis/src/semantics/common/http.rs`** (393 lines → 5 lines)
  **`analysis/src/semantics/common/db.rs`** (453 lines → 5 lines)
  - All re-exported from core; `CommonLocation` also re-exported from core

  **`analysis/src/graph/mod.rs`**
  - `GraphNode`, `GraphEdgeKind`, `ModuleCategory`, `SloProvider` are now
    `pub use unfault_core::graph::*` — ~230 lines of duplicate definitions removed
  - `CodeGraph` gains `suffix_to_file` and `module_to_file` index maps (matching
    core), making `find_file_by_path` O(1) instead of O(n linear scan)
  - `rebuild_indexes` now populates all 7 maps (was 5)
  - New `From<unfault_core::graph::CodeGraph> for CodeGraph` impl: direct field
    move + `rebuild_indexes`, zero copies, no serialization

  **`cli/src/local_graph.rs`**
  - JSON round-trip (`serde_json::to_string` + `serde_json::from_str`) replaced
    with `unfault_analysis::graph::CodeGraph::from(build_result.ir.graph)` — the
    ~300ms serialization cost is eliminated entirely on warm-cache runs

### Fixed

- `analysis/src/semantics/python/http.rs`: `httpx.URL()`, `httpx.Headers()` etc.
  were incorrectly detected as HTTP calls; non-HTTP method names are now filtered
  (fix already existed in analysis, now ported to core so both benefit)

## [0.9.16] — 2026-05-29

### Fixed

- **Revert msgpack IR round-trip (v0.9.15) — deserialization failure**
  The analysis crate's `SourceSemantics::Python` carries extra fields
  (e.g. `flask: Option<FlaskFileSummary>`) absent from the core crate's
  version. JSON tolerates missing fields via serde's `#[serde(default)]`;
  msgpack does not by default, causing `rmp_serde::from_slice` to fail
  on every graph command. Reverted to `serde_json` for the round-trip.
  The correct long-term fix (unifying the two IR types) is tracked separately.

## [0.9.15] — 2026-05-29

### Performance

- **Replace JSON round-trip with msgpack in `build_analysis_graph`**
  `local_graph.rs` converted between the core and analysis `IntermediateRepresentation`
  types via `serde_json::to_string` + `serde_json::from_str`. On a 27k-function
  graph this produced a large JSON string (text formatting, UTF-8 escaping,
  allocation per token) before immediately discarding it. Replaced with
  `rmp_serde::to_vec` + `rmp_serde::from_slice` — same Serde round-trip,
  binary format, ~10x faster serialization, far fewer allocations.

## [0.9.14] — 2026-05-29

### Changed

- **`SemanticsCache` internal redesign — lock-free read path**
  - `CacheStats` now uses `AtomicUsize` for `hits` and `misses` — all read
    methods can increment counters without holding any lock
  - All read methods (`check_metadata`, `get`, `record_metadata_hit`,
    `record_miss`, `get_stored_content_hash`) take `&self` instead of
    `&mut self` — they are safe to call from multiple threads with only
    a shared reference
  - Only `set()` (called on cache misses, the slow path) retains `&mut self`
  - `CacheStats` replaced by `CacheStatsSnapshot` (plain `usize` fields) for
    display and the `IrBuildResult` public API; `stats_snapshot()` takes a
    lock-free snapshot
  - The `Mutex<SemanticsCache>` in `ir_builder.rs` is now held for
    nanoseconds (index lookup only) on the hot path; the msgpack file read
    already happened outside the lock since v0.9.13
  - Practical effect: the remaining ~1s "File read + cache" time on a 27k-file
    warm cache is dominated by filesystem I/O (reading 27k msgpack files),
    not lock contention — a more specialised mutex would not have helped

## [0.9.13] — 2026-05-29

### Performance

- **Fix mtime fast path mutex contention (warm cache still slow at ~1.2s)**
  The v0.9.12 mtime fast path read the msgpack cache file *inside* the
  `Mutex<SemanticsCache>` lock. With 27k files all hitting the fast path in
  parallel via `par_iter`, the mutex serialised all file I/O — no better than
  before.
  Fix: split into two phases. Phase 1 (under lock, ~100ns): look up the index
  entry, return the cache file path if mtime+size match. Phase 2 (outside
  lock): read the msgpack file in parallel across Rayon threads. The lock is
  held only for the in-memory HashMap lookup; all I/O is concurrent.
  Expected warm-cache "File read + cache" to drop from ~1.2s to ~150–300ms.

## [0.9.12] — 2026-05-29

### Performance

- **Warm-cache runs 3–5× faster on large workspaces**

  Two independent optimisations targeting the two most expensive phases
  measured on a 27k-file codebase (was ~4s total on a warm cache):

  **1. mtime + size fast path for per-file cache lookup (saves ~1.5s)**
  Previously every file was read from disk on every run just to compute
  its content hash before checking the cache. The cache now stores
  `mtime_secs` and `file_size` alongside `content_hash`. On the next run
  only the file metadata is read (syscall, no I/O); if mtime and size
  match the stored values the file read is skipped entirely and the cached
  semantics are returned directly. Legacy cache entries (version < 4)
  without metadata fall back to the old content-hash path gracefully.
  `CACHE_VERSION` bumped to 4 — existing cache entries will be rebuilt
  on the first run and the fast path will apply from the second run onward.

  **2. Graph cache on disk (saves ~1.3s)**
  The petgraph was rebuilt from all semantics entries on every run even
  when nothing had changed. A `graph.msgpack` file is now stored in
  `.unfault/cache/`. It is keyed on an aggregate xxh3 hash of all file
  content hashes (stable across runs when no file changes). On a fully
  warm cache the graph is loaded directly instead of being rebuilt,
  eliminating the `build_code_graph` call entirely. The cache is
  invalidated automatically whenever any file changes.

  **Expected warm-cache timing after first primed run:**
  - File discovery: ~600ms (unchanged — filesystem walk)
  - File read + cache: ~200ms (was ~1600ms)
  - Graph build: ~50ms (was ~1300ms, now just loading msgpack)
  - Total: ~1s (was ~4s)

## [0.9.11] — 2026-05-29

### Fixed

- **Multi-line parenthesised imports had parentheses included in name strings**
  - `from pkg import (\n    foo,\n    bar,\n)` was storing `"(\n    foo"` as the first name instead of `"foo"`
  - This caused `imports_item("foo")` to return `false`, so cross-file `Calls` edges were never added for any function imported this way
  - Fix: strip leading `(` / trailing `)` from `names_part` before splitting on `,`, and additionally trim `()`  from each individual name
  - 2 new tests: `multiline_import_names_parsed_correctly`, `function_scoped_multiline_import_names_parsed_correctly`

## [0.9.10] — 2026-05-29

### Changed

- **`unfault graph callers --debug`** — extended diagnostics
  - Also searches for `_<function_name>` (underscore-prefixed handler) and prints its outgoing `Calls` edges with callee names and files
  - This reveals whether the edge from the handler to the target exists at all, or whether the cross-file resolution failed to add it

## [0.9.9] — 2026-05-29

### Added

- **`unfault graph callers --debug`** — raw graph diagnostics for the target function
  - Prints every graph node whose name matches the query, with its file path, handler metadata, and count of incoming/outgoing `Calls` edges
  - Lists each caller by name and file when incoming edges exist
  - Designed to diagnose "found in graph but no call edges resolved" cases by showing exactly what the graph contains before the BFS runs

### Tests

- 3 more graph edge tests: `flask_handler_with_underscore_prefix_calls_inner_function`, `action_route_handler_cross_file_call_function_scoped_import`, `action_route_with_inner_decorators_cross_file_call`

## [0.9.8] — 2026-05-29

### Tests

- **Cross-file call resolution from Flask handlers — 3 new tests confirming behaviour**
  - `flask_handler_cross_file_call_via_module_level_import` — `from services.users import get_all_users` at top of file, called inside `@app.route` handler
  - `flask_handler_cross_file_call_via_function_scoped_import` — same import made *inside* the handler body (`def list_users(): from services.users import get_all_users; return get_all_users()`)
  - `flask_restful_action_route_cross_file_call_via_function_scoped_import` — same function-scoped import pattern inside an `@ClassName.action_route` handler
  - All three pass: function-scoped imports are captured by the semantic extractor (with `is_module_level: false`) and the import lookup in `resolve_cross_file_call` does not filter by scope, so they resolve identically to module-level imports

## [0.9.7] — 2026-05-29

### Fixed

- **Version bump only** — `unfault-core` was not bumped in v0.9.6 despite changes to `core/src/graph/mod.rs` (`add_flask_nodes`, `handler_names_to_skip` update). Bumps: core 0.4.6, analysis 0.3.7, cli 0.9.7.

## [0.9.6] — 2026-05-29

### Fixed

- **`unfault graph callers` — two bugs causing "no call edges were resolved"**

  **Bug 1 — Double node for framework route handlers:**
  The analysis graph builder called `add_function_nodes` (which emits a plain
  `Function { is_handler: false, http_method: None, http_path: None }` node)
  and then `add_flask_nodes` / `add_fastapi_nodes` (which emit a second
  `Function { is_handler: true, http_method: Some(...), http_path: Some(...) }`
  node for the same handler). `function_nodes` was overwritten with the
  framework node (inserted last). The `Calls` edges from the third pass
  referenced the first node. `get_callers` looked up the framework node but
  found no incoming edges — zero callers.
  **Fix:** Add `handler_names_to_skip` to the analysis graph's
  `add_function_nodes`, mirroring the core graph builder's existing logic.

  **Bug 2 — Wrong caller key in the Calls edge pass:**
  The third pass iterated `sem.function_calls()` and looked up the caller in
  `function_nodes` using `func_call.caller_qualified_name` (e.g.
  `"MyClass.method"`). But `function_nodes` is keyed by the simple function
  name (e.g. `"method"`). The lookup always failed, so **zero `Calls` edges
  were ever added** in the analysis graph for method callers.
  **Fix:** Use `func_call.caller_function` (simple name) as the lookup key,
  falling back to the last segment of `caller_qualified_name`.

  **Cross-file call resolution added to analysis graph:**
  The analysis graph's Calls pass was intra-file only. It now also resolves
  calls through imports using `resolve_cross_file_call`, implementing the
  same three strategies as the core graph: direct import, module-attribute,
  and submodule-as-item.

  **3 new tests:** `intra_file_calls_edge_added`, `flask_handler_not_duplicated_in_graph`, `intra_file_calls_edge_from_flask_handler`

## [0.9.5] — 2026-05-29

### Added

- **`unfault graph routes`** — new command listing every HTTP route detected across the workspace
  - Output grouped by source file; each line shows `METHOD  /path  (handler_name)`
  - `--method GET` filters to a specific HTTP verb (case-insensitive)
  - `--file src/api` filters to files whose path contains the substring
  - `--json` emits a JSON array of `{ method, path, handler, file }` objects
  - Works across all supported frameworks: Flask (all patterns), FastAPI, Express, Gin, Axum, Actix, Rocket

- **Flask routes wired into the code graph** (was silently dropped before this release)
  - `build_code_graph()` in both `core` and `analysis` graph builders now has a `py.flask` branch alongside the existing `py.fastapi` branch
  - A new `add_flask_nodes()` function emits `GraphNode::Function { is_handler: true, http_method: Some(...), http_path: Some(...) }` for every `FlaskRoute` in `FlaskFileSummary` — covering all patterns: `@app.route`, `@bp.route`, `@blp.route` on MethodView classes, and `@ClassName.action_route`
  - Flask handler names are added to `handler_names_to_skip` in `add_function_nodes()` so they are not double-emitted as plain nameless handlers
  - `unfault graph callers`, `unfault graph stats`, and all other graph commands now see Flask routes

## [0.9.4] — 2026-05-29

### Added

- **Flask `action_route` / custom BaseController pattern support**
  - Detects routes defined through a two-level convention used in Flask-RESTful-based codebases:
    1. A controller class is registered to a base path via `@endpoint.route("/base")` on the class definition
    2. Individual handlers are attached via `@ClassName.action_route("/sub", methods=["GET"])` as the outermost decorator on the handler function
  - Full path is formed by joining the class base path with the handler sub-path: `"/base"` + `"/sub"` → `"/base/sub"`
  - Inner decorators (e.g. `@inject_auth`, `@log_request`) between `action_route` and the function are ignored — only the outermost decorator is inspected
  - `methods` kwarg is parsed identically to `@app.route(methods=[...])`: single entry → that verb, multiple → `"ANY"`, absent → `"GET"`
  - If no matching class registration is found for a given controller name, the sub-path from `action_route` is used directly as the route path
  - `is_async`, `has_try_except`, handler name, and byte ranges are all populated correctly
  - The two passes (`collect_action_route_class_bases` and `collect_action_route_handlers`) are fully recursive so the pattern is detected inside factory functions too
  - Workspace scanner now also triggers Flask profile detection for `from flask_restful import`, `import flask_restful`, and `.action_route(` text patterns
  - Profile `flask_routes` file hint extended with `.action_route(` and `BaseController`; `flask_blueprints` hint extended with `from flask_restful import` and `Endpoint(`
  - 10 new tests covering: simple GET, multiple methods, sub-path joining, inner decorators ignored, default GET, multiple controllers, orphaned handler (no class base), try/except detection, async handler, mixed with regular `@app.route`

## [0.9.3] — 2026-05-29

### Added

- **FastAPI application factory pattern support**
  - Routes, apps, middlewares, routers, and exception handlers defined inside factory functions (e.g. `def create_app()`) are now confirmed working — all collectors in `summarize_fastapi` were already fully recursive; this release documents and tests that behaviour explicitly with 6 new tests
  - 6 new core tests covering: factory app, factory routes, `include_router` with prefix inside a factory, `add_middleware` inside a factory, `@app.exception_handler` inside a factory, and router-only factory functions

### Changed

- **Eliminated `fastapi.rs` duplication between core and analysis crates**
  - `analysis/src/semantics/python/fastapi.rs` (1816 lines) replaced with a 12-line re-export facade: `pub use unfault_core::semantics::python::fastapi::*`
  - `analysis/src/semantics/python/model.rs` now calls `unfault_core::semantics::python::fastapi::summarize_fastapi` directly (same pattern already used for Flask)
  - All FastAPI rule tests and graph code continue to work unchanged via the re-export; the 49 previously duplicated tests in the analysis crate are now the canonical tests in the core crate

## [0.9.2] — 2026-05-29

### Added

- **Flask application factory pattern support**
  - Routes (`@app.route`, `@blp.route` on MethodView) defined inside factory functions (e.g. `def create_app()`) are now detected — the AST collectors were already fully recursive, confirming routes were found; this release documents and tests that behaviour explicitly
  - New `FlaskConfigSetting` type in `FlaskFileSummary` captures config values set via the two factory-pattern idioms:
    - Subscript assignment: `app.config['SECRET_KEY'] = "value"`
    - `update()` call: `app.config.update(SESSION_COOKIE_SECURE=False, ...)`
  - All three Flask rules (`hardcoded_secret_key`, `missing_session_timeout`, `insecure_cookie_settings`) now check both module-level assignments and `flask.config_settings`, so hardcoded keys and insecure cookie flags set inside `create_app()` are caught
  - `flask` field added to the analysis crate's `PyFileSemantics` (populated via `unfault_core::semantics::python::flask::summarize_flask`), making the full Flask semantic summary available to all rules without re-implementing extraction
  - 7 new tests covering: factory routes, subscript config assignment, `update()` kwargs, mixed patterns, non-config attribute filtering, blueprint registration, and MethodView inside a factory

## [0.9.1] — 2026-05-29

### Added

- **Flask-smorest / MethodView route detection**
  - `@blp.route('/path')` decorating a `MethodView` subclass is now parsed: each HTTP-method-named method (`get`, `post`, `put`, `patch`, `delete`, `options`, `head`) produces its own `FlaskRoute` entry with the path from the class-level decorator
  - `handler_name` is set to `ClassName.method` (e.g. `ItemList.get`) for unique identification
  - Methods decorated with `@blp.arguments` / `@blp.response` are correctly unwrapped and detected
  - Non-HTTP methods (`__init__`, helpers, etc.) are ignored
  - `flask_smorest` imports (`from flask_smorest import …` / `import flask_smorest`) now trigger Flask framework detection in the workspace scanner
  - `flask_smorest.Blueprint` (`blp = Blueprint('name', __name__, description=…)`) is detected as a Flask blueprint — no change needed at the AST level since the call site is identical to `flask.Blueprint`
  - File hints in the `python_flask_backend` profile extended: `@blp.route(`, `MethodView`, `from flask_smorest import Blueprint` added to `flask_routes`, `flask_blueprints`, and `flask_app` hint patterns

### Fixed

- **`unfault fault` — correct `fault run` flag usage** per the fault-project.com CLI reference:
  - `--disable-http-proxy --proxy PORT=URL` → `--proxy-address 127.0.0.1:PORT` + `--upstream URL`
  - `--schedule-start`/`--schedule-end` (non-existent) → `--<fault>-sched "start:25%,duration:50%"` using relative intervals that scale with `--duration`
  - `latency-pareto` template: `--latency-mean`/`--latency-stddev` → `--latency-shape 1.5 --latency-scale 20` (correct params for pareto distribution)
  - Bandwidth templates: added `--bandwidth-unit KBps` (default unit is `Bps`)
  - Packet loss templates: `--packet-loss-rate`/`--packet-loss-mode` (non-existent) → `--packet-loss-direction`
  - Blackhole templates: added `--blackhole-direction` (was missing)

## [0.9.0] — 2026-05-28

### Added

- **`unfault graph callers <file:function>`** — "you are here" inbound call chain view
  - New CLI command that traces who calls a given function and which HTTP routes anchor the chain
  - Renders a proper multi-branch tree with `├─` / `└─` connectors: all direct callers shown, not just one representative path
  - `--max-depth` controls how many hops to follow (default 5), `--json` emits structured output
  - When a function is found but has no call edges, suggests HTTP route handlers in the same file or same module directory as ready-to-use next steps
  - When a function name is not in the graph, shows fuzzy name-matched suggestions ranked by token overlap

- **`unfault fault <file:function>`** — fault injection scenario generator
  - New top-level command generating ready-to-run `fault run` commands (https://fault-project.com) for endpoints reachable from a given function
  - Resolves HTTP routes via the code graph; supports `--template` to select one of 12 named scenarios or prints all 12 by default
  - All 12 templates from the VSCode extension: `latency-normal`, `latency-pareto`, `latency-window`, `jitter-light`, `jitter-bidirectional`, `bandwidth-64k`, `bandwidth-48k-latency`, `mobile-3g`, `packet-loss`, `packet-loss-burst`, `blackhole`, `blackhole-window`
  - `--mode ingress` (default): proxies between curl and the local app, prints a companion `curl` command; `--mode egress`: proxies between the app and a remote dependency
  - `file:function` scoping: `service.py:get` resolves only the `get` function in that file, not every `get` across the workspace

- **FastAPI router prefix resolution**
  - `include_router(router, prefix="/assistant")` is now parsed: `prefix` keyword argument is extracted from the AST and stored on `FastApiRouter`
  - Routes registered on a sub-router now carry the full prefixed path (e.g. `/assistant/scenario/{id}` instead of `/scenario/{id}`) throughout the graph, in both `FastApiRoute` nodes and `Function { http_path }` fields
  - Prefix is resolved in the core graph builder (`unfault-core`) which is the path used at runtime by all CLI commands

- **Cross-file call edge resolution: submodule-as-item pattern**
  - Added Strategy 3 to `resolve_call_through_imports`: handles `from pkg import submodule` followed by `submodule.func()` — previously unresolved because the import's `local_module_name()` is the parent package, not the submodule alias
  - Resolves the submodule path as `pkg.submodule` and looks up the callee there

- **`unfault graph callers` help text**: added description, examples, and flag explanations

### Fixed

- **`unfault fault` route scoping**: passing `file.py:get` previously stripped the file prefix and matched every function named `get` across the entire workspace. The file hint is now threaded into `find_nodes_by_name_in_file` which filters to nodes whose file path ends with the hint before falling back to workspace-wide matches
- **`fault run` flag formatting**: multi-word flags (`--latency-direction ingress`) were being split across separate continuation lines; each flag+value pair is now kept on a single line
- **Stale `format_list` dead code** removed from `cli/src/commands/review.rs`

### Tests

- Updated `router_expr_contains_full_arguments` → `router_expr_is_first_positional_arg_and_prefix_extracted` in both `core` and `analysis` crates to reflect that `router_expr` now stores only the first positional argument and `prefix` is a separate field

### Flask first-class framework support (from prior unreleased work)

- Added `python.flask.hardcoded_secret_key`, `python.flask.session_timeout`, and `python.flask.insecure_cookie_settings` rules to the `python_flask_backend` profile
- Added `Dimension::Security` and `Dimension::Performance` to the Flask profile
- Added resilience and observability rules to the Flask profile: `missing_circuit_breaker`, `graceful_shutdown`, `unbounded_retry`, `unbounded_memory`, `large_response_memory`, `missing_correlation_id`
- Added five new file hints to the Flask profile: `flask_routes`, `flask_blueprints`, `flask_config`, `python_middleware`, `python_resilience`
- Fixed `@app.route('/path', methods=['POST'])` always mapping to `"GET"` — `methods` kwarg is now parsed correctly
- Fixed Flask cookie settings rule returning wrong applicability preset
