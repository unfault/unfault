# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

### Fixed

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
