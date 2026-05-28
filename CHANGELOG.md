# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **Flask first-class framework support**
  - Added `python.flask.hardcoded_secret_key`, `python.flask.session_timeout`, and `python.flask.insecure_cookie_settings` rules to the `python_flask_backend` profile — previously registered but never fired via the profile
  - Added `Dimension::Security` and `Dimension::Performance` to the Flask profile, bringing it to parity with FastAPI
  - Added resilience and observability rules to the Flask profile: `missing_circuit_breaker`, `graceful_shutdown`, `unbounded_retry`, `unbounded_memory`, `large_response_memory`, `missing_correlation_id`
  - Added five new file hints to the Flask profile: `flask_routes`, `flask_blueprints`, `flask_config`, `python_middleware`, `python_resilience`
  - Added `"Flask"` to the `web_priority` list in framework detection — Flask is now treated as a first-class web framework rather than a micro-framework afterthought
  - Added `session_cookie_security()` applicability preset in `applicability_defaults`

### Fixed

- **Flask semantic extractor**: `@app.route('/path', methods=['POST'])` was always mapped to `"GET"`. The `methods` kwarg is now parsed: single method → that method, multiple methods → `"ANY"`, absent → `"GET"` (Flask's default)
- **Flask cookie settings rule**: `applicability()` was returning `cors_policy()` instead of the correct cookie security applicability

### Tests

- Added four tests for the Flask profile: `has_correct_id`, `has_flask_specific_rules`, `has_security_dimension`, `has_file_hints`
- Added three tests for `@app.route` method extraction: single method kwarg, multiple methods (`"ANY"`), and default `"GET"` when kwarg is absent
