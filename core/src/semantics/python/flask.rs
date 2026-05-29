use serde::{Deserialize, Serialize};
use tree_sitter::Node;

use crate::parse::ast::{AstLocation, ParsedFile};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaskFileSummary {
    pub apps: Vec<FlaskApp>,
    pub blueprints: Vec<FlaskBlueprint>,
    pub routes: Vec<FlaskRoute>,
    pub error_handlers: Vec<FlaskErrorHandler>,
    /// Config key/value pairs collected from both module-level assignments
    /// *and* factory-function patterns such as `app.config['KEY'] = val`
    /// or `app.config.update(KEY=val, ...)`.
    pub config_settings: Vec<FlaskConfigSetting>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaskApp {
    pub var_name: String,
    pub location: AstLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaskBlueprint {
    pub var_name: String,
    pub import_name: String,
    pub location: AstLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaskRoute {
    pub app_var_name: String,
    pub http_method: String,
    pub path: String,
    pub handler_name: String,
    pub is_async: bool,
    pub has_try_except: bool,
    pub location: AstLocation,
    pub decorator_location: AstLocation,
    pub body_start_byte: usize,
    pub body_end_byte: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaskErrorHandler {
    pub app_var_name: String,
    pub error_code: u32,
    pub handler_name: String,
    pub location: AstLocation,
}

/// A single Flask config key/value pair detected in the file, regardless of
/// whether it was set at module level (`SECRET_KEY = "x"`) or inside a factory
/// function via `app.config['KEY'] = value` or `app.config.update(KEY=value)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaskConfigSetting {
    /// Config key name, e.g. `"SECRET_KEY"`, `"SESSION_COOKIE_SECURE"`.
    pub key: String,
    /// Text representation of the value as it appears in source, e.g. `"\"dev\""`, `"False"`.
    pub value_repr: String,
    pub location: AstLocation,
}

pub fn summarize_flask(file: &ParsedFile) -> Option<FlaskFileSummary> {
    let root = file.tree.root_node();

    let mut apps = Vec::new();
    let mut blueprints = Vec::new();
    let mut routes = Vec::new();
    let mut error_handlers = Vec::new();
    let mut config_settings = Vec::new();

    collect_flask_apps(file, root, &mut apps);
    collect_flask_blueprints(file, root, &mut blueprints);
    collect_flask_routes(file, root, &mut routes);
    collect_flask_error_handlers(file, root, &mut error_handlers);
    collect_flask_config_settings(file, root, &mut config_settings);

    // Two-pass action_route pattern: first build the class→base-path map,
    // then extract handlers that reference those classes.
    let class_bases = collect_action_route_class_bases(file, root);
    collect_action_route_handlers(file, root, &class_bases, &mut routes);

    if apps.is_empty()
        && blueprints.is_empty()
        && routes.is_empty()
        && error_handlers.is_empty()
        && config_settings.is_empty()
    {
        return None;
    }

    Some(FlaskFileSummary {
        apps,
        blueprints,
        routes,
        error_handlers,
        config_settings,
    })
}

fn collect_flask_apps(file: &ParsedFile, node: Node, out: &mut Vec<FlaskApp>) {
    if node.kind() == "assignment" {
        if let Some(app) = extract_flask_app(file, node) {
            out.push(app);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_flask_apps(file, child, out);
    }
}

fn extract_flask_app(file: &ParsedFile, node: Node) -> Option<FlaskApp> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;

    if left.kind() != "identifier" {
        return None;
    }

    if right.kind() != "call" {
        return None;
    }

    let function = right.child_by_field_name("function")?;
    let func_name = file.text_for_node(&function);
    if func_name != "Flask" {
        return None;
    }

    let app_var_name = file.text_for_node(&left);
    let location = file.location_for_node(&right);

    Some(FlaskApp {
        var_name: app_var_name,
        location,
    })
}

fn collect_flask_blueprints(file: &ParsedFile, node: Node, out: &mut Vec<FlaskBlueprint>) {
    if node.kind() == "assignment" {
        if let Some(bp) = extract_flask_blueprint(file, node) {
            out.push(bp);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_flask_blueprints(file, child, out);
    }
}

fn extract_flask_blueprint(file: &ParsedFile, node: Node) -> Option<FlaskBlueprint> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;

    if left.kind() != "identifier" {
        return None;
    }

    if right.kind() != "call" {
        return None;
    }

    let function = right.child_by_field_name("function")?;
    let func_name = file.text_for_node(&function);
    // Accept both `flask.Blueprint` and `flask_smorest.Blueprint` (the latter is imported
    // with `from flask_smorest import Blueprint` so the call site looks identical).
    if func_name != "Blueprint" {
        return None;
    }

    let var_name = file.text_for_node(&left);

    let args = right.child_by_field_name("arguments")?;
    let import_name = extract_first_string_arg(file, args).unwrap_or_default();

    let location = file.location_for_node(&right);

    Some(FlaskBlueprint {
        var_name,
        import_name,
        location,
    })
}

fn collect_flask_routes(file: &ParsedFile, node: Node, out: &mut Vec<FlaskRoute>) {
    if node.kind() == "decorated_definition" {
        // Function-based routes (@app.route / @blp.route on a plain function)
        extract_flask_function_route(file, node, out);
        // Class-based routes (@blp.route on a MethodView subclass)
        extract_flask_methodview_routes(file, node, out);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_flask_routes(file, child, out);
    }
}

/// Extract a single route from a decorated plain function (`@app.route('/') def index(): ...`).
fn extract_flask_function_route(file: &ParsedFile, decorated_def: Node, out: &mut Vec<FlaskRoute>) {
    let source_bytes = file.source.as_bytes();

    let mut decorators = Vec::new();
    let mut func_def: Option<Node> = None;

    let mut cursor = decorated_def.walk();
    for child in decorated_def.children(&mut cursor) {
        match child.kind() {
            "decorator" => decorators.push(child),
            "function_definition" | "async_function_definition" => func_def = Some(child),
            _ => {}
        }
    }

    let func_def = match func_def {
        Some(f) => f,
        None => return,
    };

    let fn_text = file.text_for_node(&func_def);
    let is_async = fn_text.trim_start().starts_with("async def");

    for decorator in &decorators {
        if let Some((app_var_name, http_method, path)) =
            extract_flask_route_decorator(file, *decorator)
        {
            let handler_name = func_def
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source_bytes).ok())
                .unwrap_or("unknown")
                .to_string();

            let body = match func_def.child_by_field_name("body") {
                Some(b) => b,
                None => return,
            };
            let has_try_except = body_has_try_except(body);

            let location = file.location_for_node(&decorated_def);
            let decorator_location = file.location_for_node(decorator);

            out.push(FlaskRoute {
                app_var_name,
                http_method,
                path,
                handler_name,
                is_async,
                has_try_except,
                location,
                decorator_location,
                body_start_byte: body.start_byte(),
                body_end_byte: body.end_byte(),
            });
            // Only the first matching route decorator per function.
            return;
        }
    }
}

/// Extract one `FlaskRoute` per HTTP-method handler from a Flask-smorest `MethodView` class.
///
/// Pattern:
/// ```python
/// @blp.route('/items')
/// class ItemList(MethodView):
///     def get(self): ...
///     def post(self): ...
/// ```
/// Each method (`get`, `post`, …) becomes its own `FlaskRoute` with the path from the
/// class-level `@blp.route(...)` decorator and the HTTP method inferred from the method name.
fn extract_flask_methodview_routes(
    file: &ParsedFile,
    decorated_def: Node,
    out: &mut Vec<FlaskRoute>,
) {
    let source_bytes = file.source.as_bytes();

    let mut decorators = Vec::new();
    let mut class_def: Option<Node> = None;

    let mut cursor = decorated_def.walk();
    for child in decorated_def.children(&mut cursor) {
        match child.kind() {
            "decorator" => decorators.push(child),
            "class_definition" => class_def = Some(child),
            _ => {}
        }
    }

    let class_def = match class_def {
        Some(c) => c,
        None => return,
    };

    // Find the first @blp.route(...) decorator on this class.
    let mut route_info: Option<(String, String)> = None; // (app_var_name, path)
    for decorator in &decorators {
        if let Some((app_var_name, _method, path)) = extract_flask_route_decorator(file, *decorator)
        {
            route_info = Some((app_var_name, path));
            break;
        }
    }

    let (app_var_name, path) = match route_info {
        Some(r) => r,
        None => return,
    };

    // Walk the class body and collect method definitions whose names map to HTTP methods.
    let class_body = match class_def.child_by_field_name("body") {
        Some(b) => b,
        None => return,
    };

    let class_location = file.location_for_node(&decorated_def);

    let mut body_cursor = class_body.walk();
    for child in class_body.children(&mut body_cursor) {
        // Methods can appear as plain `function_definition` or `decorated_definition`
        // (e.g. with @blp.arguments / @blp.response decorators).
        let method_node = match child.kind() {
            "function_definition" | "async_function_definition" => child,
            "decorated_definition" => {
                // Find the inner function_definition inside the decorated method.
                let mut inner: Option<Node> = None;
                let mut dc = child.walk();
                for n in child.children(&mut dc) {
                    if matches!(
                        n.kind(),
                        "function_definition" | "async_function_definition"
                    ) {
                        inner = Some(n);
                        break;
                    }
                }
                match inner {
                    Some(n) => n,
                    None => continue,
                }
            }
            _ => continue,
        };

        let method_name = match method_node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source_bytes).ok())
        {
            Some(n) => n,
            None => continue,
        };

        let http_method = match method_name.to_lowercase().as_str() {
            "get" => "GET",
            "post" => "POST",
            "put" => "PUT",
            "delete" => "DELETE",
            "patch" => "PATCH",
            "options" => "OPTIONS",
            "head" => "HEAD",
            _ => continue, // skip __init__, helper methods, etc.
        };

        let fn_text = file.text_for_node(&method_node);
        let is_async = fn_text.trim_start().starts_with("async def");

        let body = match method_node.child_by_field_name("body") {
            Some(b) => b,
            None => continue,
        };
        let has_try_except = body_has_try_except(body);

        // Use the class name as a prefix so handler_name is unique and readable.
        let class_name = class_def
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source_bytes).ok())
            .unwrap_or("Unknown");
        let handler_name = format!("{}.{}", class_name, method_name);

        // Use the first matching route decorator location for the decorator_location field.
        let decorator_location = decorators
            .first()
            .map(|d| file.location_for_node(d))
            .unwrap_or_else(|| class_location.clone());

        out.push(FlaskRoute {
            app_var_name: app_var_name.clone(),
            http_method: http_method.to_string(),
            path: path.clone(),
            handler_name,
            is_async,
            has_try_except,
            location: class_location.clone(),
            decorator_location,
            body_start_byte: body.start_byte(),
            body_end_byte: body.end_byte(),
        });
    }
}

fn extract_flask_route_decorator(
    file: &ParsedFile,
    decorator: Node,
) -> Option<(String, String, String)> {
    let source_bytes = file.source.as_bytes();

    let mut cursor = decorator.walk();
    for child in decorator.children(&mut cursor) {
        if child.kind() == "call" {
            let func = child.child_by_field_name("function")?;
            if func.kind() != "attribute" {
                continue;
            }

            let object = func.child_by_field_name("object")?;
            let attr = func.child_by_field_name("attribute")?;

            let app_var_name = object.utf8_text(source_bytes).ok()?.to_string();
            let method_name = attr.utf8_text(source_bytes).ok()?;

            let args = child.child_by_field_name("arguments")?;

            let http_method = match method_name.to_lowercase().as_str() {
                "get" => "GET".to_string(),
                "post" => "POST".to_string(),
                "put" => "PUT".to_string(),
                "delete" => "DELETE".to_string(),
                "patch" => "PATCH".to_string(),
                "options" => "OPTIONS".to_string(),
                "head" => "HEAD".to_string(),
                // @app.route() — inspect the `methods` kwarg to get the real method(s)
                "route" => extract_route_methods(file, args),
                _ => return None,
            };

            let path = extract_first_string_arg(file, args)?;

            return Some((app_var_name, http_method, path));
        }
    }

    None
}

/// Extract HTTP methods from the `methods=[...]` keyword argument of `@app.route()`.
/// Returns the single method if only one is listed, `"ANY"` if multiple are given,
/// or `"GET"` as Flask's default when the kwarg is absent.
fn extract_route_methods(file: &ParsedFile, args: Node) -> String {
    let source_bytes = file.source.as_bytes();

    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() == "keyword_argument" {
            let key = child.child_by_field_name("name");
            let value = child.child_by_field_name("value");

            let is_methods_kwarg = key
                .and_then(|k| k.utf8_text(source_bytes).ok())
                .map(|k| k == "methods")
                .unwrap_or(false);

            if !is_methods_kwarg {
                continue;
            }

            // value should be a list literal like ['GET', 'POST']
            if let Some(list_node) = value {
                if list_node.kind() == "list" {
                    let mut methods: Vec<String> = Vec::new();
                    let mut list_cursor = list_node.walk();
                    for item in list_node.children(&mut list_cursor) {
                        if item.kind() == "string" {
                            if let Ok(text) = item.utf8_text(source_bytes) {
                                let method =
                                    text.trim_matches(|c| c == '"' || c == '\'').to_uppercase();
                                if !method.is_empty() {
                                    methods.push(method);
                                }
                            }
                        }
                    }
                    return match methods.len() {
                        0 => "GET".to_string(),
                        1 => methods.remove(0),
                        _ => "ANY".to_string(),
                    };
                }
            }
        }
    }

    // No `methods` kwarg — Flask defaults to GET only
    "GET".to_string()
}

fn collect_flask_error_handlers(file: &ParsedFile, node: Node, out: &mut Vec<FlaskErrorHandler>) {
    if node.kind() == "decorated_definition" {
        if let Some(handler) = extract_flask_error_handler(file, node) {
            out.push(handler);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_flask_error_handlers(file, child, out);
    }
}

fn extract_flask_error_handler(
    file: &ParsedFile,
    decorated_def: Node,
) -> Option<FlaskErrorHandler> {
    let source_bytes = file.source.as_bytes();

    let mut decorators = Vec::new();
    let mut func_def: Option<Node> = None;

    let mut cursor = decorated_def.walk();
    for child in decorated_def.children(&mut cursor) {
        match child.kind() {
            "decorator" => decorators.push(child),
            "function_definition" | "async_function_definition" => func_def = Some(child),
            _ => {}
        }
    }

    let func_def = func_def?;

    for decorator in &decorators {
        if let Some((app_var_name, error_code)) =
            extract_flask_errorhandler_decorator(file, *decorator)
        {
            let handler_name = func_def
                .child_by_field_name("name")
                .map(|n| n.utf8_text(source_bytes).ok())
                .flatten()
                .unwrap_or("unknown")
                .to_string();

            let location = file.location_for_node(&decorated_def);

            return Some(FlaskErrorHandler {
                app_var_name,
                error_code,
                handler_name,
                location,
            });
        }
    }

    None
}

fn extract_flask_errorhandler_decorator(
    file: &ParsedFile,
    decorator: Node,
) -> Option<(String, u32)> {
    let source_bytes = file.source.as_bytes();

    let mut cursor = decorator.walk();
    for child in decorator.children(&mut cursor) {
        if child.kind() == "call" {
            let func = child.child_by_field_name("function")?;
            if func.kind() != "attribute" {
                continue;
            }

            let object = func.child_by_field_name("object")?;
            let attr = func.child_by_field_name("attribute")?;

            let app_var_name = object.utf8_text(source_bytes).ok()?.to_string();
            let method_name = attr.utf8_text(source_bytes).ok()?;

            if method_name != "errorhandler" {
                continue;
            }

            let args = child.child_by_field_name("arguments")?;
            let error_code = extract_first_int_arg(file, args)?;

            return Some((app_var_name, error_code));
        }
    }

    None
}

fn extract_first_string_arg(file: &ParsedFile, args: Node) -> Option<String> {
    let source_bytes = file.source.as_bytes();

    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        match child.kind() {
            "string" => {
                let text = child.utf8_text(source_bytes).ok()?;
                let path = text.trim_matches(|c| c == '"' || c == '\'');
                return Some(path.to_string());
            }
            _ => {}
        }
    }

    None
}

fn extract_first_int_arg(file: &ParsedFile, args: Node) -> Option<u32> {
    let source_bytes = file.source.as_bytes();

    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        match child.kind() {
            "integer" => {
                let text = child.utf8_text(source_bytes).ok()?;
                return text.parse().ok();
            }
            _ => {}
        }
    }

    None
}

fn body_has_try_except(body: Node) -> bool {
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "try_statement" {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Flask-RESTful / custom action_route pattern
// ---------------------------------------------------------------------------
//
// Supports codebases that define routes through a two-level convention:
//
//   Step 1 – a controller class is registered to a base path via an
//   endpoint-level class decorator:
//
//       endpoint = Endpoint("name")
//
//       @endpoint.route("/base")
//       class MyController(BaseController):
//           pass
//
//   Step 2 – individual handlers are attached to the controller via a
//   classmethod decorator, always the outermost decorator on the handler
//   function (innermost in tree-sitter's child list = listed first):
//
//       @MyController.action_route("/sub", methods=["GET", "POST"])
//       @inject_auth          # any number of inner decorators (ignored)
//       def handler(...):
//           ...
//
// We also detect the standard flask-restful pattern where `Resource`
// subclasses are decorated directly with `@api.resource("/path")`.
//
// The full route path is formed by joining the class base path with the
// action_route sub-path: "/base" + "/sub" → "/base/sub".

/// Maps a class name to the base path registered via `@endpoint.route("/base")`.
/// Returns an empty map if no such pattern exists in the file.
fn collect_action_route_class_bases(
    file: &ParsedFile,
    root: Node,
) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    collect_action_route_class_bases_node(file, root, &mut map);
    map
}

fn collect_action_route_class_bases_node(
    file: &ParsedFile,
    node: Node,
    map: &mut std::collections::HashMap<String, String>,
) {
    if node.kind() == "decorated_definition" {
        let source_bytes = file.source.as_bytes();

        let mut decorators = Vec::new();
        let mut class_def: Option<Node> = None;

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "decorator" => decorators.push(child),
                "class_definition" => class_def = Some(child),
                _ => {}
            }
        }

        if let Some(class_node) = class_def {
            // Try each decorator for the `@something.route("/path")` shape.
            for dec in &decorators {
                if let Some(base_path) = extract_endpoint_route_path(file, *dec) {
                    let class_name = class_node
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(source_bytes).ok())
                        .unwrap_or("")
                        .to_string();
                    if !class_name.is_empty() {
                        map.insert(class_name, base_path);
                        break;
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_action_route_class_bases_node(file, child, map);
    }
}

/// Extracts the path string from a `@something.route("/path")` decorator.
/// Returns `None` if the decorator doesn't match the shape.
fn extract_endpoint_route_path(file: &ParsedFile, decorator: Node) -> Option<String> {
    let source_bytes = file.source.as_bytes();

    let mut cursor = decorator.walk();
    for child in decorator.children(&mut cursor) {
        if child.kind() != "call" {
            continue;
        }
        let func = child.child_by_field_name("function")?;
        if func.kind() != "attribute" {
            continue;
        }
        let attr = func.child_by_field_name("attribute")?;
        let method = attr.utf8_text(source_bytes).ok()?;
        if method != "route" {
            continue;
        }
        let args = child.child_by_field_name("arguments")?;
        return extract_first_string_arg(file, args);
    }
    None
}

/// Collect `FlaskRoute` entries produced by `@ClassName.action_route("/sub", methods=[...])`.
///
/// Requires `class_bases` — a map from class name to its registered base path
/// (built by `collect_action_route_class_bases`).
fn collect_action_route_handlers(
    file: &ParsedFile,
    root: Node,
    class_bases: &std::collections::HashMap<String, String>,
    out: &mut Vec<FlaskRoute>,
) {
    collect_action_route_handlers_node(file, root, class_bases, out);
}

fn collect_action_route_handlers_node(
    file: &ParsedFile,
    node: Node,
    class_bases: &std::collections::HashMap<String, String>,
    out: &mut Vec<FlaskRoute>,
) {
    if node.kind() == "decorated_definition" {
        extract_action_route_handler(file, node, class_bases, out);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_action_route_handlers_node(file, child, class_bases, out);
    }
}

fn extract_action_route_handler(
    file: &ParsedFile,
    decorated_def: Node,
    class_bases: &std::collections::HashMap<String, String>,
    out: &mut Vec<FlaskRoute>,
) {
    let source_bytes = file.source.as_bytes();

    let mut decorators = Vec::new();
    let mut func_def: Option<Node> = None;

    let mut cursor = decorated_def.walk();
    for child in decorated_def.children(&mut cursor) {
        match child.kind() {
            "decorator" => decorators.push(child),
            "function_definition" | "async_function_definition" => func_def = Some(child),
            _ => {}
        }
    }

    let func_def = match func_def {
        Some(f) => f,
        None => return,
    };

    // The outermost decorator is always listed first in `decorators`.
    // We scan all decorators and take the first that matches `action_route`.
    for decorator in &decorators {
        if let Some((class_name, sub_path, http_method)) =
            extract_action_route_decorator(file, *decorator)
        {
            // Look up the base path for this controller class.
            let base_path = match class_bases.get(&class_name) {
                Some(p) => p.trim_end_matches('/').to_string(),
                // If there's no registered base path, use the sub-path directly.
                None => String::new(),
            };
            let full_path = if sub_path.starts_with('/') {
                format!("{}{}", base_path, sub_path)
            } else {
                format!("{}/{}", base_path, sub_path)
            };

            let handler_name = func_def
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source_bytes).ok())
                .unwrap_or("unknown")
                .to_string();

            let fn_text = file.text_for_node(&func_def);
            let is_async = fn_text.trim_start().starts_with("async def");

            let body = match func_def.child_by_field_name("body") {
                Some(b) => b,
                None => return,
            };
            let has_try_except = body_has_try_except(body);

            let location = file.location_for_node(&decorated_def);
            let decorator_location = file.location_for_node(decorator);

            out.push(FlaskRoute {
                app_var_name: class_name,
                http_method,
                path: full_path,
                handler_name,
                is_async,
                has_try_except,
                location,
                decorator_location,
                body_start_byte: body.start_byte(),
                body_end_byte: body.end_byte(),
            });
            // Stop at first matching action_route decorator.
            return;
        }
    }
}

/// Extract `(class_name, sub_path, http_method)` from `@ClassName.action_route("/sub", methods=["GET"])`.
///
/// Returns `None` if the decorator doesn't match.
fn extract_action_route_decorator(
    file: &ParsedFile,
    decorator: Node,
) -> Option<(String, String, String)> {
    let source_bytes = file.source.as_bytes();

    let mut cursor = decorator.walk();
    for child in decorator.children(&mut cursor) {
        if child.kind() != "call" {
            continue;
        }
        let func = child.child_by_field_name("function")?;
        if func.kind() != "attribute" {
            continue;
        }

        let object = func.child_by_field_name("object")?;
        let attr = func.child_by_field_name("attribute")?;

        // Must be `ClassName.action_route`
        if attr.utf8_text(source_bytes).ok()? != "action_route" {
            continue;
        }

        let class_name = object.utf8_text(source_bytes).ok()?.to_string();
        let args = child.child_by_field_name("arguments")?;

        // First positional arg is the sub-path (named `rule` in the signature,
        // but passed positionally in practice).
        let sub_path = extract_first_string_arg(file, args)?;

        // `methods=[...]` kwarg → same logic as @app.route().
        let http_method = extract_route_methods(file, args);

        return Some((class_name, sub_path, http_method));
    }
    None
}

// ---------------------------------------------------------------------------
// Flask config setting collection
// ---------------------------------------------------------------------------
//
// Recognises two factory-pattern idioms in addition to bare module-level
// assignments (which are handled separately via `py.assignments`):
//
//   1. Subscript assignment:
//      `app.config['SECRET_KEY'] = "value"`
//      AST: expression_statement → assignment
//           left  = subscript  (object=attribute "app.config", subscript=string "'SECRET_KEY'")
//           right = <value>
//
//   2. config.update() call:
//      `app.config.update(SESSION_COOKIE_SECURE=False, PERMANENT_SESSION_LIFETIME=3600)`
//      AST: call
//           function  = attribute "app.config.update"
//           arguments = argument_list with keyword_argument nodes

fn collect_flask_config_settings(file: &ParsedFile, node: Node, out: &mut Vec<FlaskConfigSetting>) {
    match node.kind() {
        // Pattern 1: app.config['KEY'] = value
        "assignment" => {
            extract_config_subscript_assignment(file, node, out);
        }
        // Pattern 2: app.config.update(KEY=value, ...)
        "call" => {
            extract_config_update_call(file, node, out);
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_flask_config_settings(file, child, out);
    }
}

/// Handles `app.config['SECRET_KEY'] = "value"`.
fn extract_config_subscript_assignment(
    file: &ParsedFile,
    node: Node,
    out: &mut Vec<FlaskConfigSetting>,
) {
    let source_bytes = file.source.as_bytes();

    let left = match node.child_by_field_name("left") {
        Some(n) => n,
        None => return,
    };
    let right = match node.child_by_field_name("right") {
        Some(n) => n,
        None => return,
    };

    // LHS must be a subscript: `app.config['KEY']`
    if left.kind() != "subscript" {
        return;
    }

    // The object of the subscript must be an attribute ending in `.config`
    let object = match left.child_by_field_name("value") {
        Some(n) => n,
        None => return,
    };
    if object.kind() != "attribute" {
        return;
    }
    let attr = match object.child_by_field_name("attribute") {
        Some(n) => n,
        None => return,
    };
    if attr.utf8_text(source_bytes).ok() != Some("config") {
        return;
    }

    // The subscript key must be a string literal.
    let subscript = match left.child_by_field_name("subscript") {
        Some(n) => n,
        None => return,
    };
    if subscript.kind() != "string" {
        return;
    }
    let raw_key = match subscript.utf8_text(source_bytes).ok() {
        Some(s) => s,
        None => return,
    };
    let key = raw_key.trim_matches(|c| c == '"' || c == '\'').to_string();
    if key.is_empty() {
        return;
    }

    let value_repr = file.text_for_node(&right);
    let location = file.location_for_node(&node);

    out.push(FlaskConfigSetting {
        key,
        value_repr,
        location,
    });
}

/// Handles `app.config.update(SESSION_COOKIE_SECURE=False, ...)`.
fn extract_config_update_call(file: &ParsedFile, node: Node, out: &mut Vec<FlaskConfigSetting>) {
    let source_bytes = file.source.as_bytes();

    // The function being called must be an attribute expression.
    let func = match node.child_by_field_name("function") {
        Some(n) => n,
        None => return,
    };
    if func.kind() != "attribute" {
        return;
    }

    // The method name must be `update`.
    let method = match func.child_by_field_name("attribute") {
        Some(n) => n,
        None => return,
    };
    if method.utf8_text(source_bytes).ok() != Some("update") {
        return;
    }

    // The receiver must itself be an attribute whose attribute part is `config`.
    let receiver = match func.child_by_field_name("object") {
        Some(n) => n,
        None => return,
    };
    if receiver.kind() != "attribute" {
        return;
    }
    let config_attr = match receiver.child_by_field_name("attribute") {
        Some(n) => n,
        None => return,
    };
    if config_attr.utf8_text(source_bytes).ok() != Some("config") {
        return;
    }

    // Walk the argument list and collect keyword arguments.
    let args = match node.child_by_field_name("arguments") {
        Some(n) => n,
        None => return,
    };

    let location = file.location_for_node(&node);
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if child.kind() != "keyword_argument" {
            continue;
        }
        let key_node = match child.child_by_field_name("name") {
            Some(n) => n,
            None => continue,
        };
        let value_node = match child.child_by_field_name("value") {
            Some(n) => n,
            None => continue,
        };
        let key = match key_node.utf8_text(source_bytes).ok() {
            Some(k) => k.to_string(),
            None => continue,
        };
        let value_repr = file.text_for_node(&value_node);
        out.push(FlaskConfigSetting {
            key,
            value_repr,
            location: location.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_summarize_flask(source: &str) -> Option<FlaskFileSummary> {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let parsed = parse_python_file(FileId(1), &sf).expect("parsing should succeed");
        summarize_flask(&parsed)
    }

    #[test]
    fn detects_simple_flask_app() {
        let src = r#"
from flask import Flask

app = Flask(__name__)
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.apps.len(), 1);
        assert_eq!(summary.apps[0].var_name, "app");
    }

    #[test]
    fn detects_flask_app_with_different_name() {
        let src = r#"
from flask import Flask

my_app = Flask(__name__)
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.apps.len(), 1);
        assert_eq!(summary.apps[0].var_name, "my_app");
    }

    #[test]
    fn detects_flask_blueprint() {
        let src = r#"
from flask import Blueprint

users_bp = Blueprint('users', __name__)
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.blueprints.len(), 1);
        assert_eq!(summary.blueprints[0].var_name, "users_bp");
    }

    #[test]
    fn detects_flask_route() {
        let src = r#"
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello"
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].path, "/");
        assert_eq!(summary.routes[0].handler_name, "index");
    }

    #[test]
    fn detects_flask_route_with_methods() {
        let src = r#"
from flask import Flask

app = Flask(__name__)

@app.route('/users', methods=['GET', 'POST'])
def get_users():
    return "users"
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].path, "/users");
        // Multiple methods → "ANY"
        assert_eq!(summary.routes[0].http_method, "ANY");
    }

    #[test]
    fn detects_flask_route_single_method_kwarg() {
        let src = r#"
from flask import Flask

app = Flask(__name__)

@app.route('/submit', methods=['POST'])
def submit():
    return "ok"
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        assert_eq!(summary.routes[0].path, "/submit");
        assert_eq!(summary.routes[0].http_method, "POST");
    }

    #[test]
    fn detects_flask_route_default_get() {
        let src = r#"
from flask import Flask

app = Flask(__name__)

@app.route('/health')
def health():
    return "ok"
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        assert_eq!(summary.routes[0].http_method, "GET");
    }

    #[test]
    fn detects_flask_error_handler() {
        let src = r#"
from flask import Flask

app = Flask(__name__)

@app.errorhandler(404)
def not_found(error):
    return "Not found"
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.error_handlers.len(), 1);
        assert_eq!(summary.error_handlers[0].error_code, 404);
    }

    #[test]
    fn detects_multiple_routes() {
        let src = r#"
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello"

@app.route('/users')
def users():
    return "users"
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 2);
    }

    #[test]
    fn detects_blueprint_route() {
        let src = r#"
from flask import Flask, Blueprint

api = Blueprint('api', __name__)

@api.route('/items')
def list_items():
    return "items"
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.blueprints.len(), 1);
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].path, "/items");
    }

    #[test]
    fn does_not_detect_django_model() {
        let src = r#"
from django.db import models

class User(models.Model):
    name = models.CharField(max_length=100)
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_none());
    }

    #[test]
    fn does_not_detect_fastapi_app() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_none());
    }

    #[test]
    fn handles_empty_file() {
        let summary = parse_and_summarize_flask("");
        assert!(summary.is_none());
    }

    #[test]
    fn handles_file_with_only_imports() {
        let src = r#"
from flask import Flask, Blueprint
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_none());
    }

    // ==================== Flask-smorest / MethodView Tests ====================

    #[test]
    fn detects_smorest_blueprint() {
        let src = r#"
from flask_smorest import Blueprint

blp = Blueprint('pets', __name__, description='Operations on pets')
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.blueprints.len(), 1);
        assert_eq!(summary.blueprints[0].var_name, "blp");
        assert_eq!(summary.blueprints[0].import_name, "pets");
    }

    #[test]
    fn detects_methodview_get_route() {
        let src = r#"
from flask_smorest import Blueprint
from flask.views import MethodView

blp = Blueprint('items', __name__)

@blp.route('/items')
class ItemList(MethodView):
    def get(self):
        return []
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].path, "/items");
        assert_eq!(summary.routes[0].http_method, "GET");
        assert_eq!(summary.routes[0].handler_name, "ItemList.get");
        assert_eq!(summary.routes[0].app_var_name, "blp");
    }

    #[test]
    fn detects_methodview_multiple_methods() {
        let src = r#"
from flask_smorest import Blueprint
from flask.views import MethodView

blp = Blueprint('items', __name__)

@blp.route('/items')
class ItemList(MethodView):
    def get(self):
        return []

    def post(self):
        return {}, 201
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        // Each HTTP method on the class becomes its own route entry.
        assert_eq!(summary.routes.len(), 2);
        let methods: Vec<&str> = summary
            .routes
            .iter()
            .map(|r| r.http_method.as_str())
            .collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"POST"));
        // Both routes share the same path.
        assert!(summary.routes.iter().all(|r| r.path == "/items"));
    }

    #[test]
    fn detects_methodview_all_http_verbs() {
        let src = r#"
from flask_smorest import Blueprint
from flask.views import MethodView

blp = Blueprint('resource', __name__)

@blp.route('/resource/<int:resource_id>')
class Resource(MethodView):
    def get(self, resource_id):
        pass

    def put(self, resource_id):
        pass

    def patch(self, resource_id):
        pass

    def delete(self, resource_id):
        pass
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 4);
        let methods: Vec<&str> = summary
            .routes
            .iter()
            .map(|r| r.http_method.as_str())
            .collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"PUT"));
        assert!(methods.contains(&"PATCH"));
        assert!(methods.contains(&"DELETE"));
    }

    #[test]
    fn methodview_skips_non_http_methods() {
        let src = r#"
from flask_smorest import Blueprint
from flask.views import MethodView

blp = Blueprint('items', __name__)

@blp.route('/items')
class ItemList(MethodView):
    def get(self):
        return self._fetch()

    def _fetch(self):
        return []

    def __init__(self):
        super().__init__()
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        // Only `get` should be picked up; `_fetch` and `__init__` are not HTTP methods.
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].http_method, "GET");
    }

    #[test]
    fn detects_methodview_async_method() {
        let src = r#"
from flask_smorest import Blueprint
from flask.views import MethodView

blp = Blueprint('items', __name__)

@blp.route('/items')
class ItemList(MethodView):
    async def get(self):
        return []
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert!(summary.routes[0].is_async);
    }

    #[test]
    fn detects_methodview_with_try_except() {
        let src = r#"
from flask_smorest import Blueprint
from flask.views import MethodView

blp = Blueprint('items', __name__)

@blp.route('/items/<int:item_id>')
class Item(MethodView):
    def get(self, item_id):
        try:
            return fetch(item_id)
        except Exception:
            return {}, 500
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert!(summary.routes[0].has_try_except);
    }

    #[test]
    fn detects_mixed_function_and_methodview_routes() {
        let src = r#"
from flask import Flask
from flask_smorest import Blueprint
from flask.views import MethodView

app = Flask(__name__)
blp = Blueprint('items', __name__)

@app.route('/health')
def health():
    return 'ok'

@blp.route('/items')
class ItemList(MethodView):
    def get(self):
        return []

    def post(self):
        return {}, 201
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        // 1 function-based + 2 class-based
        assert_eq!(summary.routes.len(), 3);
        let paths: Vec<&str> = summary.routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"/health"));
        assert!(paths.iter().filter(|&&p| p == "/items").count() == 2);
    }

    #[test]
    fn detects_methodview_decorated_methods() {
        // Methods decorated with @blp.arguments / @blp.response should still be detected.
        let src = r#"
from flask_smorest import Blueprint
from flask.views import MethodView

blp = Blueprint('items', __name__)

@blp.route('/items')
class ItemList(MethodView):
    @blp.response(200)
    def get(self):
        return []

    @blp.arguments(schema=None)
    @blp.response(201)
    def post(self):
        return {}, 201
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 2);
        let methods: Vec<&str> = summary
            .routes
            .iter()
            .map(|r| r.http_method.as_str())
            .collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"POST"));
    }

    // ==================== Application Factory Pattern Tests ====================

    #[test]
    fn factory_routes_are_detected() {
        let src = r#"
from flask import Flask

def create_app():
    app = Flask(__name__)

    @app.route('/health')
    def health():
        return 'ok'

    @app.route('/users', methods=['POST'])
    def create_user():
        return {}, 201

    return app
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.apps.len(), 1);
        assert_eq!(summary.routes.len(), 2);
        let paths: Vec<&str> = summary.routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"/health"));
        assert!(paths.contains(&"/users"));
    }

    #[test]
    fn factory_config_subscript_assignment_detected() {
        let src = r#"
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hardcoded-secret'
    app.config['SESSION_COOKIE_SECURE'] = False
    return app
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.config_settings.len(), 2);

        let secret = summary
            .config_settings
            .iter()
            .find(|c| c.key == "SECRET_KEY")
            .unwrap();
        assert_eq!(secret.value_repr, "'hardcoded-secret'");

        let cookie = summary
            .config_settings
            .iter()
            .find(|c| c.key == "SESSION_COOKIE_SECURE")
            .unwrap();
        assert_eq!(cookie.value_repr, "False");
    }

    #[test]
    fn factory_config_update_kwargs_detected() {
        let src = r#"
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.update(
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=False,
        PERMANENT_SESSION_LIFETIME=9999999,
    )
    return app
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.config_settings.len(), 3);

        let keys: Vec<&str> = summary
            .config_settings
            .iter()
            .map(|c| c.key.as_str())
            .collect();
        assert!(keys.contains(&"SESSION_COOKIE_SECURE"));
        assert!(keys.contains(&"SESSION_COOKIE_HTTPONLY"));
        assert!(keys.contains(&"PERMANENT_SESSION_LIFETIME"));
    }

    #[test]
    fn factory_config_mixed_patterns_detected() {
        // Both subscript and update() in the same factory.
        let src = r#"
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'top-secret'
    app.config.update(SESSION_COOKIE_SECURE=False)
    return app
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let cfg = summary.unwrap().config_settings;
        assert_eq!(cfg.len(), 2);
        assert!(cfg.iter().any(|c| c.key == "SECRET_KEY"));
        assert!(cfg.iter().any(|c| c.key == "SESSION_COOKIE_SECURE"));
    }

    #[test]
    fn non_config_attribute_assignments_not_collected() {
        // `app.something_else['KEY'] = value` should not be collected.
        let src = r#"
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.extensions['cache'] = 'value'
    return app
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        assert!(summary.unwrap().config_settings.is_empty());
    }

    #[test]
    fn factory_blueprint_registration_detected() {
        let src = r#"
from flask import Flask, Blueprint

users_bp = Blueprint('users', __name__)

def create_app():
    app = Flask(__name__)
    app.register_blueprint(users_bp)
    return app
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.apps.len(), 1);
        assert_eq!(summary.blueprints.len(), 1);
    }

    #[test]
    fn factory_methodview_routes_detected() {
        let src = r#"
from flask import Flask
from flask_smorest import Blueprint
from flask.views import MethodView

def create_app():
    app = Flask(__name__)
    blp = Blueprint('items', __name__)

    @blp.route('/items')
    class ItemList(MethodView):
        def get(self):
            return []

        def post(self):
            return {}, 201

    app.register_blueprint(blp)
    return app
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 2);
        let methods: Vec<&str> = summary
            .routes
            .iter()
            .map(|r| r.http_method.as_str())
            .collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"POST"));
    }

    // ==================== action_route / Custom BaseController Pattern Tests ====================

    #[test]
    fn action_route_simple_get() {
        // Most basic: single class, single handler.
        let src = r#"
from flask_restful import Resource

class BaseController(Resource):
    @classmethod
    def action_route(cls, rule: str, **options):
        pass

endpoint = Endpoint("users")

@endpoint.route("/users")
class UserController(BaseController):
    pass

@UserController.action_route("/", methods=["GET"])
def list_users():
    return []
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some(), "should detect something");
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].path, "/users/");
        assert_eq!(summary.routes[0].http_method, "GET");
        assert_eq!(summary.routes[0].handler_name, "list_users");
        assert_eq!(summary.routes[0].app_var_name, "UserController");
    }

    #[test]
    fn action_route_multiple_methods_on_same_subpath() {
        let src = r#"
endpoint = Endpoint("items")

@endpoint.route("/items")
class ItemController(BaseController):
    pass

@ItemController.action_route("/", methods=["GET"])
def list_items():
    return []

@ItemController.action_route("/", methods=["POST"])
def create_item():
    return {}, 201
"#;
        let summary = parse_and_summarize_flask(src);
        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.routes.len(), 2);

        let get_route = summary
            .routes
            .iter()
            .find(|r| r.http_method == "GET")
            .unwrap();
        assert_eq!(get_route.path, "/items/");

        let post_route = summary
            .routes
            .iter()
            .find(|r| r.http_method == "POST")
            .unwrap();
        assert_eq!(post_route.path, "/items/");
    }

    #[test]
    fn action_route_sub_path_joined_with_base() {
        let src = r#"
endpoint = Endpoint("orders")

@endpoint.route("/orders")
class OrderController(BaseController):
    pass

@OrderController.action_route("/<int:order_id>", methods=["GET"])
def get_order(order_id):
    return {}

@OrderController.action_route("/<int:order_id>", methods=["DELETE"])
def delete_order(order_id):
    return {}, 204
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        assert_eq!(summary.routes.len(), 2);
        for route in &summary.routes {
            assert_eq!(route.path, "/orders/<int:order_id>");
        }
    }

    #[test]
    fn action_route_with_inner_decorators_ignored() {
        // action_route is outermost; inner @inject_auth etc. are irrelevant.
        let src = r#"
endpoint = Endpoint("secure")

@endpoint.route("/secure")
class SecureController(BaseController):
    pass

@SecureController.action_route("/data", methods=["GET"])
@inject_auth
@log_request
def get_data():
    return {}
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].path, "/secure/data");
        assert_eq!(summary.routes[0].http_method, "GET");
        assert_eq!(summary.routes[0].handler_name, "get_data");
    }

    #[test]
    fn action_route_default_method_is_get() {
        // No `methods` kwarg → defaults to GET.
        let src = r#"
endpoint = Endpoint("health")

@endpoint.route("/health")
class HealthController(BaseController):
    pass

@HealthController.action_route("/check")
def health_check():
    return {"status": "ok"}
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].http_method, "GET");
        assert_eq!(summary.routes[0].path, "/health/check");
    }

    #[test]
    fn action_route_multiple_controllers() {
        // Two independent controllers, each with their own handlers.
        let src = r#"
endpoint = Endpoint("api")

@endpoint.route("/users")
class UserController(BaseController):
    pass

@endpoint.route("/products")
class ProductController(BaseController):
    pass

@UserController.action_route("/", methods=["GET"])
def list_users():
    return []

@ProductController.action_route("/", methods=["GET"])
def list_products():
    return []

@ProductController.action_route("/<int:id>", methods=["DELETE"])
def delete_product(id):
    return {}, 204
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        assert_eq!(summary.routes.len(), 3);

        let user_routes: Vec<_> = summary
            .routes
            .iter()
            .filter(|r| r.path.starts_with("/users"))
            .collect();
        assert_eq!(user_routes.len(), 1);

        let product_routes: Vec<_> = summary
            .routes
            .iter()
            .filter(|r| r.path.starts_with("/products"))
            .collect();
        assert_eq!(product_routes.len(), 2);
    }

    #[test]
    fn action_route_no_class_base_uses_subpath_directly() {
        // Handler uses action_route but no matching @endpoint.route class exists.
        // Path should just be the sub-path itself.
        let src = r#"
@OrphanController.action_route("/orphan", methods=["GET"])
def orphan_handler():
    return {}
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].path, "/orphan");
        assert_eq!(summary.routes[0].app_var_name, "OrphanController");
    }

    #[test]
    fn action_route_try_except_detected() {
        let src = r#"
endpoint = Endpoint("api")

@endpoint.route("/items")
class ItemController(BaseController):
    pass

@ItemController.action_route("/risky", methods=["POST"])
def risky_handler():
    try:
        return do_something()
    except Exception:
        return {}, 500
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert!(summary.routes[0].has_try_except);
    }

    #[test]
    fn action_route_async_handler_detected() {
        let src = r#"
endpoint = Endpoint("api")

@endpoint.route("/stream")
class StreamController(BaseController):
    pass

@StreamController.action_route("/events", methods=["GET"])
async def stream_events():
    return []
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        assert_eq!(summary.routes.len(), 1);
        assert!(summary.routes[0].is_async);
    }

    #[test]
    fn action_route_mixed_with_regular_flask_routes() {
        // A file that has both regular @app.route and action_route-style.
        let src = r#"
from flask import Flask

app = Flask(__name__)
endpoint = Endpoint("api")

@app.route("/health")
def health():
    return "ok"

@endpoint.route("/users")
class UserController(BaseController):
    pass

@UserController.action_route("/", methods=["GET"])
def list_users():
    return []
"#;
        let summary = parse_and_summarize_flask(src).unwrap();
        // One regular route + one action_route-based route.
        assert_eq!(summary.routes.len(), 2);
        let paths: Vec<&str> = summary.routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"/health"));
        assert!(paths.contains(&"/users/"));
    }
}
