use serde::{Deserialize, Serialize};
use tree_sitter::Node;

use crate::parse::ast::{AstLocation, ParsedFile};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaskFileSummary {
    pub apps: Vec<FlaskApp>,
    pub blueprints: Vec<FlaskBlueprint>,
    pub routes: Vec<FlaskRoute>,
    pub error_handlers: Vec<FlaskErrorHandler>,
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

pub fn summarize_flask(file: &ParsedFile) -> Option<FlaskFileSummary> {
    let root = file.tree.root_node();

    let mut apps = Vec::new();
    let mut blueprints = Vec::new();
    let mut routes = Vec::new();
    let mut error_handlers = Vec::new();

    collect_flask_apps(file, root, &mut apps);
    collect_flask_blueprints(file, root, &mut blueprints);
    collect_flask_routes(file, root, &mut routes);
    collect_flask_error_handlers(file, root, &mut error_handlers);

    if apps.is_empty() && blueprints.is_empty() && routes.is_empty() && error_handlers.is_empty() {
        return None;
    }

    Some(FlaskFileSummary {
        apps,
        blueprints,
        routes,
        error_handlers,
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
        if let Some(route) = extract_flask_route(file, node) {
            out.push(route);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_flask_routes(file, child, out);
    }
}

fn extract_flask_route(file: &ParsedFile, decorated_def: Node) -> Option<FlaskRoute> {
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

    let fn_text = file.text_for_node(&func_def);
    let is_async = fn_text.trim_start().starts_with("async def");

    for decorator in &decorators {
        if let Some((app_var_name, http_method, path)) =
            extract_flask_route_decorator(file, *decorator)
        {
            let handler_name = func_def
                .child_by_field_name("name")
                .map(|n| n.utf8_text(source_bytes).ok())
                .flatten()
                .unwrap_or("unknown")
                .to_string();

            let body = func_def.child_by_field_name("body")?;
            let has_try_except = body_has_try_except(body);

            let location = file.location_for_node(&decorated_def);
            let decorator_location = file.location_for_node(decorator);

            return Some(FlaskRoute {
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
        }
    }

    None
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
}
