// unfault-ignore: rust.println_in_lib
//! Shared terminal formatting helpers.

/// Maximum visible column width for all CLI output.
pub const COL_WIDTH: usize = 80;

/// Word-wrap `text` so each line fits within `col` visible characters.
///
/// The first line is prefixed with `first_indent`; continuation lines with
/// `cont_indent`. Returns one `String` per output line.
pub fn word_wrap(text: &str, first_indent: &str, cont_indent: &str, col: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = first_indent.to_string();

    for word in text.split_whitespace() {
        let at_indent = current == first_indent || current == cont_indent;
        let needed = if at_indent {
            current.len() + word.len()
        } else {
            current.len() + 1 + word.len()
        };

        if needed > col && !at_indent {
            lines.push(current);
            current = format!("{}{}", cont_indent, word);
        } else if at_indent {
            current.push_str(word);
        } else {
            current.push(' ');
            current.push_str(word);
        }
    }
    if !current.trim().is_empty() {
        lines.push(current);
    }
    lines
}

/// Truncate a plain string to `max` visible chars, appending `…` if cut.
pub fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        let cut: String = chars[..max.saturating_sub(1)].iter().collect();
        format!("{}…", cut)
    }
}
