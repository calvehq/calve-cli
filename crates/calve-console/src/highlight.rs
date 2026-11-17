//! Minimal syntax highlighting for diffs (console-ux §33.2). Token-level and forgiving: an
//! unknown file type or odd input just renders as plain text.

use ratatui::style::{Modifier, Style};
use ratatui::text::Span;

use crate::theme::Theme;

struct Syntax {
    keywords: &'static [&'static str],
    line_comment: &'static [&'static str],
}

fn syntax(path: &str) -> Option<Syntax> {
    let ext = path.rsplit('.').next().unwrap_or("");
    Some(match ext {
        "rs" => Syntax {
            keywords: &[
                "fn", "let", "mut", "pub", "use", "mod", "struct", "enum", "impl", "trait",
                "match", "if", "else", "for", "while", "loop", "return", "const", "static",
                "async", "await", "move", "self", "Self", "crate", "where", "type", "in", "as",
                "ref", "true", "false", "Some", "None", "Ok", "Err",
            ],
            line_comment: &["//"],
        },
        "go" => Syntax {
            keywords: &[
                "func",
                "var",
                "const",
                "type",
                "struct",
                "interface",
                "package",
                "import",
                "return",
                "if",
                "else",
                "for",
                "range",
                "go",
                "defer",
                "switch",
                "case",
                "map",
                "chan",
                "nil",
                "true",
                "false",
            ],
            line_comment: &["//"],
        },
        "py" => Syntax {
            keywords: &[
                "def", "class", "return", "if", "elif", "else", "for", "while", "import", "from",
                "as", "with", "try", "except", "finally", "raise", "lambda", "yield", "None",
                "True", "False", "and", "or", "not", "in", "is", "async", "await",
            ],
            line_comment: &["#"],
        },
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => Syntax {
            keywords: &[
                "function",
                "const",
                "let",
                "var",
                "return",
                "if",
                "else",
                "for",
                "while",
                "import",
                "export",
                "from",
                "class",
                "new",
                "async",
                "await",
                "interface",
                "type",
                "extends",
                "null",
                "undefined",
                "true",
                "false",
            ],
            line_comment: &["//"],
        },
        "java" | "kt" | "c" | "h" | "cc" | "cpp" | "hpp" | "cxx" => Syntax {
            keywords: &[
                "class",
                "public",
                "private",
                "protected",
                "static",
                "final",
                "void",
                "int",
                "long",
                "char",
                "bool",
                "return",
                "if",
                "else",
                "for",
                "while",
                "new",
                "struct",
                "include",
                "const",
                "true",
                "false",
                "null",
                "nullptr",
            ],
            line_comment: &["//"],
        },
        "sh" | "bash" | "toml" | "yaml" | "yml" => Syntax {
            keywords: &[
                "if", "then", "else", "fi", "for", "do", "done", "case", "esac", "function",
                "local", "export", "true", "false",
            ],
            line_comment: &["#"],
        },
        "tf" | "hcl" => Syntax {
            keywords: &[
                "resource", "variable", "output", "module", "provider", "data", "locals", "true",
                "false",
            ],
            line_comment: &["#", "//"],
        },
        _ => return None,
    })
}

/// Splits one line into styled spans on top of `base` (the diff line style).
pub fn spans(path: &str, text: &str, base: Style, theme: &Theme) -> Vec<Span<'static>> {
    let Some(syntax) = syntax(path) else {
        return vec![Span::styled(text.to_owned(), base)];
    };
    let keyword = base.fg(theme.accent).add_modifier(Modifier::BOLD);
    let string = base.fg(theme.review);
    let comment = base.fg(theme.muted).add_modifier(Modifier::ITALIC);
    let number = base.fg(theme.running);
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut plain = String::new();
    let flush = |plain: &mut String, out: &mut Vec<Span<'static>>| {
        if !plain.is_empty() {
            out.push(Span::styled(std::mem::take(plain), base));
        }
    };
    while i < chars.len() {
        let rest: String = chars[i..].iter().collect();
        if syntax
            .line_comment
            .iter()
            .any(|marker| rest.starts_with(marker))
        {
            flush(&mut plain, &mut out);
            out.push(Span::styled(rest, comment));
            return out;
        }
        let c = chars[i];
        if c == '"' || c == '\'' {
            flush(&mut plain, &mut out);
            let mut j = i + 1;
            while j < chars.len() && chars[j] != c {
                j += if chars[j] == '\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(chars.len());
            out.push(Span::styled(
                chars[i..end].iter().collect::<String>(),
                string,
            ));
            i = end;
            continue;
        }
        if c.is_ascii_digit() && (i == 0 || !chars[i - 1].is_alphanumeric()) {
            flush(&mut plain, &mut out);
            let mut j = i;
            while j < chars.len()
                && (chars[j].is_ascii_alphanumeric() || chars[j] == '_' || chars[j] == '.')
            {
                j += 1;
            }
            out.push(Span::styled(chars[i..j].iter().collect::<String>(), number));
            i = j;
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let mut j = i;
            while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            let word: String = chars[i..j].iter().collect();
            if syntax.keywords.contains(&word.as_str()) {
                flush(&mut plain, &mut out);
                out.push(Span::styled(word, keyword));
            } else {
                plain.push_str(&word);
            }
            i = j;
            continue;
        }
        plain.push(c);
        i += 1;
    }
    flush(&mut plain, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::ThemeName;

    #[test]
    fn tokens_are_split_and_text_is_preserved() {
        let theme = Theme::new(ThemeName::Dark);
        let line = r#"pub const X: u64 = 30; // note "quoted""#;
        let parts = spans("a.rs", line, Style::default(), &theme);
        let joined: String = parts.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(joined, line);
        assert!(parts.iter().any(|s| s.content == "pub"));
        assert!(parts.iter().any(|s| s.content == "30"));
        assert!(parts.last().unwrap().content.starts_with("// note"));
        assert_eq!(spans("a.unknown", line, Style::default(), &theme).len(), 1);
    }
}
