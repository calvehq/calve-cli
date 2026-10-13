//! Deterministic Project resource ignore rules, independent of Git.

use std::fs;
use std::path::{Component, Path};

use serde_json::{Value, json};

use crate::{Error, Project, Result};

const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_RULES: usize = 512;
const MAX_PATTERN_CHARS: usize = 512;

#[derive(Clone, Copy)]
enum Token {
    Literal(char),
    One,
    Star,
    GlobStar,
    GlobStarDir,
}

struct Rule {
    tokens: Vec<Token>,
    text: String,
    source: &'static str,
    line: Option<usize>,
    anchored: bool,
    directory: bool,
    ignored: bool,
}

pub(crate) struct IgnoreRules {
    rules: Vec<Rule>,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

fn parse_tokens(pattern: &str) -> Result<Vec<Token>> {
    let mut chars = pattern.chars().peekable();
    let mut out = Vec::new();
    while let Some(ch) = chars.next() {
        out.push(match ch {
            '\\' => Token::Literal(
                chars
                    .next()
                    .ok_or_else(|| invalid("trailing escape in .calveignore"))?,
            ),
            '?' => Token::One,
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                if chars.peek() == Some(&'/') {
                    chars.next();
                    Token::GlobStarDir
                } else {
                    Token::GlobStar
                }
            }
            '*' => Token::Star,
            _ => Token::Literal(ch),
        });
    }
    Ok(out)
}

fn parse_rule(raw: &str, line: usize) -> Result<Option<Rule>> {
    let raw = raw.trim_end_matches('\r');
    if raw.is_empty() || raw.starts_with('#') {
        return Ok(None);
    }
    let (ignored, text) = if let Some(rest) = raw.strip_prefix('!') {
        (false, rest)
    } else {
        (true, raw)
    };
    let anchored = text.starts_with('/');
    let text = text.strip_prefix('/').unwrap_or(text);
    let directory = text.ends_with('/') && !text.ends_with("\\/");
    let text = if directory {
        &text[..text.len() - 1]
    } else {
        text
    };
    if text.is_empty() || text.chars().count() > MAX_PATTERN_CHARS {
        return Err(invalid(format!(
            "invalid .calveignore pattern on line {line}"
        )));
    }
    Ok(Some(Rule {
        tokens: parse_tokens(text)?,
        text: raw.into(),
        source: ".calveignore",
        line: Some(line),
        anchored,
        directory,
        ignored,
    }))
}

fn matches_tokens(tokens: &[Token], path: &str) -> bool {
    let chars: Vec<char> = path.chars().collect();
    let mut states = vec![false; chars.len() + 1];
    states[0] = true;
    for token in tokens {
        let mut next = vec![false; chars.len() + 1];
        match token {
            Token::Literal(expected) => {
                for i in 0..chars.len() {
                    if states[i] && chars[i] == *expected {
                        next[i + 1] = true;
                    }
                }
            }
            Token::One => {
                for i in 0..chars.len() {
                    if states[i] && chars[i] != '/' {
                        next[i + 1] = true;
                    }
                }
            }
            Token::Star | Token::GlobStar => {
                next.clone_from(&states);
                for i in 0..chars.len() {
                    if next[i] && (matches!(token, Token::GlobStar) || chars[i] != '/') {
                        next[i + 1] = true;
                    }
                }
            }
            Token::GlobStarDir => {
                next.clone_from(&states);
                let mut reachable = false;
                for i in 0..chars.len() {
                    reachable |= states[i];
                    if reachable && chars[i] == '/' {
                        next[i + 1] = true;
                    }
                }
            }
        }
        states = next;
    }
    states[chars.len()]
}

impl Rule {
    fn matches(&self, path: &str, is_dir: bool) -> bool {
        let mut candidates = vec![(path, is_dir)];
        for (index, byte) in path.bytes().enumerate() {
            if byte == b'/' {
                candidates.push((&path[..index], true));
            }
        }
        candidates.into_iter().any(|(candidate, directory)| {
            if self.directory && !directory {
                return false;
            }
            if matches_tokens(&self.tokens, candidate) {
                return true;
            }
            !self.anchored
                && candidate
                    .match_indices('/')
                    .any(|(index, _)| matches_tokens(&self.tokens, &candidate[index + 1..]))
        })
    }
}

impl IgnoreRules {
    pub(crate) fn load(root: &Path) -> Result<Self> {
        let mut rules = Vec::new();
        for name in [".git", "target", "node_modules", ".venv"] {
            rules.push(Rule {
                tokens: parse_tokens(name)?,
                text: format!("{name}/"),
                source: "software default",
                line: None,
                anchored: false,
                directory: true,
                ignored: true,
            });
        }
        for language in crate::domain::LANGUAGES.iter().filter(|l| l.detected(root)) {
            for pattern in language.ignore {
                let name = pattern.trim_end_matches('/');
                if rules.iter().any(|rule| rule.text == *pattern) {
                    continue;
                }
                rules.push(Rule {
                    tokens: parse_tokens(name)?,
                    text: (*pattern).to_owned(),
                    source: "language default",
                    line: None,
                    anchored: false,
                    directory: true,
                    ignored: true,
                });
            }
        }
        let path = root.join(".calveignore");
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.len() > MAX_FILE_BYTES {
                    return Err(invalid(
                        ".calveignore must be a regular file of at most 64 KiB",
                    ));
                }
                let contents = fs::read_to_string(path)?;
                rules.extend(Self::parse(&contents)?.rules);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self { rules })
    }

    /// Parses `.calveignore` text alone, without the built-in defaults.
    pub(crate) fn parse(contents: &str) -> Result<Self> {
        if contents.len() as u64 > MAX_FILE_BYTES {
            return Err(invalid(".calveignore exceeds 64 KiB"));
        }
        let mut rules = Vec::new();
        for (index, line) in contents.lines().enumerate() {
            if let Some(rule) = parse_rule(line, index + 1)? {
                rules.push(rule);
            }
            if rules.len() > MAX_RULES {
                return Err(invalid(".calveignore exceeds 512 rules"));
            }
        }
        Ok(Self { rules })
    }

    pub(crate) fn describe(&self) -> Vec<Value> {
        self.rules
            .iter()
            .map(|rule| json!({"pattern":rule.text,"source":rule.source,"line":rule.line,"ignored":rule.ignored}))
            .collect()
    }

    pub(crate) fn check(&self, path: &str, is_dir: bool) -> Value {
        if path == ".calve" || path.starts_with(".calve/") {
            return json!({"path":path,"ignored":true,"source":"hard safety","pattern":".calve/"});
        }
        let matched = self.rules.iter().rfind(|rule| rule.matches(path, is_dir));
        match matched {
            Some(rule) => {
                json!({"path":path,"ignored":rule.ignored,"source":rule.source,"line":rule.line,"pattern":rule.text})
            }
            None => json!({"path":path,"ignored":false,"source":null,"pattern":null}),
        }
    }

    pub(crate) fn ignored(&self, path: &str, is_dir: bool) -> bool {
        self.check(path, is_dir)["ignored"] == true
    }
}

impl Project {
    pub fn check_ignore(&self, path: &Path) -> Result<Value> {
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(invalid("ignore check requires a relative Project path"));
        }
        let text = path
            .to_str()
            .ok_or_else(|| invalid("ignore check path must be UTF-8"))?
            .replace('\\', "/");
        let is_dir = text.ends_with('/')
            || fs::symlink_metadata(self.root.join(path))
                .map(|metadata| metadata.is_dir())
                .unwrap_or(false);
        Ok(IgnoreRules::load(&self.root)?.check(&text, is_dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_handle_negation_directories_root_and_escapes() {
        let rules = IgnoreRules {
            rules: vec![
                parse_rule("*.log", 1).unwrap().unwrap(),
                parse_rule("!keep.log", 2).unwrap().unwrap(),
                parse_rule("build/", 3).unwrap().unwrap(),
                parse_rule("/root.txt", 4).unwrap().unwrap(),
                parse_rule("\\#literal", 5).unwrap().unwrap(),
                parse_rule("src/**/generated?.rs", 6).unwrap().unwrap(),
            ],
        };
        assert!(rules.ignored("nested/debug.log", false));
        assert!(!rules.ignored("nested/keep.log", false));
        assert!(rules.ignored("a/build/file.rs", false));
        assert!(rules.ignored("root.txt", false));
        assert!(!rules.ignored("a/root.txt", false));
        assert!(rules.ignored("#literal", false));
        assert!(rules.ignored("src/generated1.rs", false));
        assert!(rules.ignored("src/a/b/generated2.rs", false));
    }
}
