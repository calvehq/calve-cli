//! Text safety and formatting: every string from the backend is untrusted (console-ux §76.2).

use serde_json::Value;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Removes terminal control sequences and control characters; tabs become spaces.
pub fn sanitize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\u{1b}' => {
                // CSI (`ESC [ ... final`), OSC (`ESC ] ... BEL|ST`) and two-byte escapes.
                match chars.peek() {
                    Some('[') => {
                        chars.next();
                        for c in chars.by_ref() {
                            if ('@'..='~').contains(&c) {
                                break;
                            }
                        }
                    }
                    Some(']') | Some('P') | Some('_') | Some('^') => {
                        chars.next();
                        while let Some(c) = chars.next() {
                            if c == '\u{7}' {
                                break;
                            }
                            if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                                chars.next();
                                break;
                            }
                        }
                    }
                    Some(_) => {
                        chars.next();
                    }
                    None => {}
                }
            }
            '\t' => out.push_str("  "),
            // C1 controls, bidi overrides and zero-width characters that can disguise text.
            c if c.is_control()
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
                || ('\u{200b}'..='\u{200f}').contains(&c)
                || ('\u{2060}'..='\u{2064}').contains(&c)
                || ('\u{fff9}'..='\u{fffb}').contains(&c)
                || ('\u{e0000}'..='\u{e007f}').contains(&c)
                || c == '\u{061c}'
                || c == '\u{feff}' =>
            {
                out.push('\u{fffd}');
            }
            c => out.push(c),
        }
    }
    out
}

/// Sanitized single-line text: newlines collapse to spaces.
pub fn line(input: &str) -> String {
    sanitize(&input.replace(['\n', '\r'], " "))
}

pub fn width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

/// Truncates at a display-width boundary, ending with an ellipsis.
pub fn truncate(text: &str, max: usize, ellipsis: &str) -> String {
    if width(text) <= max {
        return text.to_owned();
    }
    let room = max.saturating_sub(width(ellipsis));
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + w > room {
            break;
        }
        used += w;
        out.push(ch);
    }
    out.push_str(ellipsis);
    if width(&out) > max {
        ellipsis.chars().take(max).collect()
    } else {
        out
    }
}

/// Keeps both ends, for digests and paths (`sha256:73ae…21cd`).
pub fn middle(text: &str, max: usize, ellipsis: &str) -> String {
    if width(text) <= max {
        return text.to_owned();
    }
    // Both halves are measured in display columns, so wide (CJK) text cannot overflow.
    let room = max.saturating_sub(width(ellipsis));
    let take = |chars: &mut dyn Iterator<Item = char>, budget: usize| {
        let mut used = 0;
        let mut out = Vec::new();
        for ch in chars {
            let w = UnicodeWidthChar::width(ch).unwrap_or(0);
            if used + w > budget {
                break;
            }
            used += w;
            out.push(ch);
        }
        out
    };
    let start: String = take(&mut text.chars(), room.div_ceil(2))
        .into_iter()
        .collect();
    let end: String = take(&mut text.chars().rev(), room / 2)
        .into_iter()
        .rev()
        .collect();
    format!("{start}{ellipsis}{end}")
}

/// Pads or truncates to exactly `cols` display columns.
pub fn fit(text: &str, cols: usize, ellipsis: &str) -> String {
    let cut = truncate(text, cols, ellipsis);
    let pad = cols.saturating_sub(width(&cut));
    format!("{cut}{}", " ".repeat(pad))
}

/// Unix seconds from either a number or an RFC 3339 timestamp (`Z` or a `±hh:mm` offset).
pub fn unix_seconds(value: &Value) -> Option<i64> {
    if let Some(seconds) = value.as_i64() {
        return Some(seconds);
    }
    let text = value.as_str()?;
    let (date, rest) = text.split_once(['T', ' '])?;
    let mut parts = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, d) = (parts.next()??, parts.next()??, parts.next()??);
    let (time, offset) = match rest.find(['Z', 'z', '+', '-']) {
        Some(i) if rest[i..].eq_ignore_ascii_case("z") => (&rest[..i], 0),
        Some(i) => {
            let sign = if rest[i..].starts_with('-') { -1 } else { 1 };
            let (oh, om) = rest[i + 1..].split_once(':')?;
            (
                &rest[..i],
                sign * (oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().ok()? * 60),
            )
        }
        None => return None,
    };
    let time = time.split('.').next()?;
    let mut hms = time.split(':').map(|p| p.parse::<i64>().ok());
    let (hh, mm, ss) = (hms.next()??, hms.next()??, hms.next()??);
    // Days from civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss - offset)
}

/// Compact relative age: `now`, `42s`, `11m`, `2h`, `3d`, `5w`.
pub fn relative(then: i64, now: i64) -> String {
    let delta = (now - then).max(0);
    match delta {
        0..=4 => "now".into(),
        5..=59 => format!("{delta}s"),
        60..=3599 => format!("{}m", delta / 60),
        3600..=86_399 => format!("{}h", delta / 3600),
        86_400..=1_209_599 => format!("{}d", delta / 86_400),
        _ => format!("{}w", delta / 604_800),
    }
}

/// Exact UTC time; the zone is always stated (console-ux §54).
pub fn absolute(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let secs = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Compact UTC clock time for tables: `06:12:01Z` today, `09-28 06:12Z` otherwise.
pub fn clock(seconds: i64, now: i64) -> String {
    let full = absolute(seconds);
    if seconds.div_euclid(86_400) == now.div_euclid(86_400) {
        format!("{}Z", &full[11..19])
    } else {
        format!("{} {}Z", &full[5..10], &full[11..16])
    }
}

/// Human value for the generic structured renderer (console-ux §81).
pub fn scalar(value: &Value) -> String {
    match value {
        Value::Null => "—".into(),
        Value::Bool(true) => "yes".into(),
        Value::Bool(false) => "no".into(),
        Value::String(text) => line(text),
        Value::Number(number) => number.to_string(),
        Value::Array(items) if items.iter().all(|i| !i.is_object() && !i.is_array()) => {
            items.iter().map(scalar).collect::<Vec<_>>().join(", ")
        }
        Value::Array(items) => format!("{} items", items.len()),
        Value::Object(map) => format!("{} fields", map.len()),
    }
}

/// `org.example.files.snapshot` → `Snapshot`; `IN_PROGRESS` → `In progress`.
pub fn label(key: &str) -> String {
    let last = key.rsplit('.').next().unwrap_or(key);
    let spaced = last.replace(['_', '-'], " ").to_lowercase();
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Keeps the type prefix of Calve/OpenAEVC IDs recognizable when shortening (§55).
pub fn short_id(id: &str, max: usize, ellipsis: &str) -> String {
    if width(id) <= max {
        return id.to_owned();
    }
    match id.split_once('_') {
        Some((prefix, rest)) if prefix.len() + 2 < max => {
            let keep = max.saturating_sub(prefix.len() + 1 + width(ellipsis));
            let tail: String = rest
                .chars()
                .rev()
                .take(keep)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("{prefix}_{ellipsis}{tail}")
        }
        _ => middle(id, max, ellipsis),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hostile_sequences_are_neutralized() {
        let hostile = "ok\u{1b}[31mred\u{1b}]0;title\u{7}\u{1b}]52;c;AAAA\u{1b}\\x\u{8}\u{202e}";
        let clean = sanitize(hostile);
        assert!(!clean.contains('\u{1b}'));
        assert!(clean.starts_with("okred"));
        assert!(!clean.contains("title"));
        assert!(clean.chars().all(|c| !c.is_control()));
    }

    #[test]
    fn truncation_respects_display_width() {
        assert_eq!(truncate("hello world", 8, "…"), "hello w…");
        assert_eq!(width(&truncate("日本語テキスト", 7, "…")), 7);
        assert_eq!(
            middle("sha256:73aebbbbbbbbbbbbbb21cd", 15, "…"),
            "sha256:…bbb21cd"
        );
        assert_eq!(fit("ab", 4, "…"), "ab  ");
        assert_eq!(
            short_id("cpk_agqo5crlhz25jctk4pjyxascaq", 12, "…"),
            "cpk_…yxascaq"
        );
    }

    #[test]
    fn offsets_and_zero_width_are_handled() {
        let utc = unix_seconds(&json!("2026-09-28T00:42:01Z")).unwrap();
        assert_eq!(unix_seconds(&json!("2026-09-28T06:12:01+05:30")), Some(utc));
        assert_eq!(
            unix_seconds(&json!("2026-09-27T19:42:01.5-05:00")),
            Some(utc)
        );
        assert_eq!(unix_seconds(&json!("2026-09-28T00:42:01")), None);
        assert!(
            !sanitize("a\u{200d}b\u{feff}c\u{2060}").contains(['\u{200d}', '\u{feff}', '\u{2060}'])
        );
        assert!(width(&middle("日本語のとても長いファイル名.rs", 12, "…")) <= 12);
    }

    #[test]
    fn times_parse_and_format() {
        let t = unix_seconds(&json!("2026-09-29T10:00:05.123456789Z")).unwrap();
        assert_eq!(absolute(t), "2026-09-29 10:00:05 UTC");
        assert_eq!(unix_seconds(&json!(1_790_000_000)), Some(1_790_000_000));
        assert_eq!(relative(t - 660, t), "11m");
        assert_eq!(relative(t, t), "now");
        assert_eq!(clock(t, t + 60), "10:00:05Z");
        assert_eq!(clock(t, t + 86_400), "09-29 10:00Z");
    }
}
