//! Resource locators (ADR 0014): the one validator the host and every extension share, so a
//! locator is never accepted by one side and read differently by the other.

pub const MAX_LOCATOR_BYTES: usize = 4096;
pub const MAX_COMPONENTS: usize = 64;

/// ADR 0014: UTF-8, `/`-separated, relative, no empty/`.`/`..` component, no NUL or backslash,
/// not under `.calve/`, at most 4 096 bytes and 64 components. Byte identity (no Unicode
/// normalization).
pub fn validate(loc: &str) -> Result<(), String> {
    let bad = |m: &str| Err(format!("{loc:?}: {m}"));
    if loc.is_empty() || loc.len() > MAX_LOCATOR_BYTES {
        return bad("empty or longer than 4096 bytes");
    }
    if loc.contains(['\0', '\\']) {
        return bad("NUL or backslash");
    }
    let parts: Vec<&str> = loc.split('/').collect();
    if parts.len() > MAX_COMPONENTS {
        return bad("more than 64 components");
    }
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return bad("empty, '.' or '..' component (or absolute)");
    }
    // Case-insensitive and trailing-dot/space-insensitive filesystems (Windows, default macOS)
    // map `.CALVE`, `.calve.` and `.calve ` onto `.calve`: compare the normalized form.
    let fold = |p: &str| p.trim_end_matches(['.', ' ']).to_ascii_lowercase();
    if fold(parts[0]) == ".calve" {
        return bad("inside .calve");
    }
    for p in &parts {
        // `:` names an NTFS alternate data stream or a drive; a trailing dot or space is
        // stripped by Win32, so the name on disk would differ from the locator.
        if p.contains(':') {
            return bad("':' (drive or alternate data stream)");
        }
        if p.ends_with(['.', ' ']) {
            return bad("component ends with '.' or ' '");
        }
        // Win32 device names, with or without an extension (`NUL.txt`, `CON .txt` are still
        // devices: the stem is compared with trailing spaces removed), including the
        // superscript-digit forms `COM¹`..`LPT³`.
        let stem = p
            .split('.')
            .next()
            .unwrap_or(p)
            .trim_end_matches(' ')
            .to_uppercase();
        let port = stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|n| {
                let mut c = n.chars();
                matches!(
                    (c.next(), c.next()),
                    (Some('0'..='9' | '¹' | '²' | '³'), None)
                )
            });
        if port
            || matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
        {
            return bad("reserved Windows device name");
        }
        // NTFS/FAT 8.3 short-name aliases (`CALVE~1` can name `.calve`): refused everywhere, so
        // one locator never names two files and the rules are the same on every platform.
        if is_short_name_alias(p) {
            return bad("8.3 short-name form (NAME~N)");
        }
    }
    Ok(())
}

/// `BASE~N[.EXT]` with a base of 1–8 and an extension of 0–3 characters (no other dot).
fn is_short_name_alias(p: &str) -> bool {
    let (base, ext) = p.split_once('.').unwrap_or((p, ""));
    let Some((name, num)) = base.rsplit_once('~') else {
        return false;
    };
    !name.is_empty()
        && base.chars().count() <= 8
        && !num.is_empty()
        && num.bytes().all(|b| b.is_ascii_digit())
        && ext.chars().count() <= 3
        && !ext.contains('.')
}

#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]
        /// An accepted locator stays under the root and never names Calve's state directory.
        #[test]
        fn accepted_locators_stay_inside_and_avoid_calve_state(
            parts in proptest::collection::vec(
                prop_oneof![
                    "[a-zA-Z0-9_ .:-]{0,12}",
                    Just("..".to_owned()),
                    Just(".".to_owned()),
                    Just(".calve".to_owned()),
                    Just(".CALVE.".to_owned()),
                    Just("CON".to_owned()),
                    Just("a\\b".to_owned()),
                ],
                0..8,
            ),
            lead in prop_oneof![Just(""), Just("/")],
        ) {
            let loc = format!("{lead}{}", parts.join("/"));
            if super::validate(&loc).is_ok() {
                let p = std::path::Path::new(&loc);
                prop_assert!(p.is_relative());
                prop_assert!(p.components().all(|c| matches!(c, std::path::Component::Normal(_))));
                let first = loc.split('/').next().unwrap().trim_end_matches(['.', ' ']).to_ascii_lowercase();
                prop_assert_ne!(first, ".calve");
                prop_assert!(!loc.contains('\\') && !loc.contains(':'));
            }
        }
    }
}
