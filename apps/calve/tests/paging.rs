//! Keyset paging of `intent list` and `pack list` (R15): `--after <id> --limit <n>` walks the
//! whole list in `(created_at, id)` order without gaps or repeats; no flags returns everything;
//! an unknown cursor is NOT_FOUND.

use calve_testkit::Env;
use serde_json::Value;

fn ids(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_owned())
        .collect()
}

fn walk(env: &Env, p: &str, noun: &str) -> Vec<String> {
    let mut out = vec![];
    let mut after: Option<String> = None;
    loop {
        let mut args = vec!["--project", p, noun, "list", "--limit", "2"];
        if let Some(a) = &after {
            args.extend(["--after", a.as_str()]);
        }
        let page = ids(&env.ok(&args));
        assert!(page.len() <= 2);
        if page.is_empty() {
            return out;
        }
        after = page.last().cloned();
        out.extend(page);
    }
}

#[test]
fn intents_and_packs_page_without_gaps_or_repeats() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    for i in 0..5 {
        env.ok(&["--project", p, "intent", "create", &format!("I{i}")]);
        env.ok(&["--project", p, "pack", "create", &format!("P{i}")]);
    }
    for noun in ["intent", "pack"] {
        let all = ids(&env.ok(&["--project", p, noun, "list"]));
        assert_eq!(all.len(), 5, "{noun}");
        assert_eq!(walk(&env, p, noun), all, "{noun}");
        let missing = env.run(&["--project", p, noun, "list", "--after", "nope"]);
        assert!(!missing.success);
        assert!(missing.stderr.contains("NOT_FOUND"), "{}", missing.stderr);
    }
}

/// Filtered activity over OpenAEVC events goes through the event index (M6): it must return
/// exactly the events a full scan would: only the named pack's, only the object kind, nothing
/// outside the time bounds.
#[test]
fn indexed_activity_filters_match_their_definitions() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    let a = env.ok(&["--project", p, "pack", "create", "A"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = env.ok(&["--project", p, "pack", "create", "B"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rows = |extra: &[&str]| -> Vec<Value> {
        let mut args = vec!["--project", p, "activity", "--source", "openaevc"];
        args.extend_from_slice(extra);
        env.ok(&args).as_array().unwrap().clone()
    };
    let for_a = rows(&["--pack", &a]);
    assert!(!for_a.is_empty());
    assert!(for_a.iter().any(|r| r["kind"] == "changepack.created"));
    assert!(
        for_a
            .iter()
            .all(|r| r.to_string().contains(&a) && !r["subjects"].to_string().contains(&b)),
        "{for_a:?}"
    );
    let kinds = rows(&["--object-kind", "changepack"]);
    assert!(kinds.len() >= 2);
    assert!(
        kinds
            .iter()
            .all(|r| r["kind"].as_str().unwrap().starts_with("changepack."))
    );
    assert!(rows(&["--since", "2999-01-01T00:00:00Z"]).is_empty());
}
