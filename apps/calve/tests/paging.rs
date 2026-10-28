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

/// The console's collection views are keyset pages (M6 R5), never whole-store lists:
/// `view packs` newest first with per-state counts and a state filter, `view evidence` newest
/// first. Walking `next` returns every row exactly once, and each page agrees with the
/// authoritative per-object reads.
#[test]
fn console_views_are_keyset_pages() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    let run = |args: &[&str]| env.ok(&[&["--project", p.as_str()][..], args].concat());
    let mut packs = vec![];
    for i in 0..5 {
        let id = run(&["pack", "create", &format!("P{i}"), "--require-review"])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        packs.push(id);
    }
    // Three packs get review evidence: sealed, then rejected with a reason.
    for id in &packs[..3] {
        run(&["pack", "seal", id, "--generation", "1"]);
        run(&[
            "pack",
            "reject",
            id,
            "--generation",
            "1",
            "--reason",
            "needs work",
        ]);
    }
    let mut seen = vec![];
    let mut after: Option<String> = None;
    loop {
        let mut args = vec!["view", "packs", "--limit", "2"];
        if let Some(a) = &after {
            args.extend(["--after", a.as_str()]);
        }
        let page = run(&args);
        let items = ids(&page["items"]);
        assert!(items.len() <= 2);
        seen.extend(items);
        match page["next"].as_str() {
            Some(next) => after = Some(next.to_owned()),
            None => break,
        }
    }
    let mut all = ids(&run(&["pack", "list"]));
    all.reverse();
    assert_eq!(seen, all, "newest first, no gaps or repeats");
    let first = run(&["view", "packs"]);
    let counts = first["counts"].as_object().unwrap();
    assert_eq!(counts.values().map(|c| c.as_u64().unwrap()).sum::<u64>(), 5);
    for (state, count) in counts {
        let only = run(&["view", "packs", "--state", state]);
        let items = only["items"].as_array().unwrap();
        assert_eq!(items.len() as u64, count.as_u64().unwrap(), "{state}");
        assert!(items.iter().all(|i| i["state"] == state.as_str()));
    }
    let mut evidence = vec![];
    let mut before: Option<String> = None;
    loop {
        let mut args = vec!["view", "evidence", "--limit", "2"];
        if let Some(b) = &before {
            args.extend(["--before", b.as_str()]);
        }
        let page = run(&args);
        evidence.extend(page["items"].as_array().unwrap().iter().cloned());
        match page["next"].as_str() {
            Some(next) => before = Some(next.to_owned()),
            None => break,
        }
    }
    let digests: Vec<&str> = evidence
        .iter()
        .map(|e| e["digest"].as_str().unwrap())
        .collect();
    assert_eq!(digests.len(), 3);
    assert_eq!(
        digests
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3,
        "no repeats"
    );
    let times: Vec<&str> = evidence
        .iter()
        .map(|e| e["registered_at"].as_str().unwrap())
        .collect();
    assert!(
        times.windows(2).all(|w| w[0] >= w[1]),
        "newest first: {times:?}"
    );
    for id in &packs[..3] {
        let listed = run(&["evidence", "list", id]);
        let item = &listed["items"][0];
        let row = evidence.iter().find(|e| e["pack"] == id.as_str()).unwrap();
        assert_eq!(row["digest"], item["digest"]);
        assert_eq!(row["stale"], item["stale"]);
    }
    // The remaining console views answer --json too: overview, a diff and a Baseline.
    run(&["view", "overview"]);
    let pid = run(&["pack", "create", "Diff"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    std::fs::write(root.join("a.toy"), "one\ntwo\n").unwrap();
    run(&["pack", "capture", &pid, "a.toy", "--generation", "1"]);
    let diff = run(&["view", "pack-diff", &pid, "a.toy", "--context", "0"]);
    assert_eq!(diff["status"], "added", "{diff}");
    let g = run(&["pack", "show", &pid])["generation"].to_string();
    run(&["pack", "seal", &pid, "--generation", &g]);
    run(&["pack", "qualify", &pid, "--generation", &g]);
    let promoted = run(&["pack", "promote", &pid, "--generation", &g])["promoted_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let baseline = run(&["baseline", "create", "B", &promoted])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let view = run(&["view", "baseline", &baseline]);
    assert_eq!(view["members"][0]["pack"], pid.as_str(), "{view}");
}
