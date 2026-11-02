//! Baselines from OpenAEVC (P6), derivation and edges (P7), comparison (P8).

use std::fs;

use calve_testkit::Env;
use serde_json::Value;

struct P<'a> {
    env: &'a Env,
    root: String,
}

impl P<'_> {
    fn ok(&self, args: &[&str]) -> Value {
        self.env
            .ok(&[&["--project", self.root.as_str()][..], args].concat())
    }
    fn fails(&self, args: &[&str]) -> String {
        self.env
            .fails(&[&["--project", self.root.as_str()][..], args].concat())
    }
    /// Captures `files` into a new pack (or `revision` of `of`) and promotes it.
    fn promote(
        &self,
        title: &str,
        files: &[(&str, &str)],
        revision: Option<(&str, &str)>,
    ) -> String {
        let id = match revision {
            None => self.ok(&["pack", "create", title]),
            Some((of, rel)) => {
                self.ok(&["revision", "create", title, "--of", of, "--relation", rel])
            }
        }["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let root = std::path::Path::new(&self.root);
        for (path, content) in files {
            fs::write(root.join(path), content).unwrap();
            self.ok(&["pack", "capture", &id, path, "--generation", "1"]);
        }
        let g = self.ok(&["pack", "show", &id])["generation"].to_string();
        self.ok(&["pack", "seal", &id, "--generation", &g]);
        self.ok(&["pack", "qualify", &id, "--generation", &g]);
        self.ok(&["pack", "promote", &id, "--generation", &g])["promoted_digest"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

#[test]
fn baselines_come_from_openaevc_derive_and_compare() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let project = root.to_str().unwrap().to_owned();
    env.ok(&["init", &project]);
    env.enable_toy(&root);
    let p = P {
        root: project,
        env: &env,
    };
    fs::write(root.join("toy.toml"), "").unwrap();
    let p0 = p.promote("P0", &[("a.toy", "a1")], None);
    let p1 = p.promote("P1", &[("b.toy", "b1")], None);
    let p2 = p.promote("P2", &[("a.toy", "a2")], None);
    let b0 = p.ok(&["baseline", "create", "B0", &p0, &p1]);
    let b0_id = b0["id"].as_str().unwrap().to_owned();

    // The product index is only an index: Baselines list, validate and take aliases without it.
    {
        let db = rusqlite::Connection::open(root.join(".calve/product.sqlite3")).unwrap();
        db.execute("DELETE FROM baseline_metadata", []).unwrap();
    }
    let listed = p.ok(&["baseline", "list"]);
    let row = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["id"] == b0_id.as_str())
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(row["label"], "B0", "label from the object metadata");
    assert_eq!(p.ok(&["baseline", "validate", &b0_id])["valid"], true);
    p.ok(&["baseline", "alias", "set", "stable", &b0_id]);

    // P2 and P0 both write a.toy: without an edge the overlap is reported, with one it is ordered.
    let unordered = p.ok(&["baseline", "derive", "stable", "B1u", "--add", &p2]);
    let ordered = p.ok(&[
        "baseline",
        "derive",
        "stable",
        "B1",
        "--add",
        &p2,
        "--edge",
        &format!("{p2}:{p0}:orders-after"),
    ]);
    assert_eq!(ordered["derived_from"], b0["digest"]);
    let cmp = p.ok(&[
        "baseline",
        "compare",
        &b0_id,
        ordered["id"].as_str().unwrap(),
    ]);
    assert_eq!(cmp["only_right_members"], serde_json::json!([p2]), "{cmp}");
    let diff = &cmp["resources"]["different"];
    assert_eq!(diff[0]["path"], "a.toy", "{cmp}");
    assert!(
        cmp["resources"]["unordered_overlaps"]["right"]
            .as_object()
            .unwrap()
            .is_empty(),
        "{cmp}"
    );
    let cmp_u = p.ok(&[
        "baseline",
        "compare",
        &b0_id,
        unordered["id"].as_str().unwrap(),
    ]);
    assert!(
        cmp_u["resources"]["unordered_overlaps"]["right"]["a.toy"].is_array(),
        "{cmp_u}"
    );
    // An edge between non-members is refused by OpenAEVC.
    assert!(
        p.fails(&[
            "baseline",
            "derive",
            &b0_id,
            "Bx",
            "--edge",
            &format!("{p2}:{p0}")
        ])
        .contains("members")
    );

    // A superseding revision replaces its target.
    let r1 = p.promote("R1", &[("b.toy", "b2")], Some((&p1, "supersedes")));
    let b2 = p.ok(&["baseline", "derive", &b0_id, "B2", "--replace-with", &r1]);
    let members: Vec<String> = serde_json::from_value(b2["members"].clone()).unwrap();
    assert!(members.contains(&r1) && !members.contains(&p1), "{b2}");
    let cmp = p.ok(&["baseline", "compare", &b0_id, b2["id"].as_str().unwrap()]);
    let rev = &cmp["revisions"]["right"][0];
    assert_eq!(
        (rev["relation"].as_str(), rev["target"].as_str()),
        (Some("SUPERSEDES"), Some(p1.as_str())),
        "{cmp}"
    );
    assert_eq!(rev["target_present"], false);
    assert_eq!(cmp["resources"]["different"][0]["path"], "b.toy", "{cmp}");
    // B0 itself never changed.
    assert_eq!(
        p.ok(&["baseline", "show", &b0_id])["envelope"]["body"]["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// §48.2: `baseline compare` is set logic over members, for every pair of compositions.
#[test]
fn compare_is_set_logic_over_every_pair_of_compositions() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap();
    let mut env = env;
    env.ok(&["init", p]);
    env.enable_toy(&root);
    let run = |a: &[&str]| env.ok(&[&["--project", p][..], a].concat());
    let mut digests = Vec::new();
    for n in 0..3 {
        fs::write(root.join(format!("f{n}.toy")), format!("{n}")).unwrap();
        let pack = run(&["pack", "create", &format!("p{n}")])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let name = format!("f{n}.toy");
        run(&["pack", "capture", &pack, &name, "--generation", "1"]);
        let g = run(&["pack", "show", &pack])["generation"].to_string();
        run(&["pack", "seal", &pack, "--generation", &g]);
        run(&["pack", "qualify", &pack, "--generation", &g]);
        let done = run(&["pack", "promote", &pack, "--generation", &g]);
        digests.push(done["promoted_digest"].as_str().unwrap().to_owned());
    }
    let subset = |mask: usize| -> Vec<String> {
        (0..3)
            .filter(|b| mask >> b & 1 == 1)
            .map(|b| digests[b].clone())
            .collect()
    };
    let mut baselines = Vec::new();
    for mask in 1..8usize {
        let members = subset(mask);
        let label = format!("b{mask}");
        let mut args = vec!["baseline", "create", label.as_str()];
        args.extend(members.iter().map(String::as_str));
        baselines.push((mask, run(&args)["id"].as_str().unwrap().to_owned()));
    }
    let set = |v: &serde_json::Value| -> std::collections::BTreeSet<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str().map(str::to_owned))
            .collect()
    };
    for (a, left) in &baselines {
        for (b, right) in &baselines {
            let got = run(&["baseline", "compare", left, right]);
            let (x, y): (std::collections::BTreeSet<_>, std::collections::BTreeSet<_>) = (
                subset(*a).into_iter().collect(),
                subset(*b).into_iter().collect(),
            );
            assert_eq!(set(&got["shared_members"]), &x & &y, "{a} {b}: {got}");
            assert_eq!(set(&got["only_left_members"]), &x - &y, "{a} {b}: {got}");
            assert_eq!(set(&got["only_right_members"]), &y - &x, "{a} {b}: {got}");
        }
    }
}
