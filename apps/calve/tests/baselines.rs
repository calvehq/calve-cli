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
