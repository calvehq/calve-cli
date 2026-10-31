//! `xtask acceptance --scenario <A..P|all> [--report out.json]`: runs §57 scenarios from this
//! checkout and records an environment fingerprint. Each scenario is one test that performs every
//! step; a scenario with a documented deviation (docs/reference/acceptance.md) is reported as
//! such even when its test passes, never as a plain pass.

use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Scenario {
    pub id: char,
    /// Test target and test name in package `calve`.
    pub target: &'static str,
    pub test: &'static str,
    /// Needs the first-party catalog in `CALVE_CATALOG_ADD`.
    pub catalog: bool,
    /// Why the run is not a full pass even when the test passes.
    pub deviation: Option<&'static str>,
}

const fn s(
    id: char,
    target: &'static str,
    test: &'static str,
    catalog: bool,
    deviation: Option<&'static str>,
) -> Scenario {
    Scenario {
        id,
        target,
        test,
        catalog,
        deviation,
    }
}

pub const SCENARIOS: [Scenario; 16] = [
    s('A', "examples", "scenario_a", true, None),
    s('B', "examples", "scenario_b", true, None),
    s(
        'C',
        "examples",
        "scenario_c",
        false,
        Some(
            "steps 5-7 run on a superseding pack: OpenAEVC v0.1.0 cannot promote a pack's effects after a reopen",
        ),
    ),
    s('D', "examples", "scenario_d", false, None),
    s('E', "examples", "scenario_e", false, None),
    s('F', "examples", "scenario_f", false, None),
    s(
        'G',
        "acceptance",
        "scenario_g_capability_denial",
        false,
        None,
    ),
    s(
        'H',
        "extensions",
        "scenario_h_permission_widening",
        false,
        None,
    ),
    s('I', "examples", "scenario_i", false, None),
    s('J', "examples", "scenario_j", false, None),
    s('K', "examples", "scenario_k", false, None),
    s(
        'L',
        "extensions",
        "scenario_l_crash_during_extension_install",
        false,
        None,
    ),
    s('M', "examples", "scenario_m", false, None),
    s(
        'N',
        "extensions",
        "scenario_n_third_party_extension",
        false,
        Some("evidence only: creating resource instances needs integration metadata"),
    ),
    s('O', "examples", "scenario_o", false, None),
    s(
        'P',
        "acceptance",
        "scenario_p_version_incompatibility",
        false,
        Some(
            "the unsupported runtime is a debug-only report override; no second OpenAEVC exists to link",
        ),
    ),
];

fn output(root: &Path, program: &str, args: &[&str]) -> String {
    Command::new(program)
        .current_dir(root)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// OS, toolchain, lock hashes and pinned revisions of this run.
fn fingerprint(root: &Path) -> Result<Value> {
    let lock = std::fs::read(root.join("Cargo.lock"))?;
    let binary = root.join("target/debug/calve");
    Ok(json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "kernel": output(root, "uname", &["-r"]),
        "rustc": output(root, "rustc", &["-V"]),
        "commit": output(root, "git", &["rev-parse", "HEAD"]),
        "dirty": !output(root, "git", &["status", "--short", "--", "crates", "apps", "xtask", "Cargo.lock"]).is_empty(),
        "cargo_lock_sha256": crate::release::sha256_hex(&lock),
        "openaevc_revision": crate::OPENAEVC_REVISION,
        "calve_binary_sha256": std::fs::read(&binary).ok().map(|b| crate::release::sha256_hex(&b)),
        "first_party_catalog": std::env::var_os("CALVE_CATALOG_ADD").is_some(),
    }))
}

pub fn run(root: &Path, which: &str, report: Option<&Path>) -> Result {
    let selected: Vec<&Scenario> = SCENARIOS
        .iter()
        .filter(|s| which == "all" || which.eq_ignore_ascii_case(&s.id.to_string()))
        .collect();
    if selected.is_empty() {
        return Err(format!("no scenario {which}; use A..P or all").into());
    }
    let mut results = Vec::new();
    let mut failed = false;
    for s in selected {
        if s.catalog && std::env::var_os("CALVE_CATALOG_ADD").is_none() {
            eprintln!("{}: skipped, needs CALVE_CATALOG_ADD", s.id);
            results.push(json!({"scenario": s.id.to_string(), "result": "not-run", "reason": "needs the first-party catalog"}));
            failed = true;
            continue;
        }
        let started = std::time::Instant::now();
        let status = Command::new(env!("CARGO"))
            .current_dir(root)
            .args([
                "test", "--locked", "-p", "calve", "--test", s.target, s.test,
            ])
            .args(["--", "--exact", "--include-ignored", "--test-threads", "1"])
            .status()?;
        let result = match (status.success(), s.deviation) {
            (false, _) => "fail",
            (true, Some(_)) => "pass-with-deviation",
            (true, None) => "pass",
        };
        failed |= !status.success();
        eprintln!("{}: {result}", s.id);
        results.push(json!({"scenario": s.id.to_string(), "result": result,
            "test": format!("{}::{}", s.target, s.test), "deviation": s.deviation,
            "seconds": started.elapsed().as_secs()}));
    }
    let out = json!({"environment": fingerprint(root)?, "scenarios": results});
    let text = serde_json::to_string_pretty(&out)?;
    match report {
        Some(path) => std::fs::write(path, text)?,
        None => println!("{text}"),
    }
    if failed {
        return Err("a scenario did not pass".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scenario_is_mapped_once_in_order() {
        let ids: String = SCENARIOS.iter().map(|s| s.id).collect();
        assert_eq!(ids, "ABCDEFGHIJKLMNOP");
    }
}
