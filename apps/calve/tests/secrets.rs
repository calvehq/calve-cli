//! Secret redaction across every sink (PLAN §16.1, ADR 0015, N16): a worker that prints its
//! secret raw, in 1-byte writes, as base64 (standard and URL-safe at offsets 1 and 2),
//! JSON-escaped, percent-encoded and as hex, then fails. Afterwards no encoded form of the secret
//! exists in any CLI output, error, log, product or OpenAEVC store file, journal or diagnostics
//! bundle. The documented residual — a secret split across stdout and stderr — is asserted too.
#![cfg(unix)]

use calve_testkit::Isolated;
use std::fs;
use std::path::Path;
use std::process::Command;

const SECRET: &str = "Sup3r-S3cret/Token+Value=42";

fn calve(data: &Path, args: &[&str]) -> (bool, serde_json::Value, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_calve"))
        .isolated(data.join("d"), data.join("c"))
        .env("CALVE_TEST_SECRET", SECRET)
        .args(["--json", "--no-daemon-start"])
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        calve_testkit::json_data(&output.stdout),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn ok(data: &Path, args: &[&str]) -> (serde_json::Value, String) {
    let (success, value, stdout, stderr) = calve(data, args);
    assert!(success, "{args:?}: {stderr}");
    (value, stdout + &stderr)
}

/// Every encoded form the redactor must remove (fragments under 6 bytes are skipped: they
/// match unrelated text).
fn forms() -> Vec<Vec<u8>> {
    calve_app::redact::patterns(SECRET.as_bytes())
        .into_iter()
        .filter(|p| p.len() >= 6)
        .collect()
}

fn leaks(bytes: &[u8]) -> Vec<String> {
    forms()
        .into_iter()
        .filter(|f| bytes.windows(f.len()).any(|w| w == f.as_slice()))
        .map(|f| String::from_utf8_lossy(&f).into_owned())
        .collect()
}

fn scan_tree(dir: &Path, found: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let meta = fs::symlink_metadata(&p).unwrap();
        if meta.is_dir() {
            scan_tree(&p, found);
        } else if meta.is_file()
            && let Ok(bytes) = fs::read(&p)
        {
            for l in leaks(&bytes) {
                found.push(format!("{}: {l}", p.display()));
            }
        }
    }
}

const WORKER: &str = r#"
import os, sys, base64, json, binascii, urllib.parse
t = os.environ["TOKEN"].encode()
o, e = sys.stdout.buffer, sys.stderr.buffer
o.write(b"raw " + t + b"\n"); o.flush()
for c in b"slow " + t + b"\n":
    o.write(bytes([c])); o.flush()
e.write(b"b64 " + base64.b64encode(b"x" + t) + b"\n"); e.flush()
e.write(b"url " + base64.urlsafe_b64encode(b"xy" + t) + b"\n"); e.flush()
o.write(b"json " + json.dumps({"k": t.decode()}).encode() + b"\n")
o.write(b"pct " + urllib.parse.quote(t.decode(), safe="").encode() + b"\n")
e.write(b"hex " + binascii.hexlify(t).upper() + b"\n")
o.write(b"split " + t[:10] + b"\n"); o.flush()
e.write(t[10:] + b" tail\n"); e.flush()
sys.exit(4)
"#;

#[test]
fn secrets_never_reach_any_sink() {
    if Command::new("python3").arg("-V").output().is_err() {
        eprintln!("python3 not available; skipping");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path();
    let root = data.join("project");
    let p = root.to_str().unwrap();
    let mut seen = String::new();
    seen += &ok(data, &["init", p]).1;
    let catalog = calve_testkit::ToyCatalog::new();
    let add = catalog.add_args();
    seen += &ok(data, &add.iter().map(String::as_str).collect::<Vec<_>>()).1;
    seen += &ok(
        data,
        &[&["--project", p][..], &calve_testkit::ENABLE_TOY[..]].concat(),
    )
    .1;
    seen += &ok(
        data,
        &[
            "provider",
            "add",
            "py",
            "--kind",
            "local-process",
            "--executable",
            "python3",
            "--secret",
            "TOKEN=env:CALVE_TEST_SECRET",
        ],
    )
    .1;
    let (config, _) = ok(
        data,
        &["--project", p, "config", "edit-path", "--scope", "project"],
    );
    fs::write(
        config["path"].as_str().unwrap(),
        format!(
            "format_version = 1\n[harnesses.leak]\nprovider = \"py\"\nmode = \"check\"\ncommand = [\"-c\", '''{WORKER}''']\n"
        ),
    )
    .unwrap();
    ok(data, &["--project", p, "config", "approve"]);
    let (pack, out) = ok(data, &["--project", p, "pack", "create", "Leak"]);
    seen += &out;
    let pack = pack["id"].as_str().unwrap().to_owned();
    let (failed, value, stdout, stderr) = calve(
        data,
        &[
            "--project",
            p,
            "execution",
            "start",
            &pack,
            "--harness",
            "leak",
            "--generation",
            "1",
        ],
    );
    seen += &stdout;
    seen += &stderr;
    let id = value["id"]
        .as_str()
        .or_else(|| value["execution"].as_str())
        .unwrap_or_else(|| panic!("execution id (success={failed}): {stdout} {stderr}"))
        .to_owned();
    let (logs, out) = ok(data, &["--project", p, "execution", "logs", &id]);
    seen += &out;
    // The log lines live in `org.calve.harness.log` observations; read them through OpenAEVC.
    let digests: Vec<String> = logs["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["kind"] == "observation.appended" && e["body"]["kind"] == "org.calve.harness.log"
        })
        .filter_map(|e| e["body"]["digest"].as_str().map(str::to_owned))
        .collect();
    assert!(!digests.is_empty(), "{logs}");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let text = rt.block_on(async {
        use openaevc_sdk::OpenAevcClient as _;
        calve_app::authority::use_data_root(&data.join("d/calve"));
        let project = calve_app::Project::open(&root).unwrap();
        let mut all = String::new();
        for d in &digests {
            let digest: openaevc::protocol::Digest = d.parse().unwrap();
            let o = project
                .client
                .query(openaevc::protocol::Query::GetObject { digest })
                .await
                .unwrap();
            all += &o.to_string();
        }
        all
    });
    seen += &text;
    assert!(text.contains("[REDACTED]"), "{text}");
    for line in [
        "raw [REDACTED]",
        "slow [REDACTED]",
        "pct [REDACTED]",
        "hex [REDACTED]",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
    // Residual (user-approved, ADR 0015): halves split across stdout and stderr stay visible.
    assert!(
        text.contains(&SECRET[..10]) && text.contains(&SECRET[10..]),
        "the cross-stream split is a documented residual: {text}"
    );
    for args in [
        &["--project", p, "execution", "show", &id][..],
        &["--project", p, "activity"],
        &["--project", p, "inbox", "list"],
        &["--project", p, "status"],
    ] {
        seen += &ok(data, args).1;
    }
    let bundle = data.join("bundle");
    seen += &ok(
        data,
        &[
            "--project",
            p,
            "doctor",
            "--bundle",
            bundle.to_str().unwrap(),
            "--yes",
        ],
    )
    .1;
    // Human output and errors go through the same redaction.
    let human = Command::new(env!("CARGO_BIN_EXE_calve"))
        .isolated(data.join("d"), data.join("c"))
        .args([
            "--no-daemon-start",
            "--project",
            p,
            "execution",
            "logs",
            &id,
        ])
        .output()
        .unwrap();
    seen += &String::from_utf8_lossy(&human.stdout);
    seen += &String::from_utf8_lossy(&human.stderr);

    let mut found: Vec<String> = leaks(seen.as_bytes())
        .into_iter()
        .map(|l| format!("CLI output: {l}"))
        .collect();
    scan_tree(&data.join("d"), &mut found);
    scan_tree(&data.join("c"), &mut found);
    scan_tree(&root, &mut found);
    scan_tree(&bundle, &mut found);
    assert!(
        found.is_empty(),
        "secret leaked into:\n{}",
        found.join("\n")
    );
}

/// M4 sinks (requirement 3). File content the user captures is kept intentionally: it is the
/// product's data, stored verbatim in capture spools, journals (exact signed envelopes), chunk
/// staging, OpenAEVC, materialization backups and conflict artifacts, all owner-only. It is
/// never part of a diagnostic surface: logs, the request log, errors, listings, the GC plan,
/// recovery inspection and diagnostic bundles stay free of it.
#[test]
fn captured_content_stays_in_content_sinks_only() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path();
    let root = data.join("project");
    let p = root.to_str().unwrap();
    let catalog = calve_testkit::ToyCatalog::new();
    ok(data, &["init", p]);
    ok(
        data,
        &catalog
            .add_args()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    ok(
        data,
        &[&["--project", p][..], &calve_testkit::ENABLE_TOY[..]].concat(),
    );
    fs::write(root.join("cred.txt"), format!("api_key = {SECRET}\n")).unwrap();
    let (pack, _) = ok(data, &["--project", p, "pack", "create", "C"]);
    let pack = pack["id"].as_str().unwrap().to_owned();
    // An interrupted capture leaves its spool and journal; resume finishes it.
    let crash = Command::new(env!("CARGO_BIN_EXE_calve"))
        .isolated(data.join("d"), data.join("c"))
        .env("CALVE_FAULT", "capture.submit.1.0.after_intent")
        .args([
            "--json",
            "--no-daemon-start",
            "--project",
            p,
            "pack",
            "capture-tree",
            "--accept-deletions",
            &pack,
            ".",
            "--generation",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!crash.status.success());
    let capture = root.join(".calve/run/capture");
    let mut content_sinks = vec![];
    scan_tree(&capture, &mut content_sinks);
    assert!(
        !content_sinks.is_empty(),
        "the spool and journal hold the captured bytes (intentional)"
    );
    let mut seen = String::new();
    let (list, out) = ok(data, &["--project", p, "capture", "list"]);
    seen += &out;
    let session = list[0]["session"].as_str().unwrap().to_owned();
    seen += &ok(data, &["--project", p, "capture", "resume", &session]).1;
    // A materialization conflict keeps both versions as artifacts.
    let g = ok(data, &["--project", p, "pack", "show", &pack]).0["generation"].to_string();
    for s in ["seal", "qualify"] {
        seen += &ok(
            data,
            &["--project", p, "pack", s, &pack, "--generation", &g],
        )
        .1;
    }
    fs::write(root.join("cred.txt"), "local edit\n").unwrap();
    let conflict = Command::new(env!("CARGO_BIN_EXE_calve"))
        .isolated(data.join("d"), data.join("c"))
        .env(
            "CALVE_TEST_WRITE",
            format!("f1.after_backup={}", root.join("cred.txt").display()),
        )
        .args([
            "--json",
            "--no-daemon-start",
            "--project",
            p,
            "resource",
            "materialize",
            "cred.txt",
            "--from",
            &pack,
            "--apply",
            "--discard",
        ])
        .output()
        .unwrap();
    assert!(!conflict.status.success());
    seen += &String::from_utf8_lossy(&conflict.stderr);
    for args in [
        &["--project", p, "materialize", "list"][..],
        &["--project", p, "inbox", "list"],
        &["--project", p, "status"],
        &["--project", p, "recover", "inspect"],
        &["--project", p, "recover", "plan"],
        &["--project", p, "maintenance", "gc", "--dry-run"],
        &["--project", p, "activity"],
    ] {
        seen += &ok(data, args).1;
    }
    let bundle = data.join("bundle");
    seen += &ok(
        data,
        &[
            "--project",
            p,
            "doctor",
            "--bundle",
            bundle.to_str().unwrap(),
            "--yes",
        ],
    )
    .1;
    assert!(
        leaks(seen.as_bytes()).is_empty(),
        "diagnostic output: {seen}"
    );
    let mut diagnostic = vec![];
    for dir in [
        bundle.clone(),
        root.join(".calve/logs"),
        data.join("d/calve/logs"),
    ] {
        scan_tree(&dir, &mut diagnostic);
    }
    assert!(diagnostic.is_empty(), "{diagnostic:?}");
    // The content sinks are owner-only.
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&root.join(".calve")), 0o700);
    let conflicts = root.join(".calve/conflicts");
    let op = fs::read_dir(&conflicts)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(mode(&op.join("f1")), 0o700);
    for f in ["displaced", "ours", "meta.json"] {
        assert_eq!(mode(&op.join("f1").join(f)), 0o600, "{f}");
    }
    let run = root
        .join(".calve/run/materialize")
        .join(op.file_name().unwrap());
    assert_eq!(mode(&run), 0o700);
    assert_eq!(mode(&run.join("f1.backup")), 0o600);
    let backups = root.join(".calve/backups");
    if backups.exists() {
        assert_eq!(mode(&backups), 0o700);
    }
}
