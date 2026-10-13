use std::time::Instant;

use calve_testkit::Env;

/// The change feed returns immediately on change and waits otherwise.
#[test]
fn change_feed_long_polls() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    let first = env.ok(&["--project", p, "view", "changes", "--wait-ms", "0"]);
    let protocol = first["protocol"].to_string();
    let product = first["product"].to_string();
    let started = Instant::now();
    let idle = env.ok(&[
        "--project",
        p,
        "view",
        "changes",
        "--protocol",
        &protocol,
        "--product",
        &product,
        "--wait-ms",
        "600",
    ]);
    assert_eq!(idle["changed"], false);
    assert!(started.elapsed().as_millis() >= 600);
    env.ok(&["--project", p, "intent", "create", "Something"]);
    let moved = env.ok(&[
        "--project",
        p,
        "view",
        "changes",
        "--protocol",
        &protocol,
        "--product",
        &product,
        "--wait-ms",
        "5000",
    ]);
    assert_eq!(moved["changed"], true);
    env.ok(&["--project", p, "pack", "create", "protocol change"]);
    let product = moved["product"].to_string();
    let protocol_moved = env.ok(&[
        "--project",
        p,
        "view",
        "changes",
        "--protocol",
        &protocol,
        "--product",
        &product,
        "--wait-ms",
        "5000",
    ]);
    assert!(protocol_moved["protocol"].as_u64() > first["protocol"].as_u64());
}
