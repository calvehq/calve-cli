//! G1-TUF step 4: malicious-mirror behaviour of Calve's transport + target download.
//! A local HTTP server serves a real repository but can misbehave per path: endless body,
//! huge Content-Length, slow drip, hang, wrong bytes, 5xx. Every case must end in one bounded
//! error (no spin, no unbounded memory, no retry storm) within the configured deadline.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use calve_app::catalog::tuf::{Limits, Mirror, TrustClient, TrustError};
use calve_testkit::tuf::*;
use jiff::Timestamp;

#[derive(Clone, Copy, Debug)]
enum Bad {
    Endless,
    HugeLength,
    Drip,
    Hang,
    Status(u16),
    Replace(&'static [u8]),
}

struct Server {
    base: String,
    hits: Arc<Mutex<BTreeMap<String, u32>>>,
    bad: Arc<Mutex<BTreeMap<String, Bad>>>,
    /// Every request header line received.
    headers: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start(root: PathBuf) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let hits: Arc<Mutex<BTreeMap<String, u32>>> = Arc::default();
        let bad: Arc<Mutex<BTreeMap<String, Bad>>> = Arc::default();
        let headers: Arc<Mutex<Vec<String>>> = Arc::default();
        let (h, b, hd) = (hits.clone(), bad.clone(), headers.clone());
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let (root, h, b, hd) = (root.clone(), h.clone(), b.clone(), hd.clone());
                std::thread::spawn(move || {
                    let mut line = String::new();
                    let mut r = BufReader::new(s.try_clone().unwrap());
                    if r.read_line(&mut line).is_err() {
                        return;
                    }
                    loop {
                        let mut l = String::new();
                        if r.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
                            break;
                        }
                        hd.lock().unwrap().push(l.trim_end().to_owned());
                    }
                    let path = line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .trim_start_matches('/')
                        .to_owned();
                    *h.lock().unwrap().entry(path.clone()).or_default() += 1;
                    let behaviour = b.lock().unwrap().get(&path).copied();
                    let _ = match behaviour {
                        None => match std::fs::read(root.join(&path)) {
                            Ok(body) => s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).and_then(|_| s.write_all(&body)),
                            Err(_) => s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                        },
                        Some(Bad::Replace(body)) => s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).and_then(|_| s.write_all(body)),
                        Some(Bad::Status(c)) => s.write_all(format!("HTTP/1.1 {c} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()),
                        Some(Bad::HugeLength) => s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000000\r\n\r\n").map(|_| std::thread::sleep(Duration::from_secs(30))),
                        Some(Bad::Hang) => {
                            std::thread::sleep(Duration::from_secs(30));
                            Ok(())
                        }
                        Some(Bad::Endless) => s.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").and_then(|_| loop {
                            s.write_all(&[b'A'; 65536])?;
                        }),
                        Some(Bad::Drip) => s.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").and_then(|_| loop {
                            s.write_all(b"A")?;
                            std::thread::sleep(Duration::from_millis(200));
                        }),
                    };
                });
            }
        });
        Server {
            base,
            hits,
            bad,
            headers,
        }
    }
    fn misbehave(&self, path: &str, b: Bad) {
        self.bad.lock().unwrap().insert(path.into(), b);
    }
    fn hits(&self, path: &str) -> u32 {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }
}

const DEADLINE: Duration = Duration::from_secs(2);

fn setup() -> (Repo, Server, TrustClient) {
    let mut r = Repo::new();
    r.targets
        .insert("acme/1.0.0/pkg".into(), b"genuine-payload".to_vec());
    r.publish();
    let s = Server::start(r.path().to_owned());
    let m = Mirror::http(
        &format!("{}/metadata", s.base),
        &format!("{}/targets", s.base),
        DEADLINE,
    );
    let c = TrustClient::new(m, &r.root_bytes(1), None, Limits::default()).unwrap();
    (r, s, c)
}

fn target_url() -> String {
    format!("targets/acme/1.0.0/{}.pkg", sha(b"genuine-payload"))
}

/// Runs `f`, asserting it fails within the deadline plus slack.
fn bounded<T: std::fmt::Debug>(what: &str, f: impl FnOnce() -> Result<T, TrustError>) -> String {
    let t0 = Instant::now();
    let r = f();
    let el = t0.elapsed();
    let e = r.expect_err(what).to_string();
    assert!(
        el < DEADLINE + Duration::from_secs(2),
        "{what}: took {el:?}"
    );
    println!("{what}: {el:?}: {e}");
    e
}

#[test]
fn genuine_mirror_works() {
    let (_r, _s, mut c) = setup();
    c.refresh(Timestamp::now()).unwrap();
    let t = c
        .resolve("acme/1.0.0/pkg", Timestamp::now())
        .unwrap()
        .unwrap();
    assert_eq!(c.download(&t).unwrap(), b"genuine-payload");
}

#[test]
fn endless_metadata_is_capped() {
    let (_r, s, mut c) = setup();
    s.misbehave("metadata/timestamp.json", Bad::Endless);
    bounded("endless timestamp", || c.refresh(Timestamp::now()));
}

#[test]
fn target_attacks_end_in_one_bounded_error() {
    for (name, bad) in [
        ("endless body", Bad::Endless),
        ("huge content-length", Bad::HugeLength),
        ("slow drip", Bad::Drip),
        ("hang", Bad::Hang),
        ("server error", Bad::Status(500)),
        ("wrong bytes, same length", Bad::Replace(b"evil!!!-payload")),
        (
            "longer than pinned",
            Bad::Replace(b"genuine-payload-and-more"),
        ),
        ("shorter than pinned", Bad::Replace(b"genuine")),
    ] {
        let (_r, s, mut c) = setup();
        c.refresh(Timestamp::now()).unwrap();
        let t = c
            .resolve("acme/1.0.0/pkg", Timestamp::now())
            .unwrap()
            .unwrap();
        s.misbehave(&target_url(), bad);
        bounded(name, || c.download(&t));
        // Exactly one request: the error is final, nothing keeps consuming or retrying.
        assert_eq!(s.hits(&target_url()), 1, "{name}");
    }
}

#[test]
fn missing_target_is_an_error_not_a_hang() {
    let (r, _s, mut c) = setup();
    c.refresh(Timestamp::now()).unwrap();
    let t = c
        .resolve("acme/1.0.0/pkg", Timestamp::now())
        .unwrap()
        .unwrap();
    std::fs::remove_file(r.path().join(target_url())).unwrap();
    bounded("404 target", || c.download(&t));
}

#[test]
fn metadata_hang_and_errors_are_bounded() {
    for (p, b) in [
        ("metadata/timestamp.json", Bad::Hang),
        ("metadata/1.snapshot.json", Bad::Drip),
        ("metadata/2.root.json", Bad::Status(500)),
    ] {
        let (_r, s, mut c) = setup();
        s.misbehave(p, b);
        bounded(p, || c.refresh(Timestamp::now()));
    }
}

#[test]
fn mirror_paths_cannot_escape_the_base() {
    use sigstore_tuf::Repository;
    let r = Repo::new();
    for m in [
        Mirror::dir(r.path()),
        Mirror::http(
            "http://127.0.0.1:9/metadata",
            "http://127.0.0.1:9/targets",
            DEADLINE,
        ),
    ] {
        for p in [
            "../x",
            "a/../../x",
            "/etc/passwd",
            "a\\..\\x",
            "",
            "a//b",
            "./a",
        ] {
            let e = futures_executor::block_on(m.fetch_target(p, 10)).expect_err(p);
            assert!(e.to_string().contains("refusing"), "{p}: {e}");
        }
        assert!(futures_executor::block_on(m.fetch_metadata("a/b.json", 10)).is_err());
    }
}

#[test]
fn oversized_local_files_are_capped_too() {
    use sigstore_tuf::Repository;
    let r = Repo::new();
    std::fs::write(r.path().join("metadata/timestamp.json"), vec![b' '; 20_000]).unwrap();
    let e =
        futures_executor::block_on(Mirror::dir(r.path()).fetch_metadata("timestamp.json", 16_384))
            .unwrap_err();
    assert!(e.to_string().contains("exceeds"));
}

/// M2 requirement 9: outbound catalog requests identify only the product and version — no
/// e-mail address, user or host name, credential or local path in any header.
#[test]
fn requests_carry_no_personal_or_local_data() {
    let (_r, s, mut c) = setup();
    c.refresh(Timestamp::now()).unwrap();
    let t = c
        .resolve("acme/1.0.0/pkg", Timestamp::now())
        .unwrap()
        .unwrap();
    c.download(&t).unwrap();
    let headers = s.headers.lock().unwrap().clone();
    assert!(!headers.is_empty());
    let want_ua = format!("user-agent: calve/{}", env!("CARGO_PKG_VERSION"));
    let home = std::env::var("HOME").unwrap_or_default();
    let user = std::env::var("USER").unwrap_or_default();
    for h in &headers {
        let lower = h.to_ascii_lowercase();
        let name = lower.split(':').next().unwrap_or("");
        assert!(
            [
                "host",
                "user-agent",
                "accept",
                "accept-encoding",
                "connection"
            ]
            .contains(&name),
            "unexpected header {h}"
        );
        if name == "user-agent" {
            assert_eq!(lower, want_ua);
        }
        assert!(!h.contains('@'), "{h}");
        assert!(home.is_empty() || !h.contains(&home), "{h}");
        assert!(
            user.len() < 3 || !lower.contains(&user.to_ascii_lowercase()),
            "{h}"
        );
        assert!(
            !lower.starts_with("authorization") && !lower.starts_with("cookie"),
            "{h}"
        );
    }
}
