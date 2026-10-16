//! `calve.refs/1` reference schemas (rev 10 §13; FG16). A package declares, per effect kind,
//! which JSON pointers of the effect payload hold digests and what they are:
//! `ObjectRef` (an immutable OpenAEVC object that belongs to the transfer closure), `ContentHash`
//! (bytes verified where they live, never walked) or `ExternalCommitment` (recorded, never
//! fetched). The document's SHA-256 is bound into the native manifest as
//! `schemas["calve.refs/1"]` (a content hash: object digests are namespace-specific), so
//! history can be walked and moved without running the extension. Anything unclassified, a
//! pointer that does not resolve or a bound exceeded fails closed.
use std::collections::BTreeMap;

use serde_json::Value;

pub const SCHEMA: &str = "calve.refs/1";
pub const MAX_DEPTH: usize = 16;
pub const MAX_MATCHES: usize = 10_000;
pub const MAX_POINTERS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    ObjectRef,
    ContentHash,
    ExternalCommitment,
}

/// `{effect kind: [(pointer, edge)]}`.
pub type Refs = BTreeMap<String, Vec<(String, Edge)>>;

/// Parses and bounds-checks a refs document.
pub fn parse(doc: &Value) -> Result<Refs, String> {
    if doc["schema"] != SCHEMA {
        return Err(format!("refs schema {} is not {SCHEMA}", doc["schema"]));
    }
    let mut out = BTreeMap::new();
    for (kind, list) in doc["kinds"]
        .as_object()
        .ok_or("refs: `kinds` must be an object")?
    {
        let list = list.as_array().ok_or("refs: pointer list")?;
        if list.len() > MAX_POINTERS {
            return Err(format!(
                "refs: {kind} declares more than {MAX_POINTERS} pointers"
            ));
        }
        let mut v = vec![];
        for p in list {
            let ptr = p["pointer"].as_str().ok_or("refs: pointer")?;
            if !ptr.starts_with('/') || ptr.split('/').count() - 1 > MAX_DEPTH {
                return Err(format!(
                    "refs: pointer {ptr} is not an absolute pointer of depth ≤ {MAX_DEPTH}"
                ));
            }
            let edge = match p["edge"].as_str() {
                Some("ObjectRef") => Edge::ObjectRef,
                Some("ContentHash") => Edge::ContentHash,
                Some("ExternalCommitment") => Edge::ExternalCommitment,
                other => return Err(format!("refs: edge {other:?}")),
            };
            v.push((ptr.to_owned(), edge));
        }
        out.insert(kind.clone(), v);
    }
    Ok(out)
}

/// RFC 6901 with `*` matching every array element; bounded depth and match count. A pointer
/// that resolves to nothing is an error (fail closed).
pub fn resolve<'a>(v: &'a Value, pointer: &str) -> Result<Vec<&'a Value>, String> {
    let segs: Vec<String> = pointer
        .split('/')
        .skip(1)
        .map(|s| s.replace("~1", "/").replace("~0", "~"))
        .collect();
    if !pointer.starts_with('/') || segs.len() > MAX_DEPTH {
        return Err(format!("pointer {pointer}"));
    }
    let mut cur = vec![v];
    for seg in &segs {
        let mut next = vec![];
        for node in cur {
            match (seg.as_str(), node) {
                ("*", Value::Array(a)) => next.extend(a.iter()),
                (k, Value::Object(m)) => next.extend(m.get(k)),
                (i, Value::Array(a)) => next.extend(i.parse::<usize>().ok().and_then(|i| a.get(i))),
                _ => {}
            }
        }
        if next.len() > MAX_MATCHES {
            return Err(format!(
                "pointer {pointer} matches more than {MAX_MATCHES} values"
            ));
        }
        cur = next;
    }
    if cur.is_empty() {
        return Err(format!("pointer {pointer} does not resolve"));
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_bounds_and_resolves_wildcards() {
        let doc = json!({"schema": SCHEMA, "kinds": {
            "x.put": [{"pointer": "/chunks/*/blob_digest", "edge": "ObjectRef"}, {"pointer": "/digest", "edge": "ContentHash"}],
            "x.delete": []}});
        let r = parse(&doc).unwrap();
        assert_eq!(r["x.put"][0].1, Edge::ObjectRef);
        let payload =
            json!({"digest": "d", "chunks": [{"blob_digest": "a"}, {"blob_digest": "b"}]});
        assert_eq!(resolve(&payload, "/chunks/*/blob_digest").unwrap().len(), 2);
        assert!(resolve(&payload, "/missing").is_err());
        assert!(parse(&json!({"schema": "calve.refs/2", "kinds": {}})).is_err());
        assert!(
            parse(&json!({"schema": SCHEMA, "kinds": {"k": [{"pointer": "/a", "edge": "Bogus"}]}}))
                .is_err()
        );
        let deep = format!("/{}", vec!["a"; MAX_DEPTH + 1].join("/"));
        assert!(
            parse(
                &json!({"schema": SCHEMA, "kinds": {"k": [{"pointer": deep, "edge": "ObjectRef"}]}})
            )
            .is_err()
        );
    }
}
