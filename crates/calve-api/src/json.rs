//! `--json` is accepted only by commands that declare it (PLAN §17.1–17.2): exactly those with a
//! JSON Schema in `docs/reference/json/v1/<command>.json`. Output is the envelope
//! `{"api_version":"1","command":"<command>","data":…}` on stdout; errors are
//! `{"api_version":"1","command":…,"error":{code,message,retryable,detail,exit_code}}` on stderr.
//! `cargo xtask json-schemas` regenerates the list and the schemas from recorded outputs and
//! fails on any non-additive change.

include!("json_commands.rs");

/// Whether `calve <key>` declares JSON output.
pub fn declares(key: &str) -> bool {
    COMMANDS.binary_search(&key).is_ok()
}

/// Schema file name of a command (`pack list` → `pack.list.json`).
pub fn schema_file(key: &str) -> String {
    format!("{}.json", key.replace(' ', "."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_list_is_sorted_and_unique() {
        assert!(super::COMMANDS.windows(2).all(|w| w[0] < w[1]));
    }
}
