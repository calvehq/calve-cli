//! First-party go language extension. Depends only on `calve-domain` and OpenAEVC
//! contract crates, never on Calve internals.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    calve_domain::language::serve_language("go")
}
