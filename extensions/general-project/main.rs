//! First-party general-project extension; see `calve_domain::general`.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    calve_domain::general::serve()
}
