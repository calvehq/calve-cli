//! The stable error and exit-code contract (PLAN §41, §17.1; ADR 0020).
//!
//! Every product error has a code from [`CODES`]; the code fixes the exit status. A product
//! message may carry its code as a `CODE: message` prefix ([`split_code`]); the API's `Fault`
//! then exposes the code and the message without it. OpenAEVC errors are mapped onto these codes
//! with the original structured error kept in `Fault::detail` ([`openaevc_code`]).

/// Exit statuses (docs/reference/exit-codes.md).
pub mod exit {
    pub const OK: i32 = 0;
    pub const GENERAL: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const CONFLICT: i32 = 3;
    pub const NOT_FOUND: i32 = 4;
    pub const DENIED: i32 = 5;
    pub const INCOMPATIBLE: i32 = 6;
    pub const RECOVERY: i32 = 7;
    pub const UNAVAILABLE: i32 = 8;
    pub const REJECTED: i32 = 9;
    pub const CANCELLED: i32 = 130;
}

/// Every product error code with its exit status. The 25 §41 codes come first.
pub const CODES: &[(&str, i32)] = &[
    // §41
    ("PROJECT_NOT_FOUND", exit::NOT_FOUND),
    ("PROJECT_IDENTITY_CONFLICT", exit::CONFLICT),
    ("PROJECT_LOCKED", exit::CONFLICT),
    ("WORKSPACE_NOT_FOUND", exit::NOT_FOUND),
    ("INVALID_CONFIGURATION", exit::USAGE),
    ("OPENAEVC_INCOMPATIBLE", exit::INCOMPATIBLE),
    ("OPENAEVC_OPERATION_REJECTED", exit::REJECTED),
    ("CAPABILITY_DENIED", exit::DENIED),
    ("STALE_VIEW", exit::CONFLICT),
    ("REVIEW_STALE", exit::CONFLICT),
    ("EXTENSION_NOT_INSTALLED", exit::NOT_FOUND),
    ("EXTENSION_INCOMPATIBLE", exit::INCOMPATIBLE),
    ("EXTENSION_PERMISSION_REQUIRED", exit::DENIED),
    ("PROVIDER_UNAVAILABLE", exit::UNAVAILABLE),
    ("HARNESS_UNAVAILABLE", exit::UNAVAILABLE),
    ("SECRET_UNAVAILABLE", exit::UNAVAILABLE),
    ("RESOURCE_DIVERGED", exit::CONFLICT),
    ("UNSAFE_MATERIALIZATION", exit::CONFLICT),
    ("DAEMON_UNAVAILABLE", exit::UNAVAILABLE),
    ("DAEMON_INCOMPATIBLE", exit::INCOMPATIBLE),
    ("MIGRATION_REQUIRED", exit::RECOVERY),
    ("RECOVERY_REQUIRED", exit::RECOVERY),
    ("CORRUPT_PRODUCT_STATE", exit::RECOVERY),
    ("UNSUPPORTED_PLATFORM_FEATURE", exit::INCOMPATIBLE),
    ("USER_CANCELLED", exit::CANCELLED),
    // General
    ("PRODUCT_ERROR", exit::GENERAL),
    ("IO_ERROR", exit::GENERAL),
    ("INTERNAL", exit::GENERAL),
    ("INVALID_ARGUMENT", exit::USAGE),
    ("NOT_FOUND", exit::NOT_FOUND),
    ("ALREADY_EXISTS", exit::CONFLICT),
    ("CONFIRMATION_REQUIRED", exit::DENIED),
    ("UNSUPPORTED_API_VERSION", exit::INCOMPATIBLE),
    ("CONFIG_UNAPPROVED", exit::DENIED),
    ("REQUEST_IN_PROGRESS", exit::CONFLICT),
    ("REQUEST_ID_REUSED", exit::CONFLICT),
    ("CATALOG_RECOVERY_REQUIRED", exit::RECOVERY),
    ("UNSUPPORTED_PAYLOAD_VERSION", exit::INCOMPATIBLE),
    ("INVALID_OPERATION_KIND", exit::GENERAL),
    // Catalog and packages (rev 10)
    ("CATALOG_STALE", exit::UNAVAILABLE),
    ("CATALOG_UNTRUSTED", exit::REJECTED),
    ("CATALOG_POLICY", exit::REJECTED),
    ("EXTENSION_REVOKED", exit::REJECTED),
    ("EXTENSION_IN_USE", exit::CONFLICT),
    ("EXTENSION_IDENTITY_MISMATCH", exit::REJECTED),
    ("PUBLISHER_NOT_AUTHORIZED", exit::DENIED),
    ("PACKAGE_INVALID", exit::REJECTED),
    ("PACKAGE_TAMPERED", exit::REJECTED),
    ("T2_ACKNOWLEDGMENT_REQUIRED", exit::DENIED),
    ("CHECK_PLAN_UNAPPROVED", exit::DENIED),
    ("CHECK_PLAN_CHANGED", exit::CONFLICT),
    // CIC
    ("INCOMPATIBLE_CIC", exit::INCOMPATIBLE),
    ("ABI_VIOLATION", exit::REJECTED),
    ("TRAPPED", exit::REJECTED),
    ("OUT_OF_FUEL", exit::REJECTED),
    ("DEADLINE_EXCEEDED", exit::REJECTED),
    ("OUT_OF_MEMORY", exit::REJECTED),
    ("RELATION_FAILED", exit::REJECTED),
    ("RELATION_REFUSED", exit::REJECTED),
    ("RELATION_SCHEMA_INVALID", exit::REJECTED),
    // Capture, content, materialization
    ("CAPTURE_DIVERGED", exit::CONFLICT),
    ("CAPTURE_REFUSED", exit::REJECTED),
    ("CAPTURE_INCOMPLETE", exit::REJECTED),
    ("UNSTABLE_FILE", exit::CONFLICT),
    ("FILE_TOO_LARGE", exit::REJECTED),
    ("LIMIT_EXCEEDED", exit::REJECTED),
    ("SUPERSEDE_CONFLICT", exit::CONFLICT),
    ("SUPERSEDE_DIVERGED", exit::CONFLICT),
    ("MATERIALIZE_CONFLICT", exit::CONFLICT),
    ("CONTENT_CORRUPT", exit::RECOVERY),
    ("CONTENT_NOT_PORTABLE", exit::REJECTED),
    ("CLOSURE_UNCLASSIFIED", exit::REJECTED),
    ("CONTAINMENT_UNAVAILABLE", exit::UNAVAILABLE),
];

/// Exit status of a code; unknown codes are general failures.
pub fn exit_code(code: &str) -> i32 {
    CODES
        .iter()
        .find(|(c, _)| *c == code)
        .map_or(exit::GENERAL, |(_, e)| *e)
}

pub fn is_code(code: &str) -> bool {
    CODES.iter().any(|(c, _)| *c == code)
}

/// `CODE: message` with a known code → `(code, message)`.
pub fn split_code(message: &str) -> Option<(&'static str, &str)> {
    let (head, rest) = message.split_once(": ")?;
    CODES
        .iter()
        .find(|(c, _)| *c == head)
        .map(|(c, _)| (*c, rest))
}

/// The Calve code for an OpenAEVC error code (the original stays in `detail.openaevc`).
pub fn openaevc_code(code: &str) -> &'static str {
    match code {
        "UNAUTHORIZED" | "FORBIDDEN" | "CAPABILITY_EXPIRED" | "CAPABILITY_REVOKED" => {
            "CAPABILITY_DENIED"
        }
        "STALE_GENERATION" | "CONFLICT" => "STALE_VIEW",
        "PROTOCOL_VERSION_UNSUPPORTED" => "OPENAEVC_INCOMPATIBLE",
        "EXTENSION_INCOMPATIBLE" => "EXTENSION_INCOMPATIBLE",
        "RECOVERY_REQUIRED" | "STORAGE_INTEGRITY_ERROR" => "RECOVERY_REQUIRED",
        "NOT_FOUND" => "NOT_FOUND",
        "EFFECT_PRECONDITION_FAILED" | "PRECONDITION_FAILED" => "RESOURCE_DIVERGED",
        "ALREADY_EXISTS" => "ALREADY_EXISTS",
        "INVALID_ARGUMENT" => "INVALID_ARGUMENT",
        "INTERNAL" => "INTERNAL",
        _ => "OPENAEVC_OPERATION_REJECTED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_screaming_snake_and_cover_section_41() {
        let mut seen = std::collections::BTreeSet::new();
        for (c, _) in CODES {
            assert!(seen.insert(*c), "duplicate {c}");
            assert!(
                c.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            );
        }
        assert_eq!(
            CODES
                .iter()
                .take_while(|(c, _)| *c != "PRODUCT_ERROR")
                .count(),
            25
        );
    }

    #[test]
    fn the_exit_code_reference_lists_every_code_with_its_status() {
        let doc = include_str!("../../../docs/reference/exit-codes.md");
        for (code, status) in CODES {
            let row = doc
                .lines()
                .find(|l| l.contains(&format!("`{code}`")))
                .unwrap_or_else(|| panic!("{code} missing from exit-codes.md"));
            assert!(row.starts_with(&format!("| {status} |")), "{code}: {row}");
        }
    }

    #[test]
    fn prefixes_split_only_known_codes() {
        assert_eq!(
            split_code("STALE_VIEW: reload"),
            Some(("STALE_VIEW", "reload"))
        );
        assert_eq!(split_code("Note: something"), None);
        assert_eq!(split_code("plain"), None);
        assert_eq!(exit_code("USER_CANCELLED"), 130);
        assert_eq!(exit_code("SOMETHING_NEW"), 1);
        assert_eq!(openaevc_code("FORBIDDEN"), "CAPABILITY_DENIED");
        assert_eq!(
            openaevc_code("POLICY_DENIED"),
            "OPENAEVC_OPERATION_REJECTED"
        );
    }
}
