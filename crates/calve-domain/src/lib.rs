//! First-party domain logic compiled into Calve's extension binaries. It depends only on
//! OpenAEVC contract crates so extensions never link Calve internals.
#![forbid(unsafe_code)]

pub mod general;
pub mod language;
