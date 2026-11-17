//! Signed extension catalogs (rev 10 §9): the TUF adapter ([`tuf`]), trust-state generations
//! ([`state`]) and package installation ([`install`]).

pub mod install;
pub mod state;
pub mod tuf;
