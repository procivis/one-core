#![allow(clippy::unwrap_used)]

mod fixtures;

#[path = "test/credential.rs"]
mod credential_tests;

#[path = "test/interaction.rs"]
mod interaction_tests;

#[path = "test/random_checks.rs"]
mod random_checks;
