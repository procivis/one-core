#![allow(clippy::unwrap_used)]

mod fixtures;

#[path = "test/credential.rs"]
mod credential_tests;

#[path = "test/history.rs"]
mod history_tests;

#[path = "test/interaction.rs"]
mod interaction_tests;

#[path = "test/revocation_list.rs"]
mod revocation_list_tests;

#[path = "test/random_checks.rs"]
mod random_checks;
