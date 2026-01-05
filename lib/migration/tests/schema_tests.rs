#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)]

mod fixtures;

#[path = "test/certificate.rs"]
mod certificate_tests;
#[path = "test/credential_schema.rs"]
mod credential_schema_tests;
#[path = "test/credential.rs"]
mod credential_tests;
#[path = "test/did.rs"]
mod did_tests;
#[path = "test/history.rs"]
mod history_tests;
#[path = "test/interaction.rs"]
mod interaction_tests;
#[path = "test/revocation_list.rs"]
mod revocation_list_tests;
