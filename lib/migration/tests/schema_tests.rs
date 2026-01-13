#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)]

mod fixtures;

#[path = "test/blob_storage.rs"]
mod blob_storage_tests;
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
#[path = "test/identifier.rs"]
mod identifier_tests;
#[path = "test/interaction.rs"]
mod interaction_tests;
#[path = "test/key.rs"]
mod key_tests;
#[path = "test/organisation.rs"]
mod organisation_tests;
#[path = "test/proof_schema.rs"]
mod proof_schema_tests;
#[path = "test/proof.rs"]
mod proof_tests;
#[path = "test/remote_entity_cache.rs"]
mod remote_entity_cache_tests;
#[path = "test/revocation_list.rs"]
mod revocation_list_tests;
#[path = "test/trust.rs"]
mod trust_tests;
