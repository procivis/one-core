mod fixtures;
mod utils;

// CREDENTIAL
#[path = "api/credential/create_credential_tests.rs"]
mod create_credential_tests;

// PROOF
#[path = "api/proof/create_proof_tests.rs"]
mod create_proof_tests;
#[path = "api/proof/get_presentation_definition_tests.rs"]
mod get_presentation_definition_tests;

// INTERACTION
#[path = "api/interaction/handle_invitation_tests.rs"]
mod handle_invitation_tests;
