mod fixtures;
mod utils;

// CREDENTIAL SCHEMA
#[path = "api/credential_schema/create_credential_schema_tests.rs"]
mod create_credential_schema_tests;
#[path = "api/credential_schema/delete_credential_schema_tests.rs"]
mod delete_credential_schema_tests;
#[path = "api/credential_schema/get_credential_schema_tests.rs"]
mod get_credential_schema_tests;
#[path = "api/credential_schema/list_credential_schema_tests.rs"]
mod list_credential_schema_tests;
// CREDENTIAL
#[path = "api/credential/create_credential_tests.rs"]
mod create_credential_tests;
#[path = "api/credential/get_credential_tests.rs"]
mod get_credential_tests;
#[path = "api/credential/list_credential_tests.rs"]
mod list_credential_tests;
#[path = "api/credential/revoke_credential_tests.rs"]
mod revoke_credential_tests;

#[path = "api/credential/share_credential_tests.rs"]
mod share_credential_tests;

// OIDC
#[path = "api/oidc/direct_post_tests.rs"]
mod direct_post_tests;

// PROOF
#[path = "api/proof/create_proof_tests.rs"]
mod create_proof_tests;
#[path = "api/proof/get_presentation_definition_tests.rs"]
mod get_presentation_definition_tests;

// INTERACTION
#[path = "api/interaction/handle_invitation_tests.rs"]
mod handle_invitation_tests;

//DID
#[path = "api/did/update_did_tests.rs"]
mod update_did_tests;
