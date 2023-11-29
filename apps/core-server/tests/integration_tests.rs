mod fixtures;
mod utils;

#[path = "api/organisation/mod.rs"]
mod api_organisation_tests;

#[path = "api/credential_schema/mod.rs"]
mod api_credential_schema_tests;

#[path = "api/credential/mod.rs"]
mod api_credential_tests;

#[path = "api/oidc/mod.rs"]
mod api_oidc_tests;

#[path = "api/proof_schema/mod.rs"]
mod api_proof_schema_tests;

#[path = "api/proof/mod.rs"]
mod api_proof_tests;

#[path = "api/interaction/mod.rs"]
mod api_interaction_tests;

//DID
#[path = "api/did/mod.rs"]
mod api_did_tests;

// SSI
#[path = "api/ssi/get_did_web_document_tests.rs"]
mod get_did_web_document_tests;
