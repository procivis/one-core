#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod utils;

#[path = "api/organisation/mod.rs"]
mod api_organisation_tests;

#[path = "api/credential_schema/mod.rs"]
mod api_credential_schema_tests;

#[path = "api/credential/mod.rs"]
mod api_credential_tests;

#[path = "api/history/mod.rs"]
mod api_history_tests;

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

//DID-RESOLVER
#[path = "api/did_resolver/mod.rs"]
mod api_did_resolver_tests;

//KEY
#[path = "api/key/mod.rs"]
mod api_key_tests;

// SSI
#[path = "api/ssi/mod.rs"]
mod ssi_tests;
