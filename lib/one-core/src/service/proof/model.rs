use crate::{model::credential::Credential, provider::transport_protocol::dto::ProofClaimSchema};

#[derive(Default)]
pub(super) struct CredentialGroup {
    pub claims: Vec<ProofClaimSchema>,
    pub applicable_credentials: Vec<Credential>,
}
