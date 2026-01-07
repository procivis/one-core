use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, ProofId};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InteractionExpirationCheckResultDTO {
    pub updated_credentials: Vec<CredentialId>,
    pub updated_proofs: Vec<ProofId>,
}
