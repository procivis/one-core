use crate::service::credential_schema::dto::CredentialSchemaListItemResponseDTO;
use one_providers::credential_formatter::model::DetailCredential;
use shared_types::{ClaimSchemaId, DidValue};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct ConnectVerifierResponseDTO {
    pub claims: Vec<ProofRequestClaimDTO>,
    pub redirect_uri: Option<String>,
    pub verifier_did: DidValue,
}

#[derive(Clone, Debug)]
pub struct ProofRequestClaimDTO {
    pub id: ClaimSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: CredentialSchemaListItemResponseDTO,
}

#[derive(Clone, Debug)]
pub(super) struct ValidatedProofClaimDTO {
    pub claim_schema_id: ClaimSchemaId,
    pub credential: DetailCredential,
    pub value: (String, serde_json::Value),
}
