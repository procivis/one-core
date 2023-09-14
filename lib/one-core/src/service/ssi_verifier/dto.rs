use crate::service::credential_schema::dto::{
    ClaimSchemaId, GetCredentialSchemaListValueResponseDTO,
};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct ConnectVerifierResponseDTO {
    pub claims: Vec<ProofRequestClaimDTO>,
    pub verifier_did: String,
}

#[derive(Clone, Debug)]
pub struct ProofRequestClaimDTO {
    pub id: ClaimSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: GetCredentialSchemaListValueResponseDTO,
}

#[derive(Clone, Debug)]
pub(super) struct ValidatedProofClaimDTO {
    pub claim_schema_id: ClaimSchemaId,
    pub value: String,
}
