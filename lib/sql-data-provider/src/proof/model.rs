use crate::entity::did::DidType;
use sea_orm::FromQueryResult;
use time::OffsetDateTime;

/// temporary struct to map items returned from the list DB query
#[derive(FromQueryResult)]
pub(super) struct ProofListItemModel {
    // proof
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub transport: String,

    // verifier_did
    pub verifier_did_id: String,
    pub verifier_did: String,
    pub verifier_did_created_date: OffsetDateTime,
    pub verifier_did_last_modified: OffsetDateTime,
    pub verifier_did_name: String,
    pub verifier_did_type: DidType,
    pub verifier_did_method: String,
    pub organisation_id: String,

    // proof_schema
    pub schema_id: String,
    pub schema_name: String,
    pub schema_created_date: OffsetDateTime,
    pub schema_last_modified: OffsetDateTime,
    pub expire_duration: u32,
}
