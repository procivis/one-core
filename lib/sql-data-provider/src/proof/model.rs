use crate::entity::did::DidType;
use sea_orm::FromQueryResult;
use shared_types::DidValue;
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
    pub verifier_did_id: Option<String>,
    pub verifier_did: Option<DidValue>,
    pub verifier_did_created_date: Option<OffsetDateTime>,
    pub verifier_did_last_modified: Option<OffsetDateTime>,
    pub verifier_did_name: Option<String>,
    pub verifier_did_type: Option<DidType>,
    pub verifier_did_method: Option<String>,

    // proof_schema
    pub schema_id: String,
    pub schema_name: String,
    pub schema_created_date: OffsetDateTime,
    pub schema_last_modified: OffsetDateTime,
    pub expire_duration: u32,
}
