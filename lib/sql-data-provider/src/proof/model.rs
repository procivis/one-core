use sea_orm::FromQueryResult;
use shared_types::{DidId, DidValue, ProofId, ProofSchemaId};
use time::OffsetDateTime;

use crate::entity::did::DidType;

/// temporary struct to map items returned from the list DB query
#[derive(FromQueryResult)]
pub(super) struct ProofListItemModel {
    // proof
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub exchange: String,
    pub transport: String,
    pub redirect_uri: Option<String>,

    // verifier_did
    pub verifier_did_id: Option<DidId>,
    pub verifier_did: Option<DidValue>,
    pub verifier_did_created_date: Option<OffsetDateTime>,
    pub verifier_did_last_modified: Option<OffsetDateTime>,
    pub verifier_did_name: Option<String>,
    pub verifier_did_type: Option<DidType>,
    pub verifier_did_method: Option<String>,

    // proof_schema
    pub schema_id: ProofSchemaId,
    pub schema_name: String,
    pub schema_created_date: OffsetDateTime,
    pub schema_last_modified: OffsetDateTime,
    pub expire_duration: u32,
}
