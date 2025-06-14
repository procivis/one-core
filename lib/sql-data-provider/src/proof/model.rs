use sea_orm::FromQueryResult;
use shared_types::{DidId, DidValue, IdentifierId, ProofId, ProofSchemaId};
use time::OffsetDateTime;

use crate::entity::did::DidType;
use crate::entity::identifier::{IdentifierState, IdentifierType};
use crate::entity::proof::{ProofRequestState, ProofRole};

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
    pub state: ProofRequestState,
    pub role: ProofRole,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,

    // verifier_identifier
    pub verifier_identifier_id: Option<IdentifierId>,
    pub verifier_identifier_created_date: Option<OffsetDateTime>,
    pub verifier_identifier_last_modified: Option<OffsetDateTime>,
    pub verifier_identifier_name: Option<String>,
    pub verifier_identifier_type: Option<IdentifierType>,
    pub verifier_identifier_is_remote: Option<bool>,
    pub verifier_identifier_state: Option<IdentifierState>,

    // verifier_did
    pub verifier_did_id: Option<DidId>,
    pub verifier_did: Option<DidValue>,
    pub verifier_did_created_date: Option<OffsetDateTime>,
    pub verifier_did_last_modified: Option<OffsetDateTime>,
    pub verifier_did_name: Option<String>,
    pub verifier_did_type: Option<DidType>,
    pub verifier_did_method: Option<String>,

    // proof_schema
    pub schema_id: Option<ProofSchemaId>,
    pub schema_name: Option<String>,
    pub schema_created_date: Option<OffsetDateTime>,
    pub schema_last_modified: Option<OffsetDateTime>,
    pub schema_expire_duration: Option<u32>,
    pub schema_imported_source_url: Option<String>,
}
