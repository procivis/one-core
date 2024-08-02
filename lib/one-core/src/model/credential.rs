use super::claim::{Claim, ClaimRelations};
use super::common::GetListResponse;
use super::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use super::did::{Did, DidRelations};
use super::interaction::{Interaction, InteractionId, InteractionRelations};
use super::list_query::ListQuery;
use super::revocation_list::{RevocationList, RevocationListRelations};
use crate::model::key::KeyRelations;
use crate::service::credential::dto::{CredentialFilterValue, CredentialListIncludeEntityTypeEnum};
use dto_mapper::{convert_inner, convert_inner_of_inner, Into};
use one_providers::common_models::key::Key;
use shared_types::{CredentialId, DidId, KeyId};
use strum_macros::Display;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq, Into)]
#[into(one_providers::common_models::credential::Credential)]
pub struct Credential {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub credential: Vec<u8>,
    pub exchange: String,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,

    // Relations:
    #[into(with_fn = "convert_inner_of_inner")]
    pub state: Option<Vec<CredentialState>>,
    #[into(with_fn = "convert_inner_of_inner")]
    pub claims: Option<Vec<Claim>>,
    #[into(with_fn = "convert_inner")]
    pub issuer_did: Option<Did>,
    #[into(with_fn = "convert_inner")]
    pub holder_did: Option<Did>,
    #[into(with_fn = "convert_inner")]
    pub schema: Option<CredentialSchema>,
    #[into(with_fn = "convert_inner")]
    pub interaction: Option<Interaction>,
    #[into(skip)]
    pub revocation_list: Option<RevocationList>,
    #[into(with_fn = "convert_inner")]
    pub key: Option<Key>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CredentialRelations {
    pub state: Option<CredentialStateRelations>,
    pub claims: Option<ClaimRelations>,
    pub issuer_did: Option<DidRelations>,
    pub holder_did: Option<DidRelations>,
    pub schema: Option<CredentialSchemaRelations>,
    pub interaction: Option<InteractionRelations>,
    pub revocation_list: Option<RevocationListRelations>,
    pub key: Option<KeyRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Into)]
#[into(one_providers::common_models::credential::CredentialState)]
pub struct CredentialState {
    pub created_date: OffsetDateTime,
    pub state: CredentialStateEnum,
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Display, Into)]
#[into(one_providers::common_models::credential::CredentialStateEnum)]
pub enum CredentialStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Suspended,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CredentialStateRelations {}

pub enum SortableCredentialColumn {
    CreatedDate,
    SchemaName,
    IssuerDid,
    State,
}

pub type GetCredentialList = GetListResponse<Credential>;
pub type GetCredentialQuery =
    ListQuery<SortableCredentialColumn, CredentialFilterValue, CredentialListIncludeEntityTypeEnum>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateCredentialRequest {
    pub id: CredentialId,

    pub credential: Option<Vec<u8>>,
    pub holder_did_id: Option<DidId>,
    pub issuer_did_id: Option<DidId>,
    pub state: Option<CredentialState>,
    pub interaction: Option<InteractionId>,
    pub key: Option<KeyId>,
    pub redirect_uri: Option<Option<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Into)]
#[into(one_providers::common_models::credential::CredentialRole)]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}
