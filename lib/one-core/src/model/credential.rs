use dto_mapper::{convert_inner, convert_inner_of_inner, From, Into};
use one_providers::common_models::credential::OpenCredential;
use one_providers::common_models::key::OpenKey;
use shared_types::{CredentialId, DidId, KeyId};
use strum_macros::Display;
use time::OffsetDateTime;

use super::claim::{Claim, ClaimRelations};
use super::common::GetListResponse;
use super::credential_schema::{
    to_open_credential_schema, CredentialSchema, CredentialSchemaRelations,
};
use super::did::{Did, DidRelations};
use super::interaction::{Interaction, InteractionId, InteractionRelations};
use super::list_query::ListQuery;
use super::revocation_list::{RevocationList, RevocationListRelations};
use crate::model::key::KeyRelations;
use crate::service::credential::dto::{CredentialFilterValue, CredentialListIncludeEntityTypeEnum};
use crate::service::error::ServiceError;

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(OpenCredential)]
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
    #[from(with_fn = "convert_inner_of_inner")]
    pub state: Option<Vec<CredentialState>>,

    #[from(with_fn = "convert_inner_of_inner")]
    pub claims: Option<Vec<Claim>>,

    #[from(with_fn = "convert_inner")]
    pub issuer_did: Option<Did>,

    #[from(with_fn = "convert_inner")]
    pub holder_did: Option<Did>,

    #[from(with_fn = "convert_inner")]
    pub schema: Option<CredentialSchema>,

    #[from(with_fn = "convert_inner")]
    pub interaction: Option<Interaction>,

    #[from(replace = None)]
    pub revocation_list: Option<RevocationList>,

    #[from(with_fn = "convert_inner")]
    pub key: Option<OpenKey>,
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

#[derive(Clone, Debug, Eq, PartialEq, From, Into)]
#[from(one_providers::common_models::credential::OpenCredentialState)]
#[into(one_providers::common_models::credential::OpenCredentialState)]
pub struct CredentialState {
    pub created_date: OffsetDateTime,
    pub state: CredentialStateEnum,
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Display, From, Into)]
#[from(one_providers::common_models::credential::OpenCredentialStateEnum)]
#[into(one_providers::common_models::credential::OpenCredentialStateEnum)]
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

#[derive(Clone, Debug, Default, Eq, PartialEq, From)]
#[from(one_providers::common_models::credential::OpenUpdateCredentialRequest)]
pub struct UpdateCredentialRequest {
    pub id: CredentialId,

    pub credential: Option<Vec<u8>>,
    #[from(with_fn = convert_inner)]
    pub holder_did_id: Option<DidId>,
    #[from(with_fn = convert_inner)]
    pub issuer_did_id: Option<DidId>,
    #[from(with_fn = convert_inner)]
    pub state: Option<CredentialState>,
    #[from(with_fn = convert_inner)]
    pub interaction: Option<InteractionId>,
    #[from(with_fn = convert_inner)]
    pub key: Option<KeyId>,
    pub redirect_uri: Option<Option<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, From, Into)]
#[from(one_providers::common_models::credential::OpenCredentialRole)]
#[into(one_providers::common_models::credential::OpenCredentialRole)]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}

pub(crate) async fn to_open_credential(value: Credential) -> Result<OpenCredential, ServiceError> {
    let schema = if let Some(schema) = value.schema {
        Some(to_open_credential_schema(schema).await?)
    } else {
        None
    };
    Ok(OpenCredential {
        id: value.id.into(),
        created_date: value.created_date,
        last_modified: value.last_modified,
        deleted_at: value.deleted_at,
        issuance_date: value.issuance_date,
        credential: value.credential,
        exchange: value.exchange,
        redirect_uri: value.redirect_uri,
        role: value.role.into(),
        state: convert_inner_of_inner(value.state),
        claims: convert_inner_of_inner(value.claims),
        issuer_did: convert_inner(value.issuer_did),
        holder_did: convert_inner(value.holder_did),
        schema,
        key: convert_inner(value.key),
        interaction: convert_inner(value.interaction),
    })
}
