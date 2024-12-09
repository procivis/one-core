use one_core::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialListIncludeEntityTypeEnum,
    CredentialListItemResponseDTO, CredentialRequestClaimDTO, CredentialRevocationCheckResponseDTO,
    CredentialRole, CredentialStateEnum, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO, DetailCredentialSchemaResponseDTO,
    MdocMsoValidityResponseDTO, SuspendCredentialRequestDTO,
};
use one_dto_mapper::{convert_inner, From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, CredentialSchemaId, KeyId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::endpoint::credential_schema::dto::{
    CredentialClaimSchemaResponseRestDTO, CredentialSchemaLayoutPropertiesRestDTO,
    CredentialSchemaLayoutType, CredentialSchemaListItemResponseRestDTO, CredentialSchemaType,
    WalletStorageTypeRestEnum,
};
use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::serialize::{front_time, front_time_option};

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialListItemResponseDTO)]
pub struct CredentialListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateRestEnum,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub schema: CredentialSchemaListItemResponseRestDTO,
    #[from(with_fn = convert_inner)]
    pub issuer_did: Option<DidListItemResponseRestDTO>,
    pub role: CredentialRoleRestEnum,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(MdocMsoValidityResponseDTO)]
pub struct MdocMsoValidityResponseRestDTO {
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub expiration: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub next_update: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_update: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(CredentialDetailResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct GetCredentialResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateRestEnum,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub schema: CredentialDetailSchemaResponseRestDTO,
    #[from(with_fn = convert_inner)]
    pub issuer_did: Option<DidListItemResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialDetailClaimResponseRestDTO>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRoleRestEnum,
    /// See the [LVVC guide](../guides/lvvc.mdx).
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub lvvc_issuance_date: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub suspend_end_date: Option<OffsetDateTime>,
    #[from(with_fn = convert_inner)]
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub holder_did: Option<DidListItemResponseRestDTO>,
}

/// See the [credential roles](../api/credentials.mdx#credential-roles) guide.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[from(CredentialRole)]
#[into(CredentialRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialRoleRestEnum {
    Holder,
    Issuer,
    Verifier,
}

/// Credential schema being used to issue the credential.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DetailCredentialSchemaResponseDTO)]
pub struct CredentialDetailSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[serde(
        serialize_with = "front_time_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
    /// Indication of what type of key storage the wallet should use. See the [wallet storage type](../api/credentialSchemas.mdx#wallet-storage-type) guide.
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    /// See the [credentialSchema property](../api/credentialSchemas.mdx#credentialschema-property) guide.
    pub schema_id: String,
    pub schema_type: CredentialSchemaType,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DetailCredentialClaimResponseDTO)]
pub struct CredentialDetailClaimResponseRestDTO {
    pub path: String,
    pub schema: CredentialClaimSchemaResponseRestDTO,
    pub value: CredentialDetailClaimValueResponseRestDTO,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(DetailCredentialClaimValueResponseDTO)]
#[serde(untagged)]
pub enum CredentialDetailClaimValueResponseRestDTO {
    Boolean(bool),
    Float(f64),
    Integer(i64),
    String(String),
    #[schema(no_recursion)]
    Nested(#[from(with_fn = convert_inner)] Vec<CredentialDetailClaimResponseRestDTO>),
}

/// See the [credential states](../api/credentials.mdx#credential-states) guide.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(CredentialStateEnum)]
#[into(one_core::model::credential::CredentialStateEnum)]
pub enum CredentialStateRestEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Suspended,
    Rejected,
    Revoked,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SearchType {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsFilterQueryParamsRest {
    pub organisation_id: OrganisationId,
    #[param(nullable = false)]
    pub name: Option<String>,
    #[param(nullable = false)]
    pub role: Option<CredentialRoleRestEnum>,
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<CredentialId>>,
    #[param(rename = "status[]", inline, nullable = false)]
    pub status: Option<Vec<CredentialStateRestEnum>>,
    #[param(nullable = false)]
    pub search_text: Option<String>,
    #[param(rename = "searchType[]", inline, nullable = false)]
    pub search_type: Option<Vec<SearchType>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialListIncludeEntityTypeEnum)]
pub enum CredentialListIncludeEntityTypeRestEnum {
    LayoutProperties,
}

pub type GetCredentialQuery = ListQueryParamsRest<
    CredentialsFilterQueryParamsRest,
    SortableCredentialColumnRestEnum,
    CredentialListIncludeEntityTypeRestEnum,
>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::credential::SortableCredentialColumn")]
pub enum SortableCredentialColumnRestEnum {
    CreatedDate,
    #[serde(rename = "schema.name")]
    SchemaName,
    IssuerDid,
    State,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(CreateCredentialRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialRequestRestDTO {
    /// ID of the credential schema used to issue the credential.
    pub credential_schema_id: CredentialSchemaId,
    /// ID of the issuer DID used to issue the credential.
    pub issuer_did: Uuid,
    /// If multiple keys are specified for the assertion method of the DID,
    /// use this value to specify which key should be used as the assertion
    /// method for this credential. If a key isn't specified here, the first
    /// key listed during DID creation will be used.
    #[into(with_fn = convert_inner)]
    pub issuer_key: Option<KeyId>,
    /// Exchange protocol used. See the [exchange
    /// protocols](../api/exchangeProtocols.mdx) guide.
    pub exchange: String,
    /// Attribute from the credential schema, together with the
    /// corresponding claim being made. See the
    /// [claimValues](../api/credentials.mdx#claimvalues) guide.
    #[into(with_fn = convert_inner)]
    pub claim_values: Vec<CredentialRequestClaimRestDTO>,
    /// When a credential is accepted, the holder will be redirected to the
    /// resource specified here.
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialRequestClaimDTO)]
pub struct CredentialRequestClaimRestDTO {
    /// ID of the attribute from the credential schema.
    #[into(rename = "claim_schema_id")]
    pub claim_id: Uuid,
    /// Claim being asserted in issuance.
    pub value: String,
    /// Path to the particular claim key within the structure of the credential schema.
    pub path: String,
}

/// Array of credentials to be checked for revocation status.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRevocationCheckRequestRestDTO {
    pub credential_ids: Vec<CredentialId>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into(SuspendCredentialRequestDTO)]
pub struct SuspendCredentialRequestRestDTO {
    /// Specify the time when the credential will reactivate, or pass `{}` for an indefinite suspension.
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialRevocationCheckResponseDTO)]
pub struct CredentialRevocationCheckResponseRestDTO {
    pub credential_id: Uuid,
    pub status: CredentialStateRestEnum,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
