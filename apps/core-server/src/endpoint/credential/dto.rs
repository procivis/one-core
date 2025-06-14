use one_core::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialListIncludeEntityTypeEnum,
    CredentialListItemResponseDTO, CredentialRequestClaimDTO, CredentialRevocationCheckResponseDTO,
    CredentialRole, CredentialStateEnum, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO, DetailCredentialSchemaResponseDTO,
    MdocMsoValidityResponseDTO, SuspendCredentialRequestDTO,
};
use one_dto_mapper::{From, Into, convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{CredentialId, CredentialSchemaId, DidId, IdentifierId, KeyId, OrganisationId};
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
use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::serialize::{front_time, front_time_option};

#[skip_serializing_none]
#[derive(Debug, Serialize, ToSchema, From)]
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
    #[from(with_fn = convert_inner)]
    pub issuer: Option<GetIdentifierListItemResponseRestDTO>,
    pub role: CredentialRoleRestEnum,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub suspend_end_date: Option<OffsetDateTime>,
    pub exchange: String,
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

#[skip_serializing_none]
#[derive(Debug, Serialize, ToSchema, From)]
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
    pub issuer: Option<GetIdentifierListItemResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialDetailClaimResponseRestDTO>,
    pub redirect_uri: Option<String>,
    /// The role the system has in relation to the credential.
    pub role: CredentialRoleRestEnum,
    /// When the current LVVC was issued.
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
    #[from(with_fn = convert_inner)]
    pub holder: Option<GetIdentifierListItemResponseRestDTO>,
    pub exchange: String,
}

/// The role the system has in relation to the credential.
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
#[skip_serializing_none]
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
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
    /// Indication of what type of key storage the wallet should use.
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    /// Part of the `credentialSchema` property.
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

/// The state represenation of the credential in the system.
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
    /// Specify the organization from which to return credentials.
    pub organisation_id: OrganisationId,
    /// Return only credentials with a name starting with this string.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Filter credentials by whether they were issued by the system,
    /// verified by the system or are held by the system as with a wallet.
    #[param(nullable = false)]
    pub role: Option<CredentialRoleRestEnum>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
    /// Specify credentials to be returned by their UUID.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<CredentialId>>,
    /// Return only credentials with the specified credential state.
    #[param(rename = "status[]", inline, nullable = false)]
    pub status: Option<Vec<CredentialStateRestEnum>>,
    /// Search for a string.
    #[param(nullable = false)]
    pub search_text: Option<String>,
    /// Changes where `searchText` is searched. To search credentials,
    /// choose one or more `searchType`s and pass a `searchText`.
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

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(CreateCredentialRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialRequestRestDTO {
    /// Choose a credential schema to use.
    pub credential_schema_id: CredentialSchemaId,
    /// Choose an identifier to use to issue the credential.
    pub issuer: Option<IdentifierId>,
    #[schema(deprecated = true)]
    /// Choose a DID to use as an identifier.
    pub issuer_did: Option<DidId>,
    /// If multiple keys are specified for the assertion method of the DID,
    /// use this value to specify which key should be used as the assertion
    /// method for this credential. If a key isn't specified here, the first
    /// key listed during DID creation will be used.
    #[into(with_fn = convert_inner)]
    pub issuer_key: Option<KeyId>,
    /// Exchange protocol to use for issuing the credential to a wallet. Check
    /// the `exchange` object of the configuration for supported options and
    /// reference the configuration instance.
    #[schema(example = "OPENID4VCI_DRAFT13")]
    pub exchange: String,
    /// Attribute from the credential schema, together with the
    /// corresponding claim being made.
    #[into(with_fn = convert_inner)]
    pub claim_values: Vec<CredentialRequestClaimRestDTO>,
    /// When a credential is accepted, the holder will be redirected to the
    /// resource specified here, if redirects are enabled in the system
    /// configuration. The URI must use a scheme (for example `https`, `myapp`)
    /// that is allowed by the system configuration.
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
    #[serde(default)]
    pub value: String,
    /// Path to the particular claim key within the structure of the credential schema.
    pub path: String,
}

/// Array of credentials to be checked for revocation status.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRevocationCheckRequestRestDTO {
    pub credential_ids: Vec<CredentialId>,
    pub force_refresh: Option<bool>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into(SuspendCredentialRequestDTO)]
pub struct SuspendCredentialRequestRestDTO {
    /// Specify the time when the credential will reactivate, or pass `{}` for an indefinite suspension.
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialRevocationCheckResponseDTO)]
pub struct CredentialRevocationCheckResponseRestDTO {
    pub credential_id: Uuid,
    pub status: CredentialStateRestEnum,
    /// Indicates whether the system performed the check as planned.
    /// When using `forceRefresh`, indicates whether the external resource
    /// was reached and gave a response. For mdocs this value will only be
    /// `true` if a new MSO was issued.
    pub success: bool,
    /// Explanation of why the revocation check failed. Only present
    /// when `success: false`.
    pub reason: Option<String>,
}
