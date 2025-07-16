use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{
    CertificateId, ClaimSchemaId, CredentialId, CredentialSchemaId, DidId, IdentifierId, KeyId,
    OrganisationId,
};
use strum::{AsRefStr, Display, EnumString};
use time::OffsetDateTime;

use crate::model;
use crate::model::common::GetListResponse;
use crate::model::credential::SortableCredentialColumn;
use crate::model::credential_schema::{
    CredentialFormat, LayoutType, RevocationMethod, WalletStorageTypeEnum,
};
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::service::certificate::dto::CertificateResponseDTO;
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialSchemaLayoutPropertiesResponseDTO,
    CredentialSchemaListItemResponseDTO,
};
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;

#[derive(Clone, Debug)]
pub struct CredentialListItemResponseDTO {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateEnum,
    pub last_modified: OffsetDateTime,
    pub schema: CredentialSchemaListItemResponseDTO,
    pub issuer: Option<GetIdentifierListItemResponseDTO>,
    pub credential: Vec<u8>,
    pub role: CredentialRole,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub protocol: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDetailResponseDTO {
    pub id: CredentialId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub issuance_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateEnum,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub schema: DetailCredentialSchemaResponseDTO,
    pub issuer: Option<GetIdentifierListItemResponseDTO>,
    #[serde(skip)]
    pub issuer_certificate: Option<CertificateResponseDTO>,
    pub claims: Vec<DetailCredentialClaimResponseDTO>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,
    #[serde(with = "time::serde::rfc3339::option")]
    pub lvvc_issuance_date: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub suspend_end_date: Option<OffsetDateTime>,
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseDTO>,
    pub holder: Option<GetIdentifierListItemResponseDTO>,
    pub protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MdocMsoValidityResponseDTO {
    #[serde(with = "time::serde::rfc3339")]
    pub expiration: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub next_update: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_update: OffsetDateTime,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialSchemaResponseDTO {
    pub id: CredentialSchemaId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    #[serde(skip)]
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    pub organisation_id: OrganisationId,
    #[serde(default)]
    pub external_schema: bool,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub schema_type: CredentialSchemaType,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO>,
    pub allow_suspension: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, From, Into, Display)]
#[from(model::credential_schema::CredentialSchemaType)]
#[into(model::credential_schema::CredentialSchemaType)]
pub enum CredentialSchemaType {
    #[strum(serialize = "ProcivisOneSchema2024")]
    ProcivisOneSchema2024,
    #[strum(serialize = "FallbackSchema2024")]
    FallbackSchema2024,
    #[strum(serialize = "mdoc")]
    Mdoc,
    #[strum(serialize = "SdJwtVc")]
    SdJwtVc,
    #[strum(serialize = "{0}")]
    #[serde(untagged)]
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialClaimResponseDTO {
    pub path: String,
    pub schema: CredentialClaimSchemaDTO,
    pub value: DetailCredentialClaimValueResponseDTO,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DetailCredentialClaimValueResponseDTO {
    Boolean(bool),
    Float(f64),
    Integer(i64),
    String(String),
    Nested(Vec<DetailCredentialClaimResponseDTO>),
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, From, AsRefStr)]
#[from("crate::model::credential::CredentialRole")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, From)]
#[from("crate::model::credential::CredentialStateEnum")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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

#[derive(Clone, Debug, Eq, PartialEq, EnumString, Display)]
#[strum(serialize_all = "camelCase")]
pub enum CredentialListIncludeEntityTypeEnum {
    LayoutProperties,
    Credential,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialFilterValue {
    ClaimName(StringMatch),
    ClaimValue(StringMatch),
    CredentialSchemaName(StringMatch),
    OrganisationId(OrganisationId),
    Role(CredentialRole),
    CredentialIds(Vec<CredentialId>),
    State(Vec<crate::model::credential::CredentialStateEnum>),
    SuspendEndDate(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for CredentialFilterValue {}

pub type GetCredentialListResponseDTO = GetListResponse<CredentialListItemResponseDTO>;
pub type GetCredentialQueryDTO =
    ListQuery<SortableCredentialColumn, CredentialFilterValue, CredentialListIncludeEntityTypeEnum>;

#[derive(Clone, Debug)]
pub struct CreateCredentialRequestDTO {
    pub credential_schema_id: CredentialSchemaId,
    pub issuer: Option<IdentifierId>,
    pub issuer_did: Option<DidId>,
    pub issuer_key: Option<KeyId>,
    pub issuer_certificate: Option<CertificateId>,
    pub protocol: String,
    pub claim_values: Vec<CredentialRequestClaimDTO>,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SuspendCredentialRequestDTO {
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct CredentialRequestClaimDTO {
    pub claim_schema_id: ClaimSchemaId,
    pub value: String,
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct CredentialRevocationCheckResponseDTO {
    pub credential_id: CredentialId,
    pub status: CredentialStateEnum,
    pub success: bool,
    pub reason: Option<String>,
}
