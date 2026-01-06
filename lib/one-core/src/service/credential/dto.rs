use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{
    CertificateId, ClaimSchemaId, CredentialFormat, CredentialId, CredentialSchemaId, DidId,
    IdentifierId, KeyId, OrganisationId,
};
use strum::AsRefStr;
use time::OffsetDateTime;

use crate::model::blob::Blob;
use crate::model::common::GetListResponse;
use crate::model::credential::{
    CredentialFilterValue, CredentialListIncludeEntityTypeEnum, SortableCredentialColumn,
};
use crate::model::credential_schema::{KeyStorageSecurity, LayoutType, RevocationMethod};
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
    pub issuance_date: Option<OffsetDateTime>,
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateEnum,
    pub last_modified: OffsetDateTime,
    pub schema: CredentialSchemaListItemResponseDTO,
    pub issuer: Option<GetIdentifierListItemResponseDTO>,
    pub role: CredentialRole,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub protocol: String,
    pub profile: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDetailResponseDTO<T> {
    pub id: CredentialId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub issuance_date: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateEnum,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub schema: DetailCredentialSchemaResponseDTO,
    pub issuer: Option<GetIdentifierListItemResponseDTO>,
    #[serde(skip)]
    pub issuer_certificate: Option<CertificateResponseDTO>,
    pub claims: Vec<T>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,
    #[serde(with = "time::serde::rfc3339::option")]
    pub lvvc_issuance_date: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub suspend_end_date: Option<OffsetDateTime>,
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseDTO>,
    pub holder: Option<GetIdentifierListItemResponseDTO>,
    pub protocol: String,
    pub profile: Option<String>,
    pub wallet_app_attestation: Option<WalletAppAttestationDTO>,
    pub wallet_unit_attestation: Option<WalletUnitAttestationDTO>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletAppAttestationDTO {
    pub name: String,
    pub link: String,
    pub attestation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletUnitAttestationDTO {
    pub attestation: String,
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
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO>,
    pub allow_suspension: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialClaimResponseDTO {
    pub path: String,
    pub schema: CredentialClaimSchemaDTO,
    pub value: DetailCredentialClaimValueResponseDTO<Self>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DetailCredentialClaimValueResponseDTO<T> {
    Boolean(bool),
    Float(f64),
    Integer(i64),
    String(String),
    Nested(Vec<T>),
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, From, Into, AsRefStr)]
#[from("crate::model::credential::CredentialRole")]
#[into("crate::model::credential::CredentialRole")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, Into, From)]
#[from("crate::model::credential::CredentialStateEnum")]
#[into("crate::model::credential::CredentialStateEnum")]
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
    InteractionExpired,
}

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
    pub profile: Option<String>,
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

#[derive(Clone, Debug, Default)]
pub struct CredentialAttestationBlobs {
    pub wallet_app_attestation_blob: Option<Blob>,
    pub wallet_unit_attestation_blob: Option<Blob>,
}
