use std::collections::HashMap;

use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{
    CertificateId, ClaimSchemaId, CredentialFormat, CredentialId, CredentialSchemaId, DidId,
    EcosystemId, IdentifierId, InteractionId, KeyId, OrganisationId,
};
use strum::AsRefStr;
use time::OffsetDateTime;

use crate::model::blob::Blob;
use crate::model::common::GetListResponse;
use crate::model::credential::ExactCredentialFilterColumn;
use crate::model::credential_schema::{TransactionCode, TransactionCodeType};
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::history::TrustResolutionResult;
use crate::proto::credential_validity_manager::dto::ChangeCredentialState;
use crate::service::certificate::dto::CertificateResponseDTO;
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialSchemaListItemV2ResponseDTO,
};
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;

#[derive(Clone, Debug)]
pub struct CredentialListItemResponseDTO {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: Option<OffsetDateTime>,
    pub revocation_date: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub consumed_at: Option<OffsetDateTime>,
    pub state: CredentialStateEnum,
    pub r#type: CredentialTypeEnum,
    pub last_modified: OffsetDateTime,
    pub schema: CredentialSchemaListItemV2ResponseDTO,
    pub issuer: Option<GetIdentifierListItemResponseDTO>,
    pub role: CredentialRole,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub protocol: String,
    pub profile: Option<String>,
    pub webhook_destination_url: Option<String>,
    pub parent_id: Option<CredentialId>,
    pub redirect_uri: Option<String>,
    pub ecosystem: Option<EcosystemId>,
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
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub consumed_at: Option<OffsetDateTime>,
    pub state: CredentialStateEnum,
    pub r#type: CredentialTypeEnum,
    pub remaining_batch_item_count: Option<HashMap<CredentialFormat, u32>>,
    pub format: Option<CredentialFormat>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub schema: DetailCredentialSchemaResponseDTO,
    pub issuer: Option<GetIdentifierListItemResponseDTO>,
    #[serde(skip)]
    pub issuer_certificate: Option<CertificateResponseDTO>,
    pub claims: Vec<T>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,
    pub interaction_id: Option<InteractionId>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub suspend_end_date: Option<OffsetDateTime>,
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseDTO>,
    pub holder: Option<GetIdentifierListItemResponseDTO>,
    pub protocol: String,
    pub profile: Option<String>,
    pub wallet_instance_attestation: Option<WalletInstanceAttestationDTO>,
    pub wallet_unit_attestation: Option<WalletUnitAttestationDTO>,
    pub webhook_destination_url: Option<String>,
    pub trust_information: Option<TrustInformation>,
    pub parent_id: Option<CredentialId>,
    pub subscriber_information: Option<String>,
    pub ecosystem: Option<EcosystemId>,
    #[serde(skip)]
    pub offered_formats: Option<Vec<OfferedFormatDTO>>,
}

#[derive(Clone, Debug)]
pub struct OfferedFormatDTO {
    pub format: CredentialFormat,
    pub state: OfferedFormatStateEnum,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum OfferedFormatStateEnum {
    Pending,
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustInformation {
    pub received_at: OffsetDateTime,
    pub name: Option<String>,
    pub result: TrustResolutionResult,
    pub ecosystem_errors: EcosystemOutcomes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletInstanceAttestationDTO {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialSchemaResponseDTO {
    pub organisation_id: OrganisationId,
    #[serde(flatten)]
    pub schema: CredentialSchemaListItemV2ResponseDTO,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, From, Into)]
#[from(TransactionCode)]
#[into(TransactionCode)]
#[serde(rename_all = "camelCase")]
pub struct DetailCredentialSchemaTransactionCodeDTO {
    pub r#type: TransactionCodeType,
    pub length: u32,
    pub description: Option<String>,
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
    Expired,
    Expiring,
}

#[derive(Clone, Copy, Debug, Into)]
#[into(ChangeCredentialState)]
pub enum ChangeCredentialStateDTO {
    Accepted,
    Revoked,
    Suspended {
        suspend_end_date: Option<OffsetDateTime>,
    },
    Expiring,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, Into, From)]
#[from("crate::model::credential::CredentialType")]
#[into("crate::model::credential::CredentialType")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialTypeEnum {
    Single,
    BatchParent,
    BatchItem,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialSearchTypeDTO {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
}

#[derive(Clone, Debug)]
pub struct CredentialFilterParamsDTO {
    pub organisation_id: OrganisationId,
    pub name: Option<String>,
    pub search_text: Option<String>,
    pub search_type: Option<Vec<CredentialSearchTypeDTO>>,
    pub exact: Option<Vec<ExactCredentialFilterColumn>>,
    pub roles: Option<Vec<CredentialRole>>,
    pub ids: Option<Vec<CredentialId>>,
    pub parent_id: Option<CredentialId>,
    pub credential_schema_ids: Option<Vec<CredentialSchemaId>>,
    pub ecosystems: Option<Vec<EcosystemId>>,
    pub issuers: Option<Vec<IdentifierId>>,
    pub states: Option<Vec<CredentialStateEnum>>,
    pub profiles: Option<Vec<String>>,
    pub types: Option<Vec<CredentialTypeEnum>>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub issuance_date_after: Option<OffsetDateTime>,
    pub issuance_date_before: Option<OffsetDateTime>,
    pub revocation_date_after: Option<OffsetDateTime>,
    pub revocation_date_before: Option<OffsetDateTime>,
    pub expires_at_after: Option<OffsetDateTime>,
    pub expires_at_before: Option<OffsetDateTime>,
}

pub type GetCredentialListResponseDTO = GetListResponse<CredentialListItemResponseDTO>;

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
    pub webhook_destination_url: Option<String>,
    pub subscriber_information: Option<String>,
    pub ecosystem: Option<EcosystemId>,
    pub formats: Option<Vec<CredentialFormat>>,
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

#[derive(Clone, Debug, From)]
#[from(crate::proto::credential_validity_manager::CredentialValidityCheckResult)]
pub struct CredentialRevocationCheckResponseDTO {
    pub credential_id: CredentialId,
    pub status: CredentialStateEnum,
    pub success: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CredentialAttestationBlobs {
    pub wallet_instance_attestation_blob: Option<Blob>,
    pub wallet_key_attestation_blob: Option<Blob>,
}

#[derive(Clone, Debug)]
pub struct ShareCredentialResponseDTO {
    pub url: String,
    pub transaction_code: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
}
