use std::collections::HashMap;

use one_core::provider::signer::dto::CreateSignatureResponseDTO;
use one_core::service::signature::dto::{
    CreateSignatureRequestDTO, SignatureState, SignatureStatusInfo,
};
use one_dto_mapper::{From, Into};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId, KeyId};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[into(CreateSignatureRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateSignatureRequestRestDTO {
    /// Issuer ID.
    pub issuer: IdentifierId,
    /// Preferred key ID; leave empty for automatic selection.
    pub issuer_key: Option<KeyId>,
    /// Preferred certificate ID; leave empty for automatic selection.
    pub issuer_certificate: Option<CertificateId>,
    /// Signature provider to use for creating the signature.
    #[modify_schema(field = signer)]
    pub signer: String,
    /// Signer-specific request data.
    pub data: serde_json::Value,

    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_start: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_end: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CreateSignatureResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateSignatureResponseRestDTO {
    /// ID used to revoke the signature.
    pub id: Uuid,
    /// Signer-specific signature representation.
    pub result: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignatureRevocationCheckRequestRestDTO {
    pub signature_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignatureRevocationCheckResponseRestDTO {
    #[serde(flatten)]
    pub result: HashMap<Uuid, SignatureStatusInfoRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SignatureStatusInfo)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignatureStatusInfoRestDTO {
    pub state: SignatureStateRestEnum,
    pub r#type: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SignatureState)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SignatureStateRestEnum {
    Active,
    Revoked,
}
