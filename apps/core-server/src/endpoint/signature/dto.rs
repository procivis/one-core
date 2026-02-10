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
    /// Identifier ID of the signing entity. Must be a CA identifier for
    /// X.509 and Access Certificates, or a Certificate identifier for
    /// Registration Certificates. Ensure the identifier is registered
    /// on the appropriate trust lists.
    pub issuer: IdentifierId,
    /// Specific key to use from the issuer identifier. Omit for
    /// automatic selection.
    pub issuer_key: Option<KeyId>,
    /// Specific certificate to use from the issuer identifier. Omit
    /// for automatic selection.
    pub issuer_certificate: Option<CertificateId>,
    /// Type of signature to create. This must reference a configured
    /// `signer` object.
    #[modify_schema(field = signer)]
    pub signer: String,
    /// Signer-specific request data. Structure varies based on signer
    /// value. See the Signatures guide for complete specifications.
    pub data: serde_json::Value,
    /// Pass nothing to start validity now or choose a datetime
    /// in the future.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_start: Option<OffsetDateTime>,
    /// Pass nothing to set the maximum validity period allowed
    /// by the configuration or choose a datetime with a shorter
    /// validity period.
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
