use std::collections::HashMap;

use one_core::provider::signer::dto::CreateSignatureResponseDTO;
use one_core::service::signature::dto::{
    CreateSignatureRequestDTO, SignatureState, SignatureStatusInfo,
};
use one_dto_mapper::{From, Into};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId, KeyId, SignerId};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[into(CreateSignatureRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateSignatureRequestRestDTO {
    /// Identifier that signs. Must be a certificate authority identifier
    /// for X.509 and Access Certificates, or a certificate identifier for
    /// Registration Certificates.
    pub issuer: IdentifierId,
    /// Specific key to use from the issuer identifier. Omit for
    /// automatic selection.
    pub issuer_key: Option<KeyId>,
    /// Specific certificate to use from the issuer identifier. Omit
    /// for automatic selection.
    pub issuer_certificate: Option<CertificateId>,
    /// Name of a configured `signer` instance. Determines the structure
    /// of `data`.
    #[modify_schema(field = signer)]
    pub signer: String,
    /// Signer-specific request data. See
    /// [Signatures](https://docs.procivis.ch/signatures) for the structure
    /// each signer expects.
    #[schema(value_type = Object)]
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
    /// Signature ID. Use it to revoke the signature or check its status.
    pub id: Uuid,
    /// The signed output: a PEM certificate chain for X.509 and Access
    /// Certificates, or a signed JWT for Registration Certificates.
    pub result: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignatureRevocationCheckRequestRestDTO {
    /// IDs of the signatures to check.
    pub signature_ids: Vec<Uuid>,
}

/// Map of signature IDs to their status.
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
    /// Current state of the signature.
    pub state: SignatureStateRestEnum,
    /// Name of the signer that created the signature.
    pub r#type: SignerId,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(SignatureState)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SignatureStateRestEnum {
    Active,
    Revoked,
}
