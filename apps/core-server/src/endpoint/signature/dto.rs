use one_core::provider::signer::dto::{CreateSignatureRequestDTO, CreateSignatureResponseDTO};
use one_dto_mapper::{From, Into};
use proc_macros::ModifySchema;
use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId, KeyId};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[into(CreateSignatureRequestDTO)]
#[serde(rename_all = "camelCase")]
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
