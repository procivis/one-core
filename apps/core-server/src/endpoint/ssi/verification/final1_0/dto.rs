use std::collections::HashMap;

use one_core::provider::verification_protocol::openid4vp::final1_0::model::OpenID4VPFinal1_0ClientMetadata;
use one_dto_mapper::{From, convert_inner};
use proc_macros::options_not_nullable;
use serde::Serialize;
use utoipa::ToSchema;

use super::super::dto::{OpenID4VPClientMetadataJwksRestDTO, OpenID4VPFormatRestDTO};
use crate::endpoint::ssi::dto::{
    OID4VPAuthorizationEncryptedResponseAlgorithm,
    OID4VPAuthorizationEncryptedResponseContentEncryptionAlgorithm,
};

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VPFinal1_0ClientMetadata)]
pub(crate) struct OpenID4VPFinal1_0ClientMetadataResponseRestDTO {
    #[from(with_fn = convert_inner)]
    pub jwks: Option<OpenID4VPClientMetadataJwksRestDTO>,
    pub jwks_uri: Option<String>,
    pub id_token_ecrypted_response_enc: Option<String>,
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subject_syntax_types_supported: Vec<String>,
    #[from(with_fn = convert_inner)]
    pub vp_formats_supported: HashMap<String, OpenID4VPFormatRestDTO>,
    #[from(with_fn = convert_inner)]
    pub authorization_encrypted_response_alg: Option<OID4VPAuthorizationEncryptedResponseAlgorithm>,
    #[from(with_fn = convert_inner)]
    pub authorization_encrypted_response_enc:
        Option<OID4VPAuthorizationEncryptedResponseContentEncryptionAlgorithm>,
}
