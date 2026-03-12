use indexmap::IndexMap;
use one_core::provider::issuance_protocol::model::OpenID4VCIProofTypeSupported;
use proc_macros::options_not_nullable;
use serde::Serialize;
use utoipa::ToSchema;

use crate::endpoint::ssi::issuance::final1_0::dto::{
    CredentialSigningAlgValueRestEnum, OpenID4VCICredentialDefinitionRestDTO,
    OpenID4VCICredentialMetadataClaimResponseRestDTO, OpenID4VCICredentialMetadataResponseRestDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO,
    OpenID4VCIIssuerMetadataDisplayResponseRestDTO,
};

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCISwiyuIssuerMetadataResponseRestDTO {
    pub credential_issuer: String,
    pub authorization_servers: Option<Vec<String>>,
    pub credential_endpoint: String,
    pub nonce_endpoint: Option<String>,
    pub notification_endpoint: Option<String>,
    pub credential_configurations_supported:
        IndexMap<String, OpenID4VCISwiyuIssuerMetadataCredentialSupportedResponseRestDTO>,
    pub display: Option<Vec<OpenID4VCIIssuerMetadataDisplayResponseRestDTO>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCISwiyuIssuerMetadataCredentialSupportedResponseRestDTO {
    pub format: String,
    pub doctype: Option<String>,
    pub vct: Option<String>,
    pub credential_metadata: Option<OpenID4VCICredentialMetadataResponseRestDTO>,
    pub display: Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO>,
    pub claims: IndexMap<String, OpenID4VCICredentialMetadataClaimResponseRestDTO>,
    pub scope: Option<String>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_alg_values_supported: Option<Vec<CredentialSigningAlgValueRestEnum>>,
    #[schema(value_type = Object)]
    pub proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRestDTO>,
}
