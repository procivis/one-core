//! OpenAPI-bearing mirrors of the OpenID4VCI issuance types.
//!
//! Everything in this module that is defined by the specification lives in `standardized-types`
//! and is used directly. What remains here are mirrors of types that carry Procivis extensions and
//! therefore live in `one-core`: `one-core` has no `utoipa` dependency, so those types cannot
//! derive `ToSchema` and cannot appear in the OpenAPI document.
//!
//! [`OpenID4VCITokenRequestRestDTO`] is the exception: it is not a mirror, see its own docs.

use indexmap::IndexMap;
use one_core::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialSubjectItem,
};
use one_dto_mapper::{From, Into, convert_inner_of_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use standardized_types::etsi_119_472::disclosure_policy::DisclosurePolicy;
use standardized_types::openid4vci::{
    BatchCredentialIssuance, ClaimMetadata, CredentialDefinition, CredentialDisplay,
    CredentialMetadata, CredentialRequestEncryption, CredentialResponseEncryption,
    CredentialResponseEntry, Image, IssuerDisplay, IssuerInfoAttestation, ProofTypeSupported,
    SigningAlgValue,
};
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIIssuerMetadataResponseRestDTO {
    pub credential_issuer: String,
    pub authorization_servers: Option<Vec<String>>,
    pub credential_endpoint: String,
    pub nonce_endpoint: Option<String>,
    pub notification_endpoint: Option<String>,
    pub credential_configurations_supported:
        IndexMap<String, OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO>,
    pub display: Option<Vec<IssuerDisplay>>,
    /// ETSI TS 119 472-3 V1.1.1, Section 4.2.3
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issuer_info: Vec<IssuerInfoAttestation>,
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,
    pub credential_request_encryption: Option<CredentialRequestEncryption>,
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    pub preferred_client_status_period: Option<u64>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO {
    pub format: String,
    pub doctype: Option<String>,
    pub vct: Option<String>,
    pub credential_metadata: Option<OpenID4VCICredentialMetadataResponseRestDTO>,
    pub scope: Option<String>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_alg_values_supported: Option<Vec<SigningAlgValue>>,
    #[schema(value_type = Object)]
    pub proof_types_supported: Option<IndexMap<String, ProofTypeSupported>>,
    pub credential_definition: Option<CredentialDefinition>,
    pub disclosure_policy: Option<DisclosurePolicy>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialMetadata)]
pub(crate) struct OpenID4VCICredentialMetadataResponseRestDTO {
    #[from(with_fn = convert_inner_of_inner)]
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO>>,
    pub claims: Option<Vec<ClaimMetadata>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialDisplay)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO {
    pub name: String,
    pub locale: Option<String>,
    pub logo: Option<Image>,
    pub description: Option<String>,
    pub background_color: Option<String>,
    pub background_image: Option<Image>,
    pub text_color: Option<String>,

    #[serde(flatten, skip_serializing_if = "IndexMap::is_empty")]
    pub additional_values: IndexMap<String, serde_json::Value>,
}

/// Loosely typed form of the Token Request, deliberately *not* replaced by
/// [`standardized_types::oauth2::token::TokenRequest`].
///
/// `TokenRequest` is a discriminated union, so an unsupported `grant_type` would fail
/// deserialization and be answered with a generic extractor rejection. Accepting `grant_type` as a
/// free string lets `TryFrom` answer with the OAuth error object the specification requires
/// (`unsupported_grant_type` / `invalid_request`), and lets it reject parameter combinations that
/// do not match the grant.
#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
// No serde(deny_unknown_fields): "Additional Token Request parameters MAY be defined and used"
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1-9
pub(crate) struct OpenID4VCITokenRequestRestDTO {
    #[schema(example = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    pub refresh_token: Option<String>,
    pub tx_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, From)]
#[into(OpenID4VCICredentialDefinitionRequestDTO)]
#[from(OpenID4VCICredentialDefinitionRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCICredentialDefinitionRequestRestDTO {
    pub r#type: Vec<String>,

    #[serde(rename = "credentialSubject")]
    #[schema(value_type = Object,
        example = "{
            claim1: {
                mandatory: true
            },
            claim2: {
                mandatory: true
            }
        }",
    )]
    pub credential_subject: Option<OpenID4VCICredentialSubjectItem>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIFinal1CredentialResponseRestDTO {
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,

    pub credentials: Option<Vec<CredentialResponseEntry>>,
    pub transaction_id: Option<String>,
    pub interval: Option<u64>,
    pub notification_id: Option<String>,
}
