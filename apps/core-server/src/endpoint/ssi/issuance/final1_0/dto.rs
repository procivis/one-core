use indexmap::IndexMap;
use one_core::mapper::{opt_secret_string, secret_string};
use one_core::provider::credential_formatter::vcdm::ContextType;
use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::model::OpenID4VCIProofTypeSupported;
use one_core::provider::issuance_protocol::openid4vci_final1_0::model::{
    ExtendedSubjectDTO, OpenID4VCIAuthorizationCodeGrant, OpenID4VCICredentialConfigurationData,
    OpenID4VCICredentialDefinition, OpenID4VCICredentialDefinitionRequestDTO,
    OpenID4VCICredentialMetadataClaimResponseDTO, OpenID4VCICredentialMetadataResponseDTO,
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialRequestIdentifier,
    OpenID4VCICredentialRequestProofs, OpenID4VCICredentialSubjectItem,
    OpenID4VCICredentialValueDetails, OpenID4VCIFinal1CredentialOfferDTO, OpenID4VCIGrants,
    OpenID4VCIIssuerMetadataClaimDisplay, OpenID4VCIIssuerMetadataCredentialMetadataImage,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataDisplayResponseDTO, OpenID4VCIIssuerMetadataLogoDTO,
    OpenID4VCINonceResponseDTO, OpenID4VCINotificationEvent, OpenID4VCINotificationRequestDTO,
    OpenID4VCIPreAuthorizedCodeGrant, OpenID4VCITokenResponseDTO,
};
use one_core::service::oid4vci_final1_0::dto::{
    OAuthAuthorizationServerMetadataResponseDTO, OpenID4VCICredentialResponseDTO,
    OpenID4VCICredentialResponseEntryDTO,
};
use one_dto_mapper::{From, Into, convert_inner, convert_inner_of_inner};
use proc_macros::options_not_nullable;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use utoipa::ToSchema;

use crate::endpoint::credential_schema::dto::{
    CredentialSchemaCodeTypeRestEnum, WalletStorageTypeRestEnum,
};

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
    pub display: Option<Vec<OpenID4VCIIssuerMetadataDisplayResponseRestDTO>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataDisplayResponseDTO)]
pub(crate) struct OpenID4VCIIssuerMetadataDisplayResponseRestDTO {
    pub name: String,
    pub locale: Option<String>,
    #[from(with_fn = convert_inner)]
    pub logo: Option<OpenID4VCIIssuerMetadataLogoRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialConfigurationData)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO {
    pub format: String,
    pub doctype: Option<String>,
    pub procivis_schema: Option<String>,
    pub vct: Option<String>,
    #[from(with_fn = convert_inner)]
    pub credential_metadata: Option<OpenID4VCICredentialMetadataResponseRestDTO>,
    pub scope: Option<String>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_alg_values_supported: Option<Vec<String>>,
    #[schema(value_type = Object)]
    pub proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    #[from(with_fn = convert_inner)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialMetadataResponseDTO)]
pub(crate) struct OpenID4VCICredentialMetadataResponseRestDTO {
    #[from(with_fn = convert_inner_of_inner)]
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO>>,
    #[from(with_fn = convert_inner_of_inner)]
    pub claims: Option<Vec<OpenID4VCICredentialMetadataClaimResponseRestDTO>>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialDefinition)]
pub(crate) struct OpenID4VCICredentialDefinitionRestDTO {
    pub r#type: Vec<String>,
    #[serde(rename = "@context")]
    #[schema(value_type = Vec<String>)]
    pub context: Option<Vec<ContextType>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialMetadataClaimResponseDTO)]
pub(crate) struct OpenID4VCICredentialMetadataClaimResponseRestDTO {
    pub path: Vec<String>,
    #[from(with_fn = convert_inner_of_inner)]
    pub display: Option<Vec<OpenID4VCIIssuerMetadataClaimDisplayRestDTO>>,
    pub mandatory: Option<bool>,
    pub additional_values: Option<IndexMap<String, serde_json::Value>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataClaimDisplay)]
pub(crate) struct OpenID4VCIIssuerMetadataClaimDisplayRestDTO {
    pub name: Option<String>,
    pub locale: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO {
    pub name: String,
    pub locale: Option<String>,
    #[from(with_fn = convert_inner)]
    pub logo: Option<OpenID4VCIIssuerMetadataLogoRestDTO>,
    pub description: Option<String>,
    pub background_color: Option<String>,
    #[from(with_fn = convert_inner)]
    pub background_image: Option<OpenID4VCIIssuerMetadataCredentialMetadataImageRestDTO>,
    pub text_color: Option<String>,
    #[from(with_fn = convert_inner)]
    pub procivis_design: Option<OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesignRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataLogoDTO)]
pub(crate) struct OpenID4VCIIssuerMetadataLogoRestDTO {
    pub uri: String,
    pub alt_text: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialMetadataImage)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialMetadataImageRestDTO {
    pub uri: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesignRestDTO {
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    pub code_attribute: Option<String>,
    pub code_type: Option<CredentialSchemaCodeTypeRestEnum>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OAuthAuthorizationServerMetadataResponseDTO)]
pub(crate) struct OAuthAuthorizationServerMetadataRestDTO {
    pub issuer: String,
    #[from(with_fn = convert_inner)]
    pub authorization_endpoint: Option<String>,
    #[from(with_fn = convert_inner)]
    pub token_endpoint: Option<String>,
    #[from(with_fn = convert_inner)]
    pub jwks_uri: Option<String>,
    #[from(with_fn = convert_inner)]
    pub pushed_authorization_request_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub response_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grant_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[from(with_fn = convert_inner)]
    pub challenge_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_pop_signing_alg_values_supported: Option<Vec<String>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
pub(crate) struct OpenID4VCITokenRequestRestDTO {
    #[schema(example = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    pub refresh_token: Option<String>,
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
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VCICredentialRequestDTO)]
pub(crate) struct OpenID4VCIFinal1CredentialRequestRestDTO {
    #[serde(flatten)]
    pub credential: OpenID4VCICredentialRequestIdentifierRest,
    #[into(with_fn = convert_inner)]
    pub proofs: Option<OpenID4VCICredentialRequestProofsRest>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VCICredentialRequestIdentifier)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OpenID4VCICredentialRequestIdentifierRest {
    CredentialConfigurationId(String),
    CredentialIdentifier(String),
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VCICredentialRequestProofs)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OpenID4VCICredentialRequestProofsRest {
    Jwt(Vec<String>),
    DiVp(Vec<String>),
    Attestation([String; 1]),
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VCINotificationEvent)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub(crate) enum OpenID4VCINotificationEventRest {
    CredentialAccepted,
    CredentialFailure,
    CredentialDeleted,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VCINotificationRequestDTO)]
pub(crate) struct OpenID4VCINotificationRequestRestDTO {
    pub notification_id: String,
    pub event: OpenID4VCINotificationEventRest,
    pub event_description: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(transparent)]
pub(crate) struct TimestampRest(pub i64);

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCITokenResponseDTO)]
pub(crate) struct OpenID4VCITokenResponseRestDTO {
    #[serde(with = "secret_string")]
    #[schema(value_type = String, example = "secret")]
    pub access_token: SecretString,
    pub token_type: String,
    pub expires_in: TimestampRest,
    #[from(with_fn = convert_inner)]
    #[serde(with = "opt_secret_string")]
    #[schema(value_type = String, example = "secret", nullable = false)]
    pub refresh_token: Option<SecretString>,
    #[from(with_fn = convert_inner)]
    pub refresh_token_expires_in: Option<TimestampRest>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIErrorResponseRestDTO {
    pub error: OpenID4VCIErrorRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema, From)]
#[serde(rename_all = "snake_case")]
#[from(OpenID4VCIError)]
pub(crate) enum OpenID4VCIErrorRestEnum {
    UnsupportedGrantType,
    InvalidGrant,
    InvalidRequest,
    InvalidToken,
    InvalidNonce,
    InvalidOrMissingProof,
    UnsupportedCredentialFormat,
    UnsupportedCredentialType,
    CredentialRequestDenied,
    InvalidNotificationId,
    InvalidNotificationRequest,
    RuntimeError(String),
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialResponseDTO)]
pub(crate) struct OpenID4VCIFinal1CredentialResponseRestDTO {
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,

    #[from(with_fn = convert_inner_of_inner)]
    pub credentials: Option<Vec<OpenID4VCICredentialResponseEntryRestDTO>>,
    pub transaction_id: Option<String>,
    pub interval: Option<u64>,
    pub notification_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialResponseEntryDTO)]
pub(crate) struct OpenID4VCICredentialResponseEntryRestDTO {
    pub credential: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIFinal1CredentialOfferDTO)]
pub(crate) struct OpenID4VCIFinal1CredentialOfferRestDTO {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: OpenID4VCIGrantsRestDTO,

    #[from(with_fn = convert_inner)]
    pub credential_subject: Option<ExtendedSubjectRestDTO>,
    #[from(with_fn = convert_inner)]
    pub issuer_did: Option<DidValue>,
    pub issuer_certificate: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Serialize, Debug, From, ToSchema)]
#[from(ExtendedSubjectDTO)]
pub(crate) struct ExtendedSubjectRestDTO {
    #[from(with_fn = convert_inner)]
    pub keys: Option<ExtendedSubjectClaimsRestDTO>,
}

#[derive(Clone, Serialize, Debug, ToSchema)]
pub(crate) struct ExtendedSubjectClaimsRestDTO {
    #[serde(flatten)]
    pub claims: IndexMap<String, ProcivisSubjectClaimValueRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Serialize, Debug, From, ToSchema)]
#[from(OpenID4VCICredentialValueDetails)]
pub(crate) struct ProcivisSubjectClaimValueRestDTO {
    pub value: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIGrants)]
pub(crate) enum OpenID4VCIGrantsRestDTO {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode(OpenID4VCIPreAuthorizedGrantRestDTO),
    #[serde(rename = "authorization_code")]
    AuthorizationCode(OpenID4VCIAuthorizationCodeGrantRestDTO),
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIPreAuthorizedCodeGrant)]
pub(crate) struct OpenID4VCIPreAuthorizedGrantRestDTO {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    pub authorization_server: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIAuthorizationCodeGrant)]
pub(crate) struct OpenID4VCIAuthorizationCodeGrantRestDTO {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCINonceResponseDTO)]
pub(crate) struct OpenID4VCINonceResponseRestDTO {
    pub c_nonce: String,
}
