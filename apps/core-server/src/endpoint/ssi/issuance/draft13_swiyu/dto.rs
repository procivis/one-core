use indexmap::IndexMap;
use one_core::mapper::{opt_secret_string, secret_string};
use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::model::OpenID4VCIProofTypeSupported;
use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    ExtendedSubjectDTO, OpenID4VCIAuthorizationCodeGrant, OpenID4VCICredentialConfigurationData,
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialRequestDTO, OpenID4VCICredentialSubjectItem,
    OpenID4VCICredentialValueDetails, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIGrants,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataDisplayResponseDTO, OpenID4VCIPreAuthorizedCodeGrant,
    OpenID4VCIProofRequestDTO, OpenID4VCITokenResponseDTO,
};
use one_core::service::error::ServiceError;
use one_core::service::oid4vci_draft13::dto::OAuthAuthorizationServerMetadataResponseDTO;
use one_core::service::oid4vci_draft13_swiyu::dto::OpenID4VCISwiyuCredentialResponseDTO;
use one_dto_mapper::{
    From, Into, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
};
use proc_macros::options_not_nullable;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use utoipa::{IntoParams, ToSchema};

use crate::endpoint::ssi::issuance::draft13::dto::WalletStorageTypeRestEnum;

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIIssuerMetadataResponseRestDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub credential_configurations_supported:
        IndexMap<String, OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO>,
    pub display: Option<Vec<OpenID4VCIIssuerMetadataDisplayResponseRestDTO>>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataDisplayResponseDTO)]
pub(crate) struct OpenID4VCIIssuerMetadataDisplayResponseRestDTO {
    pub name: String,
    pub locale: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialConfigurationData)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO {
    pub format: String,
    #[schema(value_type = Object,
        example = "{
            credential_schema_id: {
                claims: {
                    claim1: {
                        mandatory: true
                    }
                },
                display: [
                {
                    name: \"Schema name\"
                }
                ],
                doctype: \"eu.europa.ec.eudi.hiid.1\",
                format: \"mso_mdoc\",
            }
        }",
    )]
    pub claims: Option<OpenID4VCICredentialSubjectItem>,
    #[from(with_fn = convert_inner_of_inner)]
    pub order: Option<Vec<String>>,
    #[from(with_fn = convert_inner)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestRestDTO>,
    pub doctype: Option<String>,
    #[from(with_fn = convert_inner_of_inner)]
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO>>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    #[from(with_fn = convert_inner)]
    pub vct: Option<String>,
    #[from(with_fn = convert_inner)]
    pub scope: Option<String>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_alg_values_supported: Option<Vec<String>>,
    #[schema(value_type = Object)]
    pub proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIDiscoveryResponseDTO)]
pub(crate) struct OpenID4VCIDiscoveryResponseRestDTO {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: String,
    pub jwks_uri: Option<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
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

#[derive(Clone, Debug, Deserialize, IntoParams)]
// No serde(deny_unknown_fields): final version of the spec allows for defining
// additional parameters. The draft doesn't say anything about allowing
// or disallowing those; allow for consistency.
pub(crate) struct OpenID4VCITokenRequestRestDTO {
    #[param(example = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    #[param(nullable = false)]
    pub pre_authorized_code: Option<String>,
    #[param(nullable = false)]
    pub refresh_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OpenID4VCICredentialDefinitionRequestRestDTO {
    pub r#type: Option<Vec<String>>,
    pub types: Option<Vec<String>>,

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

#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[serde(deny_unknown_fields)]
#[try_into(T = OpenID4VCICredentialRequestDTO, Error = ServiceError)]
pub(crate) struct OpenID4VCICredentialRequestRestDTO {
    #[try_into(infallible)]
    pub format: String,
    #[try_into(with_fn = try_convert_inner)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestRestDTO>,
    #[try_into(infallible)]
    pub doctype: Option<String>,
    #[try_into(infallible)]
    pub vct: Option<String>,
    #[try_into(infallible)]
    pub proof: OpenID4VCIProofRequestRestDTO,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(deny_unknown_fields)]
#[into(OpenID4VCIProofRequestDTO)]
pub(crate) struct OpenID4VCIProofRequestRestDTO {
    pub proof_type: String,
    pub jwt: String,
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
    pub c_nonce: Option<String>,
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
#[serde(rename_all = "camelCase")]
#[from(OpenID4VCISwiyuCredentialResponseDTO)]
pub(crate) struct OpenID4VCISwiyuCredentialResponseRestDTO {
    pub credential: String,
    pub format: String,
    pub redirect_uri: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCICredentialOfferDTO)]
pub(crate) struct OpenID4VCICredentialOfferRestDTO {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: OpenID4VCIGrantsRestDTO,

    #[from(with_fn = convert_inner)]
    pub credential_subject: Option<ExtendedSubjectRestDTO>,
    #[from(with_fn = convert_inner)]
    pub issuer_did: Option<DidValue>,
}

#[options_not_nullable]
#[derive(Clone, Serialize, Debug, From, ToSchema)]
#[from(ExtendedSubjectDTO)]
pub(crate) struct ExtendedSubjectRestDTO {
    #[from(with_fn = convert_inner)]
    pub keys: Option<ExtendedSubjectClaimsRestDTO>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
}

#[derive(Clone, Serialize, Debug, ToSchema)]
pub(crate) struct ExtendedSubjectClaimsRestDTO {
    #[serde(flatten)]
    pub claims: IndexMap<String, ProcivisSubjectClaimValueRestDTO>,
}

#[derive(Clone, Serialize, Debug, From, ToSchema)]
#[from(OpenID4VCICredentialValueDetails)]
pub(crate) struct ProcivisSubjectClaimValueRestDTO {
    pub value: Option<String>,
    pub value_type: String,
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
pub struct OpenID4VCIAuthorizationCodeGrantRestDTO {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
}
