use indexmap::IndexMap;
use one_core::common_mapper::{opt_secret_string, secret_string};
use one_core::provider::issuance_protocol::openid4vci_draft13::error::OpenID4VCIError;
use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    ExtendedSubjectDTO, OpenID4VCICredentialConfigurationData,
    OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialOfferDTO,
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialSubjectItem,
    OpenID4VCICredentialValueDetails, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIGrant,
    OpenID4VCIGrants, OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataDisplayResponseDTO, OpenID4VCIProofRequestDTO,
    OpenID4VCIProofTypeSupported, OpenID4VCITokenResponseDTO,
};
use one_core::service::oid4vci_draft13::dto::OpenID4VCICredentialResponseDTO;
use one_dto_mapper::{convert_inner, convert_inner_of_inner, From, Into};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::DidValue;
use utoipa::{IntoParams, ToSchema};

use crate::endpoint::credential_schema::dto::{CredentialSchemaType, WalletStorageTypeRestEnum};

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIIssuerMetadataResponseRestDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub credential_configurations_supported:
        IndexMap<String, OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO>,
    pub display: Option<Vec<OpenID4VCIIssuerMetadataDisplayResponseRestDTO>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataDisplayResponseDTO)]
pub(crate) struct OpenID4VCIIssuerMetadataDisplayResponseRestDTO {
    pub name: String,
    pub locale: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO)]
pub(crate) struct OpenID4VCIIssuerMetadataCredentialSchemaRestDTO {
    pub id: String,
    pub r#type: CredentialSchemaType,
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

#[derive(Clone, Debug, Deserialize, IntoParams)]
pub(crate) struct OpenID4VCITokenRequestRestDTO {
    #[param(example = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    #[param(nullable = false)]
    pub pre_authorized_code: Option<String>,
    #[param(nullable = false)]
    pub refresh_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, From)]
#[into(OpenID4VCICredentialDefinitionRequestDTO)]
#[from(OpenID4VCICredentialDefinitionRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCICredentialDefinitionRequestRestDTO {
    #[serde(rename = "types")]
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

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(OpenID4VCICredentialRequestDTO)]
pub(crate) struct OpenID4VCICredentialRequestRestDTO {
    pub format: String,
    #[into(with_fn = convert_inner)]
    pub credential_definition: Option<OpenID4VCICredentialDefinitionRequestRestDTO>,
    #[into(with_fn = convert_inner)]
    pub doctype: Option<String>,
    pub vct: Option<String>,
    pub proof: OpenID4VCIProofRequestRestDTO,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(OpenID4VCIProofRequestDTO)]
pub(crate) struct OpenID4VCIProofRequestRestDTO {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(transparent)]
pub(crate) struct TimestampRest(pub i64);

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
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

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub(crate) struct OpenID4VCIErrorResponseRestDTO {
    pub error: OpenID4VCIErrorRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "snake_case")]
#[from(OpenID4VCIError)]
pub(crate) enum OpenID4VCIErrorRestEnum {
    UnsupportedGrantType,
    InvalidGrant,
    InvalidRequest,
    InvalidToken,
    InvalidOrMissingProof,
    UnsupportedCredentialFormat,
    UnsupportedCredentialType,
    CredentialRequestDenied,
    RuntimeError(String),
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(OpenID4VCICredentialResponseDTO)]
pub(crate) struct OpenID4VCICredentialResponseRestDTO {
    pub credential: String,
    pub redirect_uri: Option<String>,
}

#[skip_serializing_none]
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

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug, From, ToSchema)]
#[from(ExtendedSubjectDTO)]
pub(crate) struct ExtendedSubjectRestDTO {
    #[from(with_fn = convert_inner)]
    pub keys: Option<ExtendedSubjectClaimsRestDTO>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
}

#[derive(Clone, Serialize, Deserialize, Debug, ToSchema)]
pub(crate) struct ExtendedSubjectClaimsRestDTO {
    #[serde(flatten)]
    pub claims: IndexMap<String, ProcivisSubjectClaimValueRestDTO>,
}

#[derive(Clone, Serialize, Deserialize, Debug, From, ToSchema)]
#[from(OpenID4VCICredentialValueDetails)]
pub(crate) struct ProcivisSubjectClaimValueRestDTO {
    pub value: String,
    pub value_type: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIGrants)]
pub(crate) struct OpenID4VCIGrantsRestDTO {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub code: OpenID4VCIGrantRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(OpenID4VCIGrant)]
pub(crate) struct OpenID4VCIGrantRestDTO {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}
