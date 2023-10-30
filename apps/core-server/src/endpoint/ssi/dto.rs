use crate::{
    endpoint::credential_schema::dto::CredentialSchemaListItemResponseRestDTO,
    serialize::front_time,
};
use dto_mapper::From;
use one_core::common_mapper::vector_into;
use one_core::service::{
    oidc::dto::{
        OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialRequestDTO,
        OpenID4VCICredentialResponseDTO, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIError,
        OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
        OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO,
        OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
    },
    ssi_issuer::dto::IssuerResponseDTO,
    ssi_verifier::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProofRequestQueryParams {
    pub proof: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequestRestDTO {
    pub did: String,
}

// verifier specific
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiVerifierConnectQueryParams {
    pub protocol: String,
    pub proof: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "ConnectVerifierResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct ConnectVerifierResponseRestDTO {
    #[convert(with_fn = "vector_into")]
    pub claims: Vec<ProofRequestClaimRestDTO>,
    pub verifier_did: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "OpenID4VCIIssuerMetadataResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCIIssuerMetadataResponseRestDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    #[convert(with_fn = "vector_into")]
    pub credentials_supported: Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO")]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO {
    pub format: String,
    pub credential_definition: OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO")]
pub struct OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "OpenID4VCIDiscoveryResponseDTO")]
pub struct OpenID4VCIDiscoveryResponseRestDTO {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(into = "OpenID4VCITokenRequestDTO")]
pub struct OpenID4VCITokenRequestRestDTO {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(into = "OpenID4VCICredentialDefinitionRequestDTO")]
pub struct OpenID4VCICredentialDefinitionRequestRestDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(into = "OpenID4VCICredentialRequestDTO")]
pub struct OpenID4VCICredentialRequestRestDTO {
    pub format: String,
    pub credential_definition: OpenID4VCICredentialDefinitionRequestRestDTO,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(transparent)]
pub struct DurationSecondsRest(pub i64);

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "OpenID4VCITokenResponseDTO")]
pub struct OpenID4VCITokenResponseRestDTO {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: DurationSecondsRest,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct OpenID4VCIErrorResponseRestDTO {
    pub error: OpenID4VCIErrorRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "snake_case")]
#[convert(from = "OpenID4VCIError")]
pub enum OpenID4VCIErrorRestEnum {
    UnsupportedGrantType,
    InvalidGrant,
    InvalidRequest,
    InvalidToken,
    UnsupportedCredentialFormat,
    UnsupportedCredentialType,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "ProofRequestClaimDTO")]
pub struct ProofRequestClaimRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: CredentialSchemaListItemResponseRestDTO,
}

// issuer specific
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerConnectQueryParams {
    pub protocol: String,
    pub credential: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "IssuerResponseDTO")]
pub struct ConnectIssuerResponseRestDTO {
    pub credential: String,
    pub format: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[convert(from = "OpenID4VCICredentialResponseDTO")]
pub struct OpenID4VCICredentialResponseRestDTO {
    pub credential: String,
    pub format: String,
}

#[derive(Clone, Debug, Deserialize, IntoParams, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerRejectQueryParams {
    pub credential_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, IntoParams, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerSubmitQueryParams {
    pub credential_id: Uuid,
}
