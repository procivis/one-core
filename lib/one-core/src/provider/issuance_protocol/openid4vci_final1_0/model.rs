use std::fmt;

use indexmap::IndexMap;
use one_dto_mapper::{Into, convert_inner};
use secrecy::{SecretSlice, SecretString};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use shared_types::OrganisationId;
use standardized_types::oauth2::dynamic_client_registration::TokenEndpointAuthMethod;
use strum::Display;
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::mapper::opt_secret_string;
use crate::mapper::params::deserialize_encryption_key;
use crate::model::credential_schema::{CodeTypeEnum, LayoutProperties};
use crate::provider::credential_formatter::vcdm::ContextType;
use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
use crate::provider::issuance_protocol::model::{
    OpenID4VCIProofTypeSupported, OpenID4VCITxCode, OpenID4VCRedirectUriParams,
    default_issuance_url_scheme,
};

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCIFinal1Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub pre_authorized_code_expires_in: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub token_expires_in: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub refresh_expires_in: Duration,
    #[serde(default)]
    pub credential_offer_by_value: bool,
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub encryption: SecretSlice<u8>,

    #[serde(default = "default_issuance_url_scheme")]
    pub url_scheme: String,

    pub redirect_uri: OpenID4VCRedirectUriParams,

    pub nonce: Option<OpenID4VCNonceParams>,

    pub oauth_attestation_leeway: u64,

    pub key_attestation_leeway: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCNonceParams {
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub signing_key: SecretSlice<u8>,
    pub expiration: Option<u64>,
    #[serde(default)]
    pub leeway: u64,
}

/// <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>
///
/// [RFC8414](https://datatracker.ietf.org/doc/html/rfc8414#section-2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OAuthAuthorizationServerMetadata {
    pub issuer: Url,
    pub authorization_endpoint: Option<Url>,
    pub token_endpoint: Option<Url>,
    pub pushed_authorization_request_endpoint: Option<Url>,
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<OAuthCodeChallengeMethod>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,

    /// Attestation-Based Client Authentication challenge endpoint
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-13.1>
    pub challenge_endpoint: Option<Url>,

    /// Attestation-Based Client Authentication - supported signing algorithms for client attestation
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-10.1>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_signing_alg_values_supported: Option<Vec<String>>,

    /// Attestation-Based Client Authentication - supported signing algorithms for client attestation PoP
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-10.1>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_attestation_pop_signing_alg_values_supported: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
}

/// [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#pkce-code-challenge-method)
///
/// [RFC7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OAuthCodeChallengeMethod {
    #[serde(rename = "plain")]
    Plain,
    #[serde(rename = "S256")]
    S256,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct HolderInteractionData {
    pub issuer_url: String,
    pub credential_endpoint: String,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub notification_endpoint: Option<String>,
    #[serde(default)]
    pub nonce_endpoint: Option<String>,
    #[serde(default)]
    pub challenge_endpoint: Option<String>,
    #[serde(default)]
    pub grants: Option<OpenID4VCIGrants>,
    #[serde(default)]
    pub continue_issuance: Option<ContinueIssuanceDTO>,
    #[serde(default)]
    pub access_token: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub refresh_token: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub credential_signing_alg_values_supported: Option<Vec<CredentialSigningAlgValue>>,
    #[serde(default)]
    pub proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<TokenEndpointAuthMethod>>,
    #[serde(default)]
    pub credential_metadata: Option<OpenID4VCICredentialMetadataResponseDTO>,
    pub credential_configuration_id: String,
    #[serde(default)]
    pub notification_id: Option<String>,

    /// selected issuance protocol (config identifier)
    pub protocol: String,

    /// OpenID4VCI credential format (of the offered credential)
    pub format: String,
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4
#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataResponseDTO {
    pub credential_issuer: String,
    pub authorization_servers: Option<Vec<String>>,
    pub credential_endpoint: String,
    pub nonce_endpoint: Option<String>,
    pub notification_endpoint: Option<String>,
    pub credential_configurations_supported:
        IndexMap<String, OpenID4VCICredentialConfigurationData>,
    pub display: Option<Vec<OpenID4VCIIssuerMetadataDisplayResponseDTO>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIIssuerMetadataDisplayResponseDTO {
    pub name: String,
    pub locale: Option<String>,
    pub logo: Option<OpenID4VCIIssuerMetadataLogoDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct OpenID4VCIIssuerMetadataLogoDTO {
    pub uri: String,
    pub alt_text: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OpenID4VCICredentialConfigurationData {
    pub format: String,
    pub credential_metadata: Option<OpenID4VCICredentialMetadataResponseDTO>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_alg_values_supported: Option<Vec<CredentialSigningAlgValue>>,
    pub proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    pub scope: Option<String>,

    // mandatory for W3C formats
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1.1.2
    pub credential_definition: Option<OpenID4VCICredentialDefinition>,

    // mandatory for mso_mdoc
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.2.2
    pub doctype: Option<String>,

    // mandatory for SD-JWT VC
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3.2
    pub vct: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OpenID4VCICredentialDefinition {
    pub r#type: Vec<String>,
    #[serde(rename = "@context")]
    pub context: Option<Vec<ContextType>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCICredentialMetadataResponseDTO {
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO>>,
    pub claims: Option<Vec<OpenID4VCICredentialMetadataClaimResponseDTO>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
    pub name: String,
    pub locale: Option<String>,
    pub logo: Option<OpenID4VCIIssuerMetadataLogoDTO>,
    pub description: Option<String>,
    pub background_color: Option<String>,
    pub background_image: Option<OpenID4VCIIssuerMetadataCredentialMetadataImage>,
    pub text_color: Option<String>,

    // procivis extension
    pub procivis_design: Option<OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OpenID4VCIIssuerMetadataCredentialMetadataImage {
    pub uri: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign {
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    pub code_attribute: Option<String>,
    pub code_type: Option<CodeTypeEnum>,
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-B.2
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCICredentialMetadataClaimResponseDTO {
    pub path: Vec<String>,
    pub display: Option<Vec<OpenID4VCIIssuerMetadataClaimDisplay>>,
    pub mandatory: Option<bool>,
    pub additional_values: Option<IndexMap<String, serde_json::Value>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIIssuerMetadataClaimDisplay {
    pub name: Option<String>,
    pub locale: Option<String>,
}

pub use super::super::model::CredentialSigningAlgValue;

#[derive(Clone, Debug, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

#[derive(Debug, Deserialize)]
pub struct OpenID4VCITokenResponseDTO {
    pub access_token: SecretString,
    pub token_type: String,
    pub expires_in: Timestamp,
    #[serde(default, with = "opt_secret_string")]
    pub refresh_token: Option<SecretString>,
    #[serde(default)]
    pub refresh_token_expires_in: Option<Timestamp>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCINonceResponseDTO {
    pub c_nonce: String,
}

/// Response from the attestation-based client authentication challenge endpoint
/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-8>
#[derive(Clone, Debug, Deserialize)]
pub struct ChallengeResponseDTO {
    pub attestation_challenge: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "grant_type")]
pub enum OpenID4VCITokenRequestDTO {
    /// [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1)
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode {
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,
        tx_code: Option<String>,
    },

    /// [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)
    #[serde(rename = "authorization_code")]
    AuthorizationCode {
        #[serde(rename = "code")]
        authorization_code: String,
        client_id: String,
        redirect_uri: Option<String>,

        /// [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636#section-4.5)
        code_verifier: Option<String>,
    },

    #[serde(rename = "refresh_token")]
    RefreshToken { refresh_token: String },
}

impl OpenID4VCITokenRequestDTO {
    pub fn is_pre_authorized_code(&self) -> bool {
        matches!(self, Self::PreAuthorizedCode { .. })
    }

    pub fn is_refresh_token(&self) -> bool {
        matches!(self, Self::RefreshToken { .. })
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OpenID4VCIIssuerInteractionDataDTO {
    pub pre_authorized_code_used: bool,
    pub access_token_hash: Vec<u8>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub refresh_token_hash: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub notification_id: Option<String>,
    pub transaction_code: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCICredentialDefinitionRequestDTO {
    pub r#type: Vec<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<OpenID4VCICredentialSubjectItem>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCICredentialRequestDTO {
    #[serde(flatten)]
    pub credential: OpenID4VCICredentialRequestIdentifier,
    pub proofs: Option<OpenID4VCICredentialRequestProofs>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenID4VCICredentialRequestIdentifier {
    CredentialConfigurationId(String),
    CredentialIdentifier(String),
}

/// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types>
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenID4VCICredentialRequestProofs {
    Jwt(Vec<String>),
    DiVp(Vec<String>),
    Attestation([String; 1]),
}

#[derive(Clone, Debug, Serialize, Display)]
#[serde(rename_all = "snake_case")]
pub enum OpenID4VCINotificationEvent {
    CredentialAccepted,
    CredentialFailure,
    CredentialDeleted,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCINotificationRequestDTO {
    pub notification_id: String,
    pub event: OpenID4VCINotificationEvent,
    pub event_description: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Into)]
#[into(LayoutProperties)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaLayoutPropertiesRequestDTO {
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRequestDTO>,
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRequestDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesRequestDTO>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaLogoPropertiesRequestDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaBackgroundPropertiesRequestDTO {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaCodePropertiesRequestDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeEnum,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CredentialSchemaCodeTypeEnum {
    Barcode,
    Mrz,
    QrCode,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIFinal1CredentialOfferDTO {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: OpenID4VCIGrants,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum OpenID4VCIGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode(OpenID4VCIPreAuthorizedCodeGrant),
    #[serde(rename = "authorization_code")]
    AuthorizationCode(OpenID4VCIAuthorizationCodeGrant),
}

impl OpenID4VCIGrants {
    pub fn tx_code(&self) -> Option<&OpenID4VCITxCode> {
        match self {
            OpenID4VCIGrants::PreAuthorizedCode(pre_authorized_code) => {
                pre_authorized_code.tx_code.as_ref()
            }
            OpenID4VCIGrants::AuthorizationCode(_authorization_code) => None,
        }
    }

    pub fn authorization_server(&self) -> Option<&String> {
        match self {
            OpenID4VCIGrants::PreAuthorizedCode(pre_authorized_code) => {
                pre_authorized_code.authorization_server.as_ref()
            }
            OpenID4VCIGrants::AuthorizationCode(authorization_code) => {
                authorization_code.authorization_server.as_ref()
            }
        }
    }
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIPreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default)]
    pub tx_code: Option<OpenID4VCITxCode>,
    pub authorization_server: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIAuthorizationCodeGrant {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Debug, Default, PartialEq, Eq)]
pub struct OpenID4VCICredentialSubjectItem {
    // Rest of the keys as objects
    #[serde(flatten, deserialize_with = "empty_is_none")]
    pub claims: Option<IndexMap<String, OpenID4VCICredentialSubjectItem>>,

    // Array of objects descritpion
    #[serde(flatten, deserialize_with = "empty_is_none")]
    pub arrays: Option<IndexMap<String, Vec<OpenID4VCICredentialSubjectItem>>>,

    // Additional unexpected keys with just string values
    #[serde(flatten, deserialize_with = "empty_is_none")]
    pub additional_values: Option<IndexMap<String, serde_json::Value>>,

    #[serde(default)]
    pub display: Option<Vec<CredentialSubjectDisplay>>,
    #[serde(default)]
    pub value_type: Option<String>,
    #[serde(default)]
    pub mandatory: Option<bool>,

    // This is custom and optional - keeps the presentation order of claims
    #[serde(default)]
    pub order: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for OpenID4VCICredentialSubjectItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Create a custom visitor for handling dynamic keys
        struct OpenID4VCICredentialSubjectItemVisitor;

        impl<'de> Visitor<'de> for OpenID4VCICredentialSubjectItemVisitor {
            type Value = OpenID4VCICredentialSubjectItem;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map representing OpenID4VCICredentialSubjectItem")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut claims = IndexMap::new();
                let mut arrays = IndexMap::new();
                let mut additional_values = IndexMap::new();
                let mut display = None;
                let mut value_type = None;
                let mut mandatory = None;
                let mut order = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        // Predefined keys
                        "display" => {
                            display = Some(map.next_value()?);
                        }
                        "value_type" => {
                            value_type = Some(map.next_value::<String>()?.to_uppercase());
                        }
                        "mandatory" => {
                            mandatory = Some(map.next_value()?);
                        }
                        "order" => {
                            order = Some(map.next_value()?);
                        }
                        _ => {
                            // Dynamic keys
                            let next_value = map.next_value::<serde_json::Value>()?;

                            // Classify the field by inspecting its type
                            if next_value.is_object() {
                                match serde_json::from_value::<OpenID4VCICredentialSubjectItem>(
                                    next_value.clone(),
                                ) {
                                    Ok(obj) => {
                                        // Check if array
                                        if let Some(value_type) = obj
                                            .value_type
                                            .as_ref()
                                            .and_then(|vt| vt.strip_suffix("[]"))
                                        {
                                            arrays.insert(
                                                key,
                                                vec![OpenID4VCICredentialSubjectItem {
                                                    value_type: Some(value_type.to_string()),
                                                    ..Default::default()
                                                }],
                                            );
                                        } else {
                                            claims.insert(key, obj);
                                        }
                                    }
                                    Err(_) => {
                                        // If it fails to deserialize, add it to additional_values
                                        additional_values.insert(key, next_value);
                                    }
                                }
                            } else if next_value.is_array() {
                                // Handle arrays
                                // First try to deserialize as our custom array
                                match serde_json::from_value::<Vec<OpenID4VCICredentialSubjectItem>>(
                                    next_value.clone(),
                                ) {
                                    Ok(arr) => {
                                        arrays.insert(key, arr);
                                    }
                                    Err(_) => {
                                        // If it fails, add as additional value
                                        additional_values.insert(key, next_value);
                                    }
                                }
                            } else if next_value.is_string()
                                || next_value.is_boolean()
                                || next_value.is_number()
                            {
                                additional_values.insert(key, next_value);
                            } else {
                                // For any other type, add to additional values
                                additional_values.insert(key, next_value);
                            }
                        }
                    }
                }

                Ok(OpenID4VCICredentialSubjectItem {
                    claims: if claims.is_empty() {
                        None
                    } else {
                        Some(claims)
                    },
                    arrays: if arrays.is_empty() {
                        None
                    } else {
                        Some(arrays)
                    },
                    additional_values: if additional_values.is_empty() {
                        None
                    } else {
                        Some(additional_values)
                    },
                    display,
                    value_type,
                    mandatory,
                    order,
                })
            }
        }

        deserializer.deserialize_map(OpenID4VCICredentialSubjectItemVisitor)
    }
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CredentialSubjectDisplay {
    pub name: Option<String>,
    pub locale: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialIssuerParams {
    #[expect(dead_code)]
    pub logo: Option<String>,
    pub issuer: String,
    pub client_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuationIssuanceDTO {
    pub organisation_id: OrganisationId,
    pub protocol: String,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<Vec<String>>,
    pub authorization_details: Option<Vec<ContinueIssuanceAuthorizationDetailDTO>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinueIssuanceAuthorizationDetailDTO {
    pub r#type: String,
    pub credential_configuration_id: String,
}

#[derive(Debug)]
pub(super) struct TokenRequestWalletAttestationRequest {
    pub wallet_attestation: String,
    pub wallet_attestation_pop: String,
}

#[derive(Debug, Default)]
pub(super) struct WalletAttestationResult {
    /// WIA with proof-of-possession for token request (if WIA is used)
    pub wia_request: Option<TokenRequestWalletAttestationRequest>,
    /// WUA proof for credential request (if key attestation is required)
    pub wua_proof: Option<String>,
}
