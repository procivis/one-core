use std::fmt;
use std::num::NonZeroU32;

use indexmap::IndexMap;
use one_dto_mapper::{Into, convert_inner};
use secrecy::SecretSlice;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use shared_types::{CredentialId, CredentialSchemaFormatId, SerializedCredential};
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::openid4vci::{CredentialConfiguration, CredentialIssuerMetadata};
use time::{Duration, OffsetDateTime};

use super::super::HolderBindingInput;
use super::super::error::IssuanceProtocolError;
use super::super::model::{CommonParams, OpenID4VCRedirectUriParams, default_issuance_url_scheme};
use crate::config::core_config::{KeyAlgorithmType, default_true};
use crate::mapper::params::deserialize_encryption_key;
use crate::model::credential_schema::{CodeTypeEnum, CredentialSchema, LayoutProperties};
use crate::model::identifier::Identifier;
use crate::model::key::Key;

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCIFinal1Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub pre_authorized_code_expires_in_seconds: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub token_expires_in_seconds: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub refresh_expires_in_seconds: Duration,
    #[serde(default)]
    pub credential_offer_by_value: bool,
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub encryption: SecretSlice<u8>,

    #[serde(default = "default_issuance_url_scheme")]
    pub url_scheme: String,

    pub redirect_uri: OpenID4VCRedirectUriParams,

    pub nonce: Option<OpenID4VCNonceParams>,
    pub oauth_attestation_challenge: Option<OpenID4VCNonceParams>,

    #[serde_as(as = "DurationSeconds<i64>")]
    pub oauth_attestation_leeway_seconds: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub key_attestation_leeway_seconds: Duration,

    #[serde(default)]
    pub credential_endpoint_encryption: CredentialEndpointEncryptionParams,

    /// Enables the deviations required by the swiyu ecosystem: the credential offer is always
    /// embedded by value, the issuer endpoints are served under a dedicated URL path, outgoing
    /// requests carry the swiyu API version header and the advertised capabilities are narrowed
    /// down to what the swiyu wallet supports.
    #[serde(default)]
    pub swiyu_mode: bool,

    #[serde(flatten)]
    pub common: CommonParams,

    #[serde(default)]
    pub holder: OpenID4VCIFinal1HolderParams,

    /// Issuer DPoP configuration
    #[serde(default)]
    pub dpop: Option<OpenID4VCDpopParams>,

    /// Issuer: requires refresh token requests to present a client attestation with the same
    /// Client Instance Key (`cnf`) as the one the refresh token was issued to.
    /// Spec: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-12#section-10.3>
    ///
    /// Holders using a new key for every client attestation cannot refresh tokens while enabled.
    #[serde(default = "default_true")]
    pub enforce_client_instance_binding: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCIFinal1HolderParams {
    /// Holder-side DPoP key configuration.
    /// If not configured, the holder will not use DPoP.
    #[serde(default)]
    pub dpop_key_storage: Option<String>,

    /// Holder-side key storage of the Client Instance Keys of client attestations (WIA), needed
    /// when the DPoP key cannot be used as Client Instance Key.
    #[serde(default)]
    pub client_attestation_key_storage: Option<String>,

    /// Maximum number of proofs per credential request. A batch with more holder bindings is
    /// split into several credential requests. If not configured, one credential request
    /// contains all proofs of the batch.
    #[serde(default)]
    pub max_proofs_per_credential_request: Option<NonZeroU32>,

    /// Maximum number of concurrent credential requests of one batch.
    #[serde(default = "default_max_parallel_credential_requests")]
    pub max_parallel_credential_requests: NonZeroU32,
}

fn default_max_parallel_credential_requests() -> NonZeroU32 {
    NonZeroU32::MIN
}

impl Default for OpenID4VCIFinal1HolderParams {
    fn default() -> Self {
        Self {
            dpop_key_storage: None,
            client_attestation_key_storage: None,
            max_proofs_per_credential_request: None,
            max_parallel_credential_requests: default_max_parallel_credential_requests(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialEndpointEncryptionParams {
    #[serde(default)]
    pub request_required: bool,
    #[serde(default)]
    pub response_required: bool,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCNonceParams {
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub signing_key: SecretSlice<u8>,
    #[serde(default = "default_5_minutes")]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expiration_seconds: Duration,
    #[serde(default)]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway_seconds: Duration,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCDpopParams {
    #[serde(default = "default_true")]
    pub enforced: bool,
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub signing_key: SecretSlice<u8>,
    #[serde(default = "default_5_minutes")]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub nonce_validity_seconds: Duration,
    #[serde(default = "default_1_minute")]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub nonce_refresh_threshold_seconds: Duration,
    #[serde(default)]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway_seconds: Duration,
    pub signing_algorithms: Vec<KeyAlgorithmType>,
}

pub(super) fn default_1_minute() -> Duration {
    Duration::minutes(1)
}
pub(super) fn default_5_minutes() -> Duration {
    Duration::minutes(5)
}

/// Holder side data of an OpenID4VCI issuance, stored in the interaction.
///
/// Persisted: changes must stay compatible with the stored data checked by `test_stored_data`
/// (or come with a DB migration).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct HolderInteractionData {
    /// selected issuance protocol (config identifier)
    pub protocol: String,
    /// Credential issuer metadata at the time of the invitation, limited to the offered
    /// credential configurations. Never modified.
    ///
    /// Stored without display data (`display` and the `credential_metadata` of the configurations,
    /// including logos): accepting the offer takes it from the current issuer metadata.
    pub issuer_metadata: CredentialIssuerMetadata,
    /// Metadata of the authorization server used for this issuance. Never modified.
    pub authorization_server_metadata: AuthorizationServerMetadata,
    pub metadata_source: MetadataSource,
    /// Everything written during the issuance and later refreshes
    pub state: HolderIssuanceState,
}

/// Origin of the metadata snapshot of a [`HolderInteractionData`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MetadataSource {
    /// fetched from the issuer and the authorization server when handling the invitation
    Fetched,
    /// Reconstructed by a DB migration from the few metadata fields stored by earlier versions.
    /// Metadata outside of that subset is unknown, not absent. The authorization server
    /// `issuer` is the credential issuer.
    Migrated,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct HolderIssuanceState {
    /// Grant to redeem at the token endpoint. `None` if unknown: interactions migrated from data
    /// without grant, which can only refresh tokens.
    pub grant: Option<TokenGrant>,
    /// Client ID of the authorization code flow, also the `iss` of credential request proofs
    pub client_id: Option<String>,
    pub tokens: TokenState,
    pub dpop: DpopState,
    /// offered credential configurations, in the order of the offer
    pub credential_configurations: Vec<HolderCredentialConfigurationState>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum TokenGrant {
    /// the transaction code is supplied when accepting the offer
    PreAuthorizedCode { pre_authorized_code: String },
    AuthorizationCode {
        authorization_code: String,
        redirect_uri: Option<String>,
        code_verifier: Option<String>,
    },
}

/// Encrypted tokens of the token endpoint
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub(crate) struct TokenState {
    pub access_token: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub(crate) struct DpopState {
    pub nonce: Option<String>,
    /// The issuer answered with a Bearer token: the issuance is not DPoP bound even though the
    /// authorization server advertises DPoP.
    pub disabled: bool,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct HolderCredentialConfigurationState {
    pub credential_configuration_id: String,
    /// Each notification_id corresponds to one credential response
    /// For cases where the holder retrieves the batch items in batches
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notification_ids: Vec<String>,
    /// Top-level credential (single or batch parent) holding the items of this configuration.
    /// Grouped configurations (same schema, ecosystem and claims, e.g. one credential in several
    /// formats) share it, different credentials of one offer have different IDs.
    /// `None` if not issued.
    pub credential_id: Option<CredentialId>,
    /// exact format of the issued items, `None` if not issued
    pub credential_schema_format_id: Option<CredentialSchemaFormatId>,
}

impl HolderInteractionData {
    pub fn issuer_url(&self) -> &str {
        &self.issuer_metadata.credential_issuer
    }

    pub fn batch_size(&self) -> Option<u32> {
        self.issuer_metadata
            .batch_credential_issuance
            .as_ref()
            .map(|batch| batch.batch_size)
    }

    /// DPoP signing algorithms to bind the issuance with, `None` if not DPoP bound
    pub fn dpop_signing_alg_values_supported(&self) -> Option<&[String]> {
        if self.state.dpop.disabled {
            return None;
        }
        self.authorization_server_metadata
            .dpop_signing_alg_values_supported
            .as_deref()
    }

    /// configurations selected for acceptance, in the order of the offer
    pub fn selected_configurations(
        &self,
        credential_configuration_ids: &[String],
    ) -> Result<Vec<HolderCredentialConfiguration>, IssuanceProtocolError> {
        self.state
            .credential_configurations
            .iter()
            .filter(|c| credential_configuration_ids.contains(&c.credential_configuration_id))
            .map(|state| self.configuration(state))
            .collect()
    }

    /// all offered configurations, in the order of the offer
    pub fn configurations(
        &self,
    ) -> Result<Vec<HolderCredentialConfiguration>, IssuanceProtocolError> {
        self.state
            .credential_configurations
            .iter()
            .map(|state| self.configuration(state))
            .collect()
    }

    fn configuration(
        &self,
        state: &HolderCredentialConfigurationState,
    ) -> Result<HolderCredentialConfiguration, IssuanceProtocolError> {
        let metadata = self
            .issuer_metadata
            .credential_configurations_supported
            .get(&state.credential_configuration_id)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!(
                    "Credential configuration {} missing from issuer metadata",
                    state.credential_configuration_id
                ))
            })?;
        Ok(HolderCredentialConfiguration {
            metadata: metadata.to_owned(),
            state: state.to_owned(),
        })
    }

    pub fn configuration_mut(
        &mut self,
        credential_configuration_id: &str,
    ) -> Option<&mut HolderCredentialConfigurationState> {
        self.state
            .credential_configurations
            .iter_mut()
            .find(|c| c.credential_configuration_id == credential_configuration_id)
    }

    /// Configurations associated with the main credential
    pub fn configurations_for_credential(
        &self,
        credential_id: CredentialId,
    ) -> Result<Vec<HolderCredentialConfiguration>, IssuanceProtocolError> {
        self.state
            .credential_configurations
            .iter()
            .filter(|c| c.credential_id == Some(credential_id))
            .map(|state| self.configuration(state))
            .collect()
    }
}

/// An offered credential configuration: its issuer metadata and its issuance state
#[derive(Debug, Clone)]
pub(crate) struct HolderCredentialConfiguration {
    pub metadata: CredentialConfiguration,
    pub state: HolderCredentialConfigurationState,
}

impl HolderCredentialConfiguration {
    pub fn id(&self) -> &str {
        &self.state.credential_configuration_id
    }
}

// procivis extension under CredentialDisplay
pub const PROCIVIS_DESIGN_KEY: &str = "procivis_design";

/// `profile_version` advertised in the issuer metadata of a swiyu issuer.
///
/// Spec: Swiss Profile for Issuance, Section 12.2.4
/// <https://swiyu-admin-ch.github.io/specifications/swiss-profile-issuance/#1224-credential-issuer-metadata-parameters>
pub(crate) const SWISS_PROFILE_ISSUANCE_VERSION: &str = "swiss-profile-issuance:1.0.0";

/// Prefix shared by all versions of [`SWISS_PROFILE_ISSUANCE_VERSION`], marking an issuer as part
/// of the swiyu ecosystem regardless of the profile version it implements.
pub(crate) const SWISS_PROFILE_ISSUANCE_PREFIX: &str = "swiss-profile-issuance:";

/// Swiss Profile header claims of a signed metadata document, next to the standard JOSE header.
///
/// Spec: Swiss Profile for Issuance, Section 12.2.3
/// <https://swiyu-admin-ch.github.io/specifications/swiss-profile-issuance/#1223-signed-metadata>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct SwissProfileHeader {
    /// Ecosystem profile the document conforms to, e.g. [`SWISS_PROFILE_ISSUANCE_VERSION`]; unset
    /// outside of swiyu mode, where no marker is emitted at all.
    pub profile_version: Option<String>,
}

/// URL schemes a swiyu credential offer may use. A swiyu wallet accepts an offer under either of
/// them, while offers it creates itself carry the configured [`OpenID4VCIFinal1Params::url_scheme`].
///
/// Spec: Swiss Profile for Issuance, Section 4.1.2
/// <https://swiyu-admin-ch.github.io/specifications/swiss-profile-issuance/#412-sending-credential-offer-by-value-using-credential_offer-parameter>
pub(crate) const SWIYU_URL_SCHEMES: [&str; 2] = ["openid-credential-offer", "swiyu"];

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign {
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    pub code_attribute: Option<String>,
    pub code_type: Option<CodeTypeEnum>,
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
    #[serde(
        default,
        alias = "notification_id",
        deserialize_with = "deserialize_format_notifications"
    )]
    pub notification_ids: Vec<FormatNotification>,
    pub transaction_code: Option<String>,
    #[serde(default)]
    pub formats: Option<Vec<CredentialSchemaFormatId>>,
    /// JWK SHA-256 thumbprint of the DPoP key the issued tokens are bound to
    #[serde(default)]
    pub dpop_jkt: Option<String>,
    /// JWK SHA-256 thumbprint of the Client Instance Key (`cnf` of the client attestation) the
    /// refresh token is bound to
    #[serde(default)]
    pub client_instance_jkt: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FormatNotification {
    pub notification_id: String,
    /// missing on interactions created before multi-format support
    #[serde(default)]
    pub format: Option<CredentialSchemaFormatId>,
}

// interactions created before multi-format support store a single `notification_id` without format
fn deserialize_format_notifications<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<FormatNotification>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Entries(Vec<FormatNotification>),
        LegacyNotificationId(Option<String>),
    }

    Ok(match Repr::deserialize(deserializer)? {
        Repr::Entries(entries) => entries,
        Repr::LegacyNotificationId(notification_id) => notification_id
            .map(|notification_id| FormatNotification {
                notification_id,
                format: None,
            })
            .into_iter()
            .collect(),
    })
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCICredentialDefinitionRequestDTO {
    pub r#type: Vec<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<OpenID4VCICredentialSubjectItem>,
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

#[derive(Debug)]
pub(super) struct TokenRequestAttestationHeaders {
    pub wallet_attestation: String,
    /// `None` in DPoP combined mode, where the DPoP proof serves as proof of possession
    pub wallet_attestation_pop: Option<String>,
    /// Client Instance Key of the wallet attestation
    pub client_attestation_key: Key,
}

/// holder binding of a credential, with the key attestation when the issuer requires one
#[derive(Debug, Clone)]
pub(super) struct HolderBinding {
    pub identifier: Identifier,
    pub key: Key,
    pub wua_proof: Option<String>,
}

impl From<HolderBindingInput> for HolderBinding {
    fn from(input: HolderBindingInput) -> Self {
        Self {
            identifier: input.identifier,
            key: input.key,
            wua_proof: None,
        }
    }
}

/// credential requested from the issuer, one holder binding per credential of a batch
pub(super) struct RequestedCredential {
    pub configuration: HolderCredentialConfiguration,
    pub holder_bindings: Vec<HolderBinding>,
}

/// issuer response to one credential request
pub(super) struct CredentialRequestResponse {
    pub credentials: Vec<SerializedCredential>,
    pub redirect_uri: Option<String>,
    pub notification_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedMetadata {
    pub(crate) protocol_base_url: String,
    pub(crate) schema: CredentialSchema,
    pub(crate) credential_configurations_supported: IndexMap<String, CredentialConfiguration>,
}
