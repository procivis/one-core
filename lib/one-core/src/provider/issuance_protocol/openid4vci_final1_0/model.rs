use std::fmt;

use indexmap::IndexMap;
use one_dto_mapper::{Into, convert_inner};
use secrecy::SecretSlice;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use shared_types::{CredentialId, CredentialSchemaFormatId};
use standardized_types::etsi_119_472::disclosure_policy::DisclosurePolicy;
use standardized_types::oauth2::dynamic_client_registration::TokenEndpointAuthMethod;
use standardized_types::openid4vci::{
    CredentialConfiguration, CredentialMetadata, CredentialRequestEncryption,
    CredentialResponseEncryption, Grants, IssuerDisplay, ProofTypeSupported, SigningAlgValue,
};
use time::{Duration, OffsetDateTime};

use super::super::HolderBindingInput;
use super::super::dto::ContinueIssuanceDTO;
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

    /// Holder-side DPoP key configuration.
    /// If not configured, the holder will not use DPoP.
    #[serde(default)]
    pub holder_dpop_key_storage: Option<String>,

    /// Issuer DPoP configuration
    #[serde(default)]
    pub dpop: Option<OpenID4VCDpopParams>,
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
    pub grants: Option<Grants>,
    #[serde(default)]
    pub continue_issuance: Option<ContinueIssuanceDTO>,
    #[serde(default)]
    pub batch_size: Option<u32>,
    #[serde(default)]
    pub access_token: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub refresh_token: Option<Vec<u8>>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    #[serde(default)]
    pub client_attestation_pop_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub issuer_display: Option<Vec<IssuerDisplay>>,
    #[serde(default)]
    pub credential_request_encryption: Option<CredentialRequestEncryption>,
    #[serde(default)]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    /// DPoP signing algorithms the authorization server advertises. `None` means the issuance is
    /// not DPoP bound; otherwise the binding key is generated from this list when the offer is
    /// accepted.
    #[serde(default)]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub dpop_nonce: Option<String>,

    /// selected issuance protocol (config identifier)
    pub protocol: String,

    /// offered credential configurations, in the order of the credential offer
    #[serde(
        flatten,
        serialize_with = "serialize_credential_configurations",
        deserialize_with = "deserialize_credential_configurations"
    )]
    pub credential_configurations: Vec<HolderCredentialConfiguration>,
}

#[derive(Serialize, Deserialize)]
struct CredentialConfigurations<T> {
    credential_configurations: T,
}

// interactions created before multi-format support store the single configuration at the top level
fn deserialize_credential_configurations<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<HolderCredentialConfiguration>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Entries(CredentialConfigurations<Vec<HolderCredentialConfiguration>>),
        Legacy(Box<HolderCredentialConfiguration>),
    }

    Ok(match Repr::deserialize(deserializer)? {
        Repr::Entries(entries) => entries.credential_configurations,
        Repr::Legacy(configuration) => vec![*configuration],
    })
}

// a flattened field serializes as a map, not as a sequence
fn serialize_credential_configurations<S: Serializer>(
    credential_configurations: &[HolderCredentialConfiguration],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    CredentialConfigurations {
        credential_configurations,
    }
    .serialize(serializer)
}

impl HolderInteractionData {
    /// configurations selected for acceptance, in the order of the offer
    pub fn selected_configurations(
        &self,
        credential_configuration_ids: &[String],
    ) -> Vec<HolderCredentialConfiguration> {
        self.credential_configurations
            .iter()
            .filter(|c| credential_configuration_ids.contains(&c.credential_configuration_id))
            .cloned()
            .collect()
    }

    pub fn configuration_mut(
        &mut self,
        credential_configuration_id: &str,
    ) -> Option<&mut HolderCredentialConfiguration> {
        self.credential_configurations
            .iter_mut()
            .find(|c| c.credential_configuration_id == credential_configuration_id)
    }

    /// Successful configurations associated with the main credential
    pub fn configurations_for_credential(
        &self,
        credential_id: CredentialId,
    ) -> impl Iterator<Item = &HolderCredentialConfiguration> {
        self.credential_configurations.iter().filter(move |c| {
            c.credential_id == Some(credential_id)
                    // Legacy interactions have one configuration without a credential ID.
                    || (c.credential_id.is_none() && self.credential_configurations.len() == 1)
        })
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct HolderCredentialConfiguration {
    pub credential_configuration_id: String,
    /// OpenID4VCI credential format
    pub format: String,
    #[serde(default)]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub credential_signing_alg_values_supported: Option<Vec<SigningAlgValue>>,
    #[serde(default)]
    pub proof_types_supported: Option<IndexMap<String, ProofTypeSupported>>,
    #[serde(default)]
    pub credential_metadata: Option<CredentialMetadata>,
    #[serde(default)]
    pub disclosure_policy: Option<DisclosurePolicy>,
    #[serde(default)]
    pub notification_id: Option<String>,
    /// main credential created for this configuration
    #[serde(default)]
    pub credential_id: Option<CredentialId>,
    /// Exact format of the issued items; absent in interactions created before format routing.
    #[serde(default)]
    pub credential_schema_format_id: Option<CredentialSchemaFormatId>,
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
    #[serde(default)]
    pub dpop_jkt: Option<String>,
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
    pub wallet_attestation_pop: String,
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

#[derive(Debug, Clone)]
pub(crate) struct PreparedMetadata {
    pub(crate) protocol_base_url: String,
    pub(crate) schema: CredentialSchema,
    pub(crate) credential_configurations_supported: IndexMap<String, CredentialConfiguration>,
}
