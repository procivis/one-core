//! Credential Issuer Metadata
//!
//! Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata>

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::{VecSkipError, serde_as, skip_serializing_none};

use crate::etsi_119_472::disclosure_policy::DisclosurePolicy;
use crate::iana::{EncryptionAlgorithm, EncryptionKeyManagementAlgorithm};
use crate::jwe::CompressionAlgorithm;
use crate::jwk::Jwks;
use crate::openid4vp::dcql::{ClaimPath, CredentialQueryId};
use crate::w3c_vcdm::Context;

/// Credential Issuer Metadata document, served from
/// `/.well-known/openid-credential-issuer`.
///
/// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    pub authorization_servers: Option<Vec<String>>,
    pub credential_endpoint: String,
    pub nonce_endpoint: Option<String>,
    pub notification_endpoint: Option<String>,
    pub credential_configurations_supported: IndexMap<String, CredentialConfiguration>,
    pub display: Option<Vec<IssuerDisplay>>,
    /// ETSI TS 119 472-3 V1.1.1, Section 4.2.3
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_info: Vec<IssuerInfoAttestation>,
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,
    pub credential_request_encryption: Option<CredentialRequestEncryption>,
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    /// EUDI TS3 Wallet Unit Attestation V1.5.2, Section 2.4.2
    pub preferred_client_status_period: Option<u64>,
}

/// Entry of the `issuer_info` Credential Issuer Metadata parameter.
///
/// Spec: ETSI TS 119 472-3 V1.1.1, Section 4.2.3
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct IssuerInfoAttestation {
    pub format: IssuerInfoAttestationFormat,
    pub data: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_ids: Vec<CredentialQueryId>,
}

/// Format of an [`IssuerInfoAttestation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum IssuerInfoAttestationFormat {
    /// ETSI TS 119 472-3 V1.1.1, Section 4.2.3
    RegistrationCert,
}

/// Display properties of the Credential Issuer itself, for a given locale.
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct IssuerDisplay {
    pub name: String,
    pub locale: Option<String>,
    pub logo: Option<Image>,
}

/// Image object, as used for `logo` and `background_image`.
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Image {
    pub uri: String,
    pub alt_text: Option<String>,
}

/// Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-batch-credential-issuance>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct BatchCredentialIssuance {
    pub batch_size: u32,
}

/// Credential Request encryption parameters advertised by the Credential Issuer.
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CredentialRequestEncryption {
    pub jwks: Jwks,
    #[serde_as(as = "VecSkipError<_>")]
    pub enc_values_supported: Vec<EncryptionAlgorithm>,
    #[serde_as(as = "VecSkipError<_>")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zip_values_supported: Vec<CompressionAlgorithm>,
    pub encryption_required: bool,
}

/// Credential Response encryption parameters advertised by the Credential Issuer.
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CredentialResponseEncryption {
    #[serde_as(as = "VecSkipError<_>")]
    pub alg_values_supported: Vec<EncryptionKeyManagementAlgorithm>,
    #[serde_as(as = "VecSkipError<_>")]
    pub enc_values_supported: Vec<EncryptionAlgorithm>,
    #[serde_as(as = "VecSkipError<_>")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zip_values_supported: Vec<CompressionAlgorithm>,
    pub encryption_required: bool,
}

/// An entry of `credential_configurations_supported`.
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    pub format: String,
    pub credential_metadata: Option<CredentialMetadata>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_alg_values_supported: Option<Vec<SigningAlgValue>>,
    pub proof_types_supported: Option<IndexMap<String, ProofTypeSupported>>,
    pub scope: Option<String>,

    /// Mandatory for W3C formats.
    /// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1.1.2>
    pub credential_definition: Option<CredentialDefinition>,

    /// Mandatory for `mso_mdoc`.
    /// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.2.2>
    pub doctype: Option<String>,

    /// Mandatory for SD-JWT VC.
    /// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3.2>
    pub vct: Option<String>,

    /// Spec: ETSI TS 119 472-2
    pub disclosure_policy: Option<DisclosurePolicy>,
}

/// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1.1.2>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CredentialDefinition {
    pub r#type: Vec<String>,
    #[serde(rename = "@context")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>, nullable = false))]
    pub context: Option<Vec<Context>>,
}

/// Display and claim metadata of a credential configuration.
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub display: Option<Vec<CredentialDisplay>>,
    pub claims: Option<Vec<ClaimMetadata>>,
}

/// Display properties of a credential configuration, for a given locale.
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialDisplay {
    pub name: String,
    pub locale: Option<String>,
    pub logo: Option<Image>,
    pub description: Option<String>,
    pub background_color: Option<String>,
    pub background_image: Option<Image>,
    pub text_color: Option<String>,

    /// The Credential Display Object is open; members not defined by the specification are
    /// retained here rather than discarded.
    #[serde(flatten, default, skip_serializing_if = "IndexMap::is_empty")]
    pub additional_values: IndexMap<String, serde_json::Value>,
}

/// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-B.2>
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ClaimMetadata {
    pub path: ClaimPath,
    pub display: Option<Vec<ClaimDisplay>>,
    pub mandatory: Option<bool>,
    /// The Claims Description Object is open; members not defined by the specification are
    /// retained here rather than discarded.
    #[serde(flatten, default, skip_serializing_if = "IndexMap::is_empty")]
    pub additional_values: IndexMap<String, serde_json::Value>,
}

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ClaimDisplay {
    pub name: Option<String>,
    pub locale: Option<String>,
}

/// Credential signing algorithm value: a JOSE algorithm name (e.g. `ES256`) or a COSE algorithm
/// identifier (e.g. `-7`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum SigningAlgValue {
    String(String),
    Integer(i64),
}

/// An entry of `proof_types_supported`.
///
/// Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
    pub key_attestations_required: Option<KeyAttestationsRequired>,
}

/// Key attestation requirements of a proof type.
///
/// Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-attestations>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttestationsRequired {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_storage: Vec<KeyStorageSecurityLevel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_authentication: Vec<String>,
    /// EUDI TS3 Wallet Unit Attestation V1.5.2, Section 2.4.2
    pub preferred_key_storage_status_period: Option<u64>,
}

/// Attack potential resistance level of the key storage, as defined by ISO/IEC 18045.
///
/// Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-attack-potential-resistance>
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStorageSecurityLevel {
    #[serde(rename = "iso_18045_high")]
    High,
    #[serde(rename = "iso_18045_moderate")]
    Moderate,
    #[serde(rename = "iso_18045_enhanced-basic")]
    EnhancedBasic,
    #[serde(rename = "iso_18045_basic")]
    Basic,
}

impl KeyStorageSecurityLevel {
    pub fn select_lowest(levels: &[Self]) -> Option<Self> {
        levels
            .iter()
            .min_by_key(|level| match level {
                Self::High => 4,
                Self::Moderate => 3,
                Self::EnhancedBasic => 2,
                Self::Basic => 1,
            })
            .copied()
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_issuer_metadata_deserializes_with_default_type_parameters() {
        let metadata: CredentialIssuerMetadata = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "nonce_endpoint": "https://issuer.example.com/nonce",
            "batch_credential_issuance": { "batch_size": 5 },
            "preferred_client_status_period": 2592000,
            "credential_configurations_supported": {
                "UniversityDegree": {
                    "format": "dc+sd-jwt",
                    "vct": "https://issuer.example.com/UniversityDegree",
                    "scope": "UniversityDegree",
                    "credential_signing_alg_values_supported": ["ES256", -7],
                    "proof_types_supported": {
                        "jwt": {
                            "proof_signing_alg_values_supported": ["ES256"],
                            "key_attestations_required": {
                                "key_storage": ["iso_18045_moderate"],
                                "preferred_key_storage_status_period": 3600
                            }
                        }
                    },
                    "credential_metadata": {
                        "display": [{ "name": "University Degree", "locale": "en-US" }],
                        "claims": [{ "path": ["degree"], "mandatory": true, "value_type": "STRING" }]
                    }
                }
            }
        }))
        .unwrap();

        assert_eq!(
            Some(BatchCredentialIssuance { batch_size: 5 }),
            metadata.batch_credential_issuance
        );
        assert_eq!(Some(2592000), metadata.preferred_client_status_period);

        let config = &metadata.credential_configurations_supported["UniversityDegree"];
        assert_eq!("dc+sd-jwt", config.format);
        assert_eq!(
            Some(vec![
                SigningAlgValue::String("ES256".to_string()),
                SigningAlgValue::Integer(-7),
            ]),
            config.credential_signing_alg_values_supported
        );
        assert_eq!(
            Some(&KeyAttestationsRequired {
                key_storage: vec![KeyStorageSecurityLevel::Moderate],
                user_authentication: vec![],
                preferred_key_storage_status_period: Some(3600),
            }),
            config.proof_types_supported.as_ref().unwrap()["jwt"]
                .key_attestations_required
                .as_ref()
        );

        let metadata = config.credential_metadata.as_ref().unwrap();
        assert_eq!(
            "University Degree",
            metadata.display.as_ref().unwrap()[0].name
        );

        // unrecognized claim members are retained
        let claim = &metadata.claims.as_ref().unwrap()[0];
        assert_eq!(
            serde_json::to_value(&claim.path).unwrap(),
            serde_json::json!(["degree"])
        );
        assert_eq!(
            Some(&serde_json::json!("STRING")),
            claim.additional_values.get("value_type")
        );
    }

    #[test]
    fn test_issuer_metadata_round_trips_array_claim_paths() {
        let json = serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "Degree": {
                    "format": "dc+sd-jwt",
                    "vct": "https://issuer.example.com/Degree",
                    "credential_metadata": {
                        "claims": [
                            { "path": ["degrees", null, "type"], "mandatory": true },
                            { "path": ["degrees", 0, "university"], "mandatory": true }
                        ]
                    }
                }
            }
        });

        let metadata: CredentialIssuerMetadata = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(metadata).unwrap(), json);
    }

    #[test]
    fn test_issuer_metadata_round_trips_etsi_extensions() {
        let json = serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "UniversityDegree": {
                    "format": "dc+sd-jwt",
                    "disclosure_policy": {
                        "id": "policy-1",
                        "policy": "none"
                    }
                }
            },
            "issuer_info": [{
                "format": "registration_cert",
                "data": "eyJhbGciOiJFUzI1NiJ9",
                "credential_ids": ["UniversityDegree"]
            }]
        });

        let metadata: CredentialIssuerMetadata = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(1, metadata.issuer_info.len());
        assert_eq!(
            IssuerInfoAttestationFormat::RegistrationCert,
            metadata.issuer_info[0].format
        );
        assert_eq!(
            "policy-1",
            metadata.credential_configurations_supported["UniversityDegree"]
                .disclosure_policy
                .as_ref()
                .unwrap()
                .id
        );

        assert_eq!(json, serde_json::to_value(&metadata).unwrap());
    }

    #[test]
    fn test_issuer_metadata_omits_absent_etsi_extensions() {
        let metadata: CredentialIssuerMetadata = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": { "x": { "format": "mso_mdoc" } }
        }))
        .unwrap();

        assert!(metadata.issuer_info.is_empty());
        let serialized = serde_json::to_value(&metadata).unwrap();
        assert!(serialized.get("issuer_info").is_none());
        assert!(
            serialized["credential_configurations_supported"]["x"]
                .get("disclosure_policy")
                .is_none()
        );
    }

    #[test]
    fn test_key_storage_security_level_serde_names() {
        for (name, level) in [
            ("iso_18045_high", KeyStorageSecurityLevel::High),
            ("iso_18045_moderate", KeyStorageSecurityLevel::Moderate),
            (
                "iso_18045_enhanced-basic",
                KeyStorageSecurityLevel::EnhancedBasic,
            ),
            ("iso_18045_basic", KeyStorageSecurityLevel::Basic),
        ] {
            assert_eq!(
                serde_json::json!(name),
                serde_json::to_value(level).unwrap()
            );
            assert_eq!(
                level,
                serde_json::from_value::<KeyStorageSecurityLevel>(serde_json::json!(name)).unwrap()
            );
        }
    }

    #[test]
    fn test_select_lowest_key_storage_security_level() {
        assert_eq!(
            Some(KeyStorageSecurityLevel::EnhancedBasic),
            KeyStorageSecurityLevel::select_lowest(&[
                KeyStorageSecurityLevel::High,
                KeyStorageSecurityLevel::EnhancedBasic,
                KeyStorageSecurityLevel::Moderate,
            ])
        );
        assert_eq!(None, KeyStorageSecurityLevel::select_lowest(&[]));
    }

    #[test]
    fn test_encryption_metadata_skips_unsupported_algorithms() {
        let encryption: CredentialResponseEncryption = serde_json::from_value(serde_json::json!({
            "alg_values_supported": ["ECDH-ES", "SOMETHING-NEW"],
            "enc_values_supported": ["A256GCM", "SOMETHING-NEW"],
            "encryption_required": true
        }))
        .unwrap();

        assert_eq!(1, encryption.alg_values_supported.len());
        assert_eq!(1, encryption.enc_values_supported.len());
        assert!(encryption.zip_values_supported.is_empty());
    }
}
