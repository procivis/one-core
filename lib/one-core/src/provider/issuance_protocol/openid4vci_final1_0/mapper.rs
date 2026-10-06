use std::collections::HashSet;

use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_dto_mapper::convert_inner_of_inner;
use secrecy::ExposeSecret;
use serde::de::Error;
use standardized_types::oauth2::token::TokenResponse;
use standardized_types::openid4vci::{
    CredentialConfiguration, CredentialDisplay, KeyAttestationsRequired, KeyStorageSecurityLevel,
    ProofTypeSupported,
};
use time::OffsetDateTime;

use super::IssuerMetadataRepresentation;
use super::model::{
    CredentialIssuerParams, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesRequestDTO, CredentialSchemaCodeTypeEnum,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLogoPropertiesRequestDTO,
    HolderCredentialConfiguration, OpenID4VCIIssuerInteractionDataDTO,
    OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign, PROCIVIS_DESIGN_KEY,
};
use crate::config::ConfigValidationError;
use crate::config::core_config::{IdentifierType, Params};
use crate::model::credential::Credential;
use crate::model::credential_schema::{
    BackgroundProperties, CodeProperties, CodeTypeEnum, KeyStorageSecurity, LayoutProperties,
    LogoProperties, WalletAttestation,
};
use crate::provider::issuance_protocol::error::{IssuanceProtocolError, OpenID4VCIError};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

pub(crate) fn get_credential_offer_url(
    protocol_base_url: String,
    credential: &Credential,
) -> Result<String, IssuanceProtocolError> {
    Ok(format!(
        "{protocol_base_url}/{}/offer/{}",
        credential.common().schema.id(),
        credential.common().id
    ))
}

impl TryFrom<&TokenResponse> for OpenID4VCIIssuerInteractionDataDTO {
    type Error = OpenID4VCIError;
    fn try_from(value: &TokenResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            pre_authorized_code_used: true,
            access_token_hash: SHA256
                .hash(value.access_token.expose_secret().as_bytes())
                .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?,
            access_token_expires_at: Some(
                OffsetDateTime::from_unix_timestamp(value.expires_in.0)
                    .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?,
            ),
            refresh_token_hash: value
                .refresh_token
                .as_ref()
                .map(|refresh_token| {
                    SHA256
                        .hash(refresh_token.expose_secret().as_bytes())
                        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))
                })
                .transpose()?,
            refresh_token_expires_at: value
                .refresh_token_expires_in
                .as_ref()
                .map(|refresh_token_expires_in| {
                    OffsetDateTime::from_unix_timestamp(refresh_token_expires_in.0)
                        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))
                })
                .transpose()?,
            notification_ids: Default::default(),
            transaction_code: None,
            formats: None,
            dpop_jkt: None,
        })
    }
}

impl From<CredentialSchemaBackgroundPropertiesRequestDTO> for BackgroundProperties {
    fn from(value: CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: value.color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaLogoPropertiesRequestDTO> for LogoProperties {
    fn from(value: CredentialSchemaLogoPropertiesRequestDTO) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaCodePropertiesRequestDTO> for CodeProperties {
    fn from(value: CredentialSchemaCodePropertiesRequestDTO) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<CredentialSchemaCodeTypeEnum> for CodeTypeEnum {
    fn from(value: CredentialSchemaCodeTypeEnum) -> Self {
        match value {
            CredentialSchemaCodeTypeEnum::Barcode => Self::Barcode,
            CredentialSchemaCodeTypeEnum::Mrz => Self::Mrz,
            CredentialSchemaCodeTypeEnum::QrCode => Self::QrCode,
        }
    }
}

impl From<LayoutProperties> for CredentialSchemaLayoutPropertiesRequestDTO {
    fn from(value: LayoutProperties) -> Self {
        Self {
            background: value.background.map(|value| {
                CredentialSchemaBackgroundPropertiesRequestDTO {
                    color: value.color,
                    image: value.image,
                }
            }),
            logo: value
                .logo
                .map(|v| CredentialSchemaLogoPropertiesRequestDTO {
                    font_color: v.font_color,
                    background_color: v.background_color,
                    image: v.image,
                }),
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code: value
                .code
                .map(|v| CredentialSchemaCodePropertiesRequestDTO {
                    attribute: v.attribute,
                    r#type: match v.r#type {
                        CodeTypeEnum::Barcode => CredentialSchemaCodeTypeEnum::Barcode,
                        CodeTypeEnum::Mrz => CredentialSchemaCodeTypeEnum::Mrz,
                        CodeTypeEnum::QrCode => CredentialSchemaCodeTypeEnum::QrCode,
                    },
                }),
        }
    }
}

pub(crate) fn map_proof_types_supported<R: From<[(String, ProofTypeSupported); 1]>>(
    supported_jose_alg_ids: Vec<String>,
    wallet_attestation: &WalletAttestation,
) -> R {
    let key_attestations_required =
        wallet_attestation
            .key_storage_security_level
            .map(|level| KeyAttestationsRequired {
                key_storage: vec![level.into()],
                user_authentication: vec![],
                preferred_key_storage_status_period: wallet_attestation
                    .preferred_key_storage_attestation_lifetime
                    .map(|lifetime| lifetime.whole_seconds() as u64),
            });

    R::from([(
        "jwt".to_string(),
        ProofTypeSupported {
            proof_signing_alg_values_supported: supported_jose_alg_ids,
            key_attestations_required,
        },
    )])
}

pub(crate) fn map_cryptographic_binding_methods_supported(
    supported_did_methods: &[String],
    holder_identifier_types: &[IdentifierType],
) -> Vec<String> {
    let mut result = vec![];
    if holder_identifier_types.contains(&IdentifierType::Key) {
        result.push("jwk".to_string());
    }
    if holder_identifier_types.contains(&IdentifierType::Did) {
        result.extend(
            supported_did_methods
                .iter()
                .map(|did_method| format!("did:{did_method}")),
        );
    }
    result
}

pub(crate) fn parse_credential_issuer_params(
    issuer: &str,
    config_params: &Option<Params>,
) -> Result<CredentialIssuerParams, ConfigValidationError> {
    config_params
        .as_ref()
        .and_then(|p| p.merge())
        .map(serde_json::from_value)
        .ok_or(ConfigValidationError::FieldsDeserialization {
            key: issuer.to_string(),
            source: serde_json::Error::custom("Params missing"),
        })?
        .map_err(|source| ConfigValidationError::FieldsDeserialization {
            key: issuer.to_string(),
            source,
        })
}

pub(crate) fn convert_metadata_to_layout_properties(
    mut metadata: CredentialDisplay,
) -> Option<LayoutProperties> {
    let background = match (metadata.background_image, metadata.background_color) {
        (None, None) => None,
        (None, Some(background_color)) => Some(BackgroundProperties {
            color: Some(background_color),
            ..Default::default()
        }),
        (Some(background_image), _) => Some(BackgroundProperties {
            image: Some(background_image.uri),
            ..Default::default()
        }),
    };

    let logo = match (metadata.logo, metadata.text_color) {
        (None, None) => None,
        (None, Some(text_color)) => Some(LogoProperties {
            font_color: Some(text_color),
            ..Default::default()
        }),
        (Some(logo), None) => Some(LogoProperties {
            image: Some(logo.uri),
            ..Default::default()
        }),
        (Some(logo), Some(text_color)) => Some(LogoProperties {
            image: Some(logo.uri),
            font_color: Some(text_color),
            ..Default::default()
        }),
    };

    let procivis_design: Option<OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign> =
        metadata
            .additional_values
            .swap_remove(PROCIVIS_DESIGN_KEY)
            .and_then(|v| serde_json::from_value(v).ok());

    let additional = procivis_design.map(
        |OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign {
             primary_attribute,
             secondary_attribute,
             picture_attribute,
             code_attribute,
             code_type,
         }| {
            let code = match (code_attribute, code_type) {
                (Some(attribute), Some(r#type)) => Some(CodeProperties { attribute, r#type }),
                _ => None,
            };

            LayoutProperties {
                primary_attribute,
                secondary_attribute,
                picture_attribute,
                code,
                ..Default::default()
            }
        },
    );

    match (&background, &logo, &additional) {
        (None, None, None) => None,
        _ => Some(LayoutProperties {
            background,
            logo,
            ..additional.unwrap_or_default()
        }),
    }
}

pub(crate) fn configuration_to_accepted_key_storage_security(
    configuration: &HolderCredentialConfiguration,
) -> Option<Vec<KeyStorageSecurityLevel>> {
    configuration
        .proof_types_supported
        .as_ref()
        .and_then(|proof_types| {
            proof_types.get("jwt").and_then(|proof_type| {
                proof_type
                    .key_attestations_required
                    .as_ref()
                    .map(|kar| kar.key_storage.clone())
                    // An empty `key_attestations_required` means that a key attestation is needed
                    // without additional constraints, so each level is accepted.
                    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.11.2.5.2.2.1
                    .map(|levels| {
                        if levels.is_empty() {
                            vec![
                                KeyStorageSecurityLevel::High,
                                KeyStorageSecurityLevel::Moderate,
                                KeyStorageSecurityLevel::EnhancedBasic,
                                KeyStorageSecurityLevel::Basic,
                            ]
                        } else {
                            levels
                        }
                    })
            })
        })
}

// None means no restriction
pub(super) fn intersect_supported<T: PartialEq>(
    current: Option<Vec<T>>,
    other: Option<Vec<T>>,
) -> Option<Vec<T>> {
    match (current, other) {
        (None, other) => other,
        (current, None) => current,
        (Some(current), Some(other)) => Some(
            current
                .into_iter()
                .filter(|value| other.contains(value))
                .collect(),
        ),
    }
}

pub(super) fn credential_config_to_holder_signing_algs_and_key_storage_security(
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    credential_config: &CredentialConfiguration,
) -> (Option<Vec<String>>, Option<Vec<KeyStorageSecurity>>) {
    let Some(proof_types_supported) = &credential_config.proof_types_supported else {
        return (None, None);
    };
    let Some(proof_type) = proof_types_supported.get("jwt") else {
        return (None, None);
    };
    let algs = proof_type
        .proof_signing_alg_values_supported
        .iter()
        .filter_map(|alg| {
            key_algorithm_provider
                .key_algorithm_from_jose_alg(alg)
                .map(|(alg_type, _)| alg_type.to_string())
        })
        .collect::<HashSet<_>>();
    let algs = if algs.is_empty() {
        None
    } else {
        Some(algs.into_iter().collect())
    };

    let key_storage_security = proof_type
        .key_attestations_required
        .as_ref()
        .map(|key_attestations| key_attestations.key_storage.clone())
        .and_then(|levels| (!levels.is_empty()).then_some(levels));
    (algs, convert_inner_of_inner(key_storage_security))
}

impl From<IssuerMetadataRepresentation>
    for crate::provider::ecosystem::model::IssuerMetadataRepresentation
{
    fn from(value: IssuerMetadataRepresentation) -> Self {
        match value {
            IssuerMetadataRepresentation::Unsigned(credential_issuer_metadata) => {
                crate::provider::ecosystem::model::IssuerMetadataRepresentation::Unsigned(Box::new(
                    credential_issuer_metadata,
                ))
            }
            IssuerMetadataRepresentation::Signed(jwt) => {
                crate::provider::ecosystem::model::IssuerMetadataRepresentation::Signed(Box::new(
                    jwt,
                ))
            }
        }
    }
}
