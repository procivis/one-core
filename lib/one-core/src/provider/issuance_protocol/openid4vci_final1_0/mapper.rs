use std::collections::HashSet;

use indexmap::IndexMap;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_dto_mapper::convert_inner_of_inner;
use secrecy::ExposeSecret;
use time::OffsetDateTime;

use super::model::{
    CredentialIssuerParams, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesRequestDTO, CredentialSchemaCodeTypeEnum,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLogoPropertiesRequestDTO,
    HolderInteractionData, OpenID4VCICredentialConfigurationData,
    OpenID4VCICredentialMetadataResponseDTO, OpenID4VCIIssuerInteractionDataDTO,
    OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO, OpenID4VCITokenResponseDTO,
};
use crate::config::core_config::{IdentifierType, Params};
use crate::config::{ConfigError, ConfigParsingError};
use crate::model::credential::Credential;
use crate::model::credential_schema::{
    BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema, KeyStorageSecurity,
    LayoutProperties, LogoProperties,
};
use crate::provider::issuance_protocol::error::{IssuanceProtocolError, OpenID4VCIError};
use crate::provider::issuance_protocol::model::{
    KeyStorageSecurityLevel, OpenID4VCIKeyAttestationsRequired, OpenID4VCIProofTypeSupported,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

pub(crate) fn get_credential_offer_url(
    protocol_base_url: String,
    credential: &Credential,
) -> Result<String, IssuanceProtocolError> {
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "Missing credential schema".to_owned(),
        ))?;
    Ok(format!(
        "{protocol_base_url}/{}/offer/{}",
        credential_schema.id, credential.id
    ))
}

impl TryFrom<&OpenID4VCITokenResponseDTO> for OpenID4VCIIssuerInteractionDataDTO {
    type Error = OpenID4VCIError;
    fn try_from(value: &OpenID4VCITokenResponseDTO) -> Result<Self, Self::Error> {
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
            notification_id: None,
            transaction_code: None,
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

pub(super) fn credentials_supported_mdoc(
    schema: CredentialSchema,
    credential_metadata: OpenID4VCICredentialMetadataResponseDTO,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
) -> Result<OpenID4VCICredentialConfigurationData, IssuanceProtocolError> {
    let credential_configuration = OpenID4VCICredentialConfigurationData {
        format: "mso_mdoc".to_string(),
        doctype: Some(schema.schema_id.clone()),
        credential_metadata: Some(credential_metadata),
        cryptographic_binding_methods_supported: Some(vec!["cose_key".to_string()]),
        proof_types_supported,
        scope: Some(schema.schema_id),
        ..Default::default()
    };

    Ok(credential_configuration)
}

pub(crate) fn map_proof_types_supported<R: From<[(String, OpenID4VCIProofTypeSupported); 1]>>(
    supported_jose_alg_ids: Vec<String>,
    key_storage_security_level: Option<KeyStorageSecurityLevel>,
) -> R {
    let key_attestations_required =
        key_storage_security_level.map(|level| OpenID4VCIKeyAttestationsRequired {
            key_storage: vec![level],
            user_authentication: vec![],
        });

    R::from([(
        "jwt".to_string(),
        OpenID4VCIProofTypeSupported {
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
    config_params: &Option<Params>,
) -> Result<CredentialIssuerParams, ConfigError> {
    config_params
        .as_ref()
        .and_then(|p| p.merge())
        .map(serde_json::from_value)
        .ok_or(ConfigError::Parsing(
            ConfigParsingError::GeneralParsingError("Credential issuer params missing".to_string()),
        ))?
        .map_err(|e| ConfigError::Parsing(ConfigParsingError::GeneralParsingError(e.to_string())))
}

impl From<OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO> for Option<LayoutProperties> {
    fn from(value: OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO) -> Self {
        let background = match (value.background_image, value.background_color) {
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

        let logo = match (value.logo, value.text_color) {
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

        let additional = value.procivis_design.map(
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
}

pub(crate) fn interaction_data_to_accepted_key_storage_security(
    data: &HolderInteractionData,
) -> Option<Vec<KeyStorageSecurityLevel>> {
    data.proof_types_supported.as_ref().and_then(|proof_types| {
        proof_types.get("jwt").and_then(|proof_type| {
            proof_type
                .key_attestations_required
                .as_ref()
                .map(|kar| kar.key_storage.clone())
                .and_then(|levels| (!levels.is_empty()).then_some(levels))
        })
    })
}

pub(super) fn credential_config_to_holder_signing_algs_and_key_storage_security(
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    credential_config: &OpenID4VCICredentialConfigurationData,
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
