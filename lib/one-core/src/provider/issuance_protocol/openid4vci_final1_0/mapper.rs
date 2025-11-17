use indexmap::IndexMap;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use secrecy::ExposeSecret;
use time::OffsetDateTime;

use super::model::{
    CredentialIssuerParams, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesRequestDTO, CredentialSchemaCodeTypeEnum,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLogoPropertiesRequestDTO,
    OpenID4VCICredentialConfigurationData, OpenID4VCICredentialMetadataResponseDTO,
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO, OpenID4VCITokenResponseDTO,
};
use crate::config::core_config::{CoreConfig, Params};
use crate::config::{ConfigError, ConfigParsingError};
use crate::mapper::oidc::map_to_openid4vp_format;
use crate::model::credential::Credential;
use crate::model::credential_schema::{
    BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema, LayoutProperties,
    LogoProperties,
};
use crate::model::wallet_unit_attestation::KeyStorageSecurityLevel;
use crate::provider::issuance_protocol::error::{IssuanceProtocolError, OpenID4VCIError};
use crate::provider::issuance_protocol::model::{
    OpenID4VCIProofTypeSupported, OpenIF4VCIKeyAttestationsRequired,
};

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
    config: &CoreConfig,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
) -> Result<OpenID4VCICredentialConfigurationData, IssuanceProtocolError> {
    let format_type = config
        .format
        .get_fields(&schema.format)
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
        .r#type;

    let credential_configuration = OpenID4VCICredentialConfigurationData {
        format: map_to_openid4vp_format(&format_type)
            .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?
            .to_string(),
        doctype: Some(schema.schema_id.clone()),
        credential_metadata: Some(credential_metadata),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
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
        key_storage_security_level.map(|level| OpenIF4VCIKeyAttestationsRequired {
            key_storage: vec![level],
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
) -> Vec<String> {
    let mut binding_methods: Vec<_> = supported_did_methods
        .iter()
        .map(|did_method| format!("did:{did_method}"))
        .collect();
    binding_methods.push("jwk".to_string());
    binding_methods
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
