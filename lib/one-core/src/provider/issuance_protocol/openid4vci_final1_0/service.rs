use std::str::FromStr;

use indexmap::IndexMap;
use one_crypto::utilities;
use secrecy::SecretString;
use shared_types::CredentialSchemaId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::mapper::{credentials_supported_mdoc, map_cryptographic_binding_methods_supported};
use super::model::{
    ExtendedSubjectDTO, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIGrants,
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedLogoDTO, OpenID4VCIIssuerMetadataDisplayResponseDTO,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCIPreAuthorizedCodeGrant,
    OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO, Timestamp,
};
use super::validator::throw_if_credential_state_not_eq;
use crate::config::core_config::CoreConfig;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::IdentifierType;
use crate::model::interaction::{Interaction, InteractionId};
use crate::provider::credential_formatter::sdjwtvc_formatter::vct_for_schema;
use crate::provider::issuance_protocol::error::{OpenID4VCIError, OpenIDIssuanceError};
use crate::provider::issuance_protocol::model::OpenID4VCIProofTypeSupported;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialConfigurationData, OpenID4VCICredentialMetadataClaimResponseDTO,
    OpenID4VCICredentialMetadataResponseDTO, OpenID4VCIFinal1CredentialOfferDTO,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::validator::{
    throw_if_interaction_created_date, throw_if_interaction_pre_authorized_code_used,
    throw_if_token_request_invalid, validate_refresh_token,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_issuer_metadata_response(
    protocol_base_url: &str,
    protocol_id: &str,
    oidc_format: &str,
    schema: &CredentialSchema,
    config: &CoreConfig,
    supported_did_methods: &[String],
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    credential_signing_alg_values_supported: Vec<String>,
    core_base_url: Option<&String>,
) -> Result<OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCIError> {
    let credential_configurations_supported: IndexMap<
        String,
        OpenID4VCICredentialConfigurationData,
    > = credential_configurations_supported(
        oidc_format,
        schema,
        config,
        supported_did_methods,
        proof_types_supported,
        credential_signing_alg_values_supported,
        core_base_url,
    )?;

    let schema_base_url = get_credential_schema_base_url(&schema.id, protocol_base_url);

    let base_url = core_base_url.ok_or(OpenID4VCIError::RuntimeError(
        "Can not build authorization server metadata, missing base_url".to_owned(),
    ))?;

    let authorization_server_url = {
        format!(
            "{base_url}/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{}",
            schema.id
        )
    };

    Ok(OpenID4VCIIssuerMetadataResponseDTO {
        credential_issuer: schema_base_url.to_owned(),
        authorization_servers: Some(vec![authorization_server_url]),
        credential_endpoint: format!("{schema_base_url}/credential"),
        nonce_endpoint: Some(format!("{protocol_base_url}/{protocol_id}/nonce")),
        notification_endpoint: Some(format!("{schema_base_url}/notification")),
        credential_configurations_supported,
        display: Some(vec![OpenID4VCIIssuerMetadataDisplayResponseDTO {
            name: schema
                .organisation
                .as_ref()
                .ok_or(OpenID4VCIError::RuntimeError(
                    "missing organisation".to_string(),
                ))?
                .name
                .clone(),
            locale: "en".to_string(),
        }]),
    })
}

fn credential_configurations_supported(
    oidc_format: &str,
    credential_schema: &CredentialSchema,
    config: &CoreConfig,
    supported_did_methods: &[String],
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    credential_signing_alg_values_supported: Vec<String>,
    core_base_url: Option<&String>,
) -> Result<IndexMap<String, OpenID4VCICredentialConfigurationData>, OpenID4VCIError> {
    let schema_id = credential_schema.schema_id.to_owned();
    let cryptographic_binding_methods_supported =
        map_cryptographic_binding_methods_supported(supported_did_methods);

    let credential_metadata_claims: Vec<OpenID4VCICredentialMetadataClaimResponseDTO> = {
        if let Some(claims) = credential_schema.claim_schemas.as_ref() {
            claims
                .iter()
                .filter_map(|claim| {
                    if claim.schema.data_type == "OBJECT" {
                        return None;
                    }

                    if claim.schema.metadata {
                        return None;
                    }

                    let path = claim
                        .schema
                        .key
                        .split('/')
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>();

                    let name = path.last().unwrap_or(&claim.schema.key).to_owned();

                    Some(OpenID4VCICredentialMetadataClaimResponseDTO {
                        path,
                        mandatory: Some(claim.required),
                        additional_values: None,
                        display: Some(vec![OpenID4VCIIssuerMetadataDisplayResponseDTO {
                            name,
                            locale: "en".to_string(),
                        }]),
                    })
                })
                .collect()
        } else {
            vec![]
        }
    };

    let display_dto = create_display_dto_from_schema(credential_schema);

    let credential_metadata = OpenID4VCICredentialMetadataResponseDTO {
        display: Some(vec![display_dto]),
        claims: Some(credential_metadata_claims),
    };

    Ok(IndexMap::from([(
        schema_id,
        match oidc_format {
            "ldp_vc" => jsonld_configuration(
                oidc_format,
                credential_metadata,
                credential_schema,
                cryptographic_binding_methods_supported,
                proof_types_supported,
            ),
            "jwt_vc_json" => jwt_configuration(
                oidc_format,
                credential_metadata,
                credential_schema,
                cryptographic_binding_methods_supported,
                proof_types_supported,
                credential_signing_alg_values_supported,
            ),
            "vc+sd-jwt" | "dc+sd-jwt" => sdjwt_configuration(
                oidc_format,
                credential_metadata,
                credential_schema,
                Some(
                    vct_for_schema(core_base_url, credential_schema)
                        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?,
                ),
                cryptographic_binding_methods_supported,
                proof_types_supported,
                credential_signing_alg_values_supported,
            ),
            "mso_mdoc" => credentials_supported_mdoc(
                credential_schema.clone(),
                credential_metadata,
                config,
                cryptographic_binding_methods_supported,
                proof_types_supported,
            )
            .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?,
            _ => jwt_configuration(
                oidc_format,
                credential_metadata,
                credential_schema,
                cryptographic_binding_methods_supported,
                proof_types_supported,
                credential_signing_alg_values_supported,
            ),
        },
    )]))
}

pub(crate) fn create_display_dto_from_schema(
    credential_schema: &CredentialSchema,
) -> OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
    let mut display = OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
        name: credential_schema.name.clone(),
        locale: Some("en".to_string()),
        logo: None,
        background_color: None,
        text_color: None,
    };

    if let Some(layout_properties) = &credential_schema.layout_properties {
        // Extract background color
        if let Some(background) = &layout_properties.background {
            if let Some(color) = &background.color {
                display.background_color = Some(color.clone());
            }
        }

        // Extract logo and text color
        if let Some(logo_props) = &layout_properties.logo {
            // Use font_color as text_color
            if let Some(font_color) = &logo_props.font_color {
                display.text_color = Some(font_color.clone());
            }

            // Create logo DTO if image is available
            if let Some(image_url) = &logo_props.image {
                display.logo = Some(OpenID4VCIIssuerMetadataCredentialSupportedLogoDTO {
                    url: image_url.clone(),
                    alt_text: Some(format!("{} logo", credential_schema.name)),
                });
            }
        }
    }

    display
}

fn jsonld_configuration(
    oidc_format: &str,
    credential_metadata: OpenID4VCICredentialMetadataResponseDTO,
    credential_schema: &CredentialSchema,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
) -> OpenID4VCICredentialConfigurationData {
    OpenID4VCICredentialConfigurationData {
        context: None, //TODO! Fill for json_ld
        format: oidc_format.into(),
        credential_metadata: Some(credential_metadata),
        procivis_schema: Some(credential_schema.imported_source_url.clone()),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        proof_types_supported,
        ..Default::default()
    }
}

fn jwt_configuration(
    oidc_format: &str,
    credential_metadata: OpenID4VCICredentialMetadataResponseDTO,
    credential_schema: &CredentialSchema,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    credential_signing_alg_values_supported: Vec<String>,
) -> OpenID4VCICredentialConfigurationData {
    OpenID4VCICredentialConfigurationData {
        format: oidc_format.into(),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        procivis_schema: Some(credential_schema.imported_source_url.clone()),
        credential_metadata: Some(credential_metadata),
        proof_types_supported,
        credential_signing_alg_values_supported: Some(credential_signing_alg_values_supported),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn sdjwt_configuration(
    oidc_format: &str,
    credential_metadata: OpenID4VCICredentialMetadataResponseDTO,
    credential_schema: &CredentialSchema,
    vct: Option<String>,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    credential_signing_alg_values_supported: Vec<String>,
) -> OpenID4VCICredentialConfigurationData {
    OpenID4VCICredentialConfigurationData {
        format: oidc_format.into(),
        credential_metadata: Some(credential_metadata),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        procivis_schema: Some(credential_schema.imported_source_url.clone()),
        vct: vct.clone(),
        scope: vct,
        proof_types_supported,
        credential_signing_alg_values_supported: Some(credential_signing_alg_values_supported),
        ..Default::default()
    }
}

pub(crate) fn create_service_discovery_response(
    schema_base_url: &str,
) -> Result<OpenID4VCIDiscoveryResponseDTO, OpenID4VCIError> {
    Ok(OpenID4VCIDiscoveryResponseDTO {
        issuer: schema_base_url.to_owned(),
        authorization_endpoint: Some(format!("{schema_base_url}/authorize")),
        token_endpoint: format!("{schema_base_url}/token"),
        jwks_uri: Some(format!("{schema_base_url}/jwks")),
        response_types_supported: vec!["token".to_string()],
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            "refresh_token".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec![],
    })
}

pub(crate) fn get_protocol_base_url(base_url: &str) -> String {
    format!("{base_url}/ssi/openid4vci/final-1.0")
}

pub(crate) fn get_credential_schema_base_url(
    credential_schema_id: &CredentialSchemaId,
    protocol_base_url: &str,
) -> String {
    format!("{protocol_base_url}/{credential_schema_id}")
}

pub(crate) fn create_credential_offer(
    protocol_base_url: &str,
    pre_authorized_code: &str,
    credential: &Credential,
    credential_schema_uuid: &CredentialSchemaId,
    credential_schema_id: &str,
    credential_subject: ExtendedSubjectDTO,
) -> Result<OpenID4VCIFinal1CredentialOfferDTO, OpenIDIssuanceError> {
    let issuer_identifier =
        credential
            .issuer_identifier
            .as_ref()
            .ok_or(OpenID4VCIError::RuntimeError(
                "Missing issuer_identifier".to_owned(),
            ))?;
    let (issuer_did, issuer_certificate) = match issuer_identifier.r#type {
        IdentifierType::Key => (None, None),
        IdentifierType::Did => (
            issuer_identifier.did.as_ref().map(|did| did.did.clone()),
            None,
        ),
        IdentifierType::Certificate => (
            None,
            credential
                .issuer_certificate
                .as_ref()
                .map(|issuer_certificate| issuer_certificate.chain.clone()),
        ),
    };
    Ok(OpenID4VCIFinal1CredentialOfferDTO {
        credential_issuer: format!("{protocol_base_url}/{credential_schema_uuid}"),
        issuer_did,
        issuer_certificate,
        credential_configuration_ids: vec![credential_schema_id.to_string()],
        grants: OpenID4VCIGrants::PreAuthorizedCode(OpenID4VCIPreAuthorizedCodeGrant {
            pre_authorized_code: pre_authorized_code.to_owned(),
            tx_code: None,
            authorization_server: None,
        }),
        credential_subject: Some(credential_subject),
    })
}

pub(crate) fn oidc_issuer_create_token(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    credentials: &[Credential],
    interaction: &Interaction,
    request: &OpenID4VCITokenRequestDTO,
    pre_authorization_expires_in: Duration,
    access_token_expires_in: Duration,
    refresh_token_expires_in: Duration,
) -> Result<OpenID4VCITokenResponseDTO, OpenIDIssuanceError> {
    throw_if_token_request_invalid(request)?;

    let generate_new_token = || {
        SecretString::from(format!(
            "{}.{}",
            interaction.id,
            utilities::generate_alphanumeric(32)
        ))
    };

    let now = OffsetDateTime::now_utc();
    Ok(match request {
        OpenID4VCITokenRequestDTO::PreAuthorizedCode { .. } => {
            throw_if_interaction_created_date(pre_authorization_expires_in, interaction)?;
            throw_if_interaction_pre_authorized_code_used(interaction_data)?;

            credentials.iter().try_for_each(|credential| {
                throw_if_credential_state_not_eq(credential, CredentialStateEnum::Pending)
            })?;

            OpenID4VCITokenResponseDTO {
                access_token: generate_new_token(),
                token_type: "bearer".to_string(),
                expires_in: Timestamp((now + access_token_expires_in).unix_timestamp()),
                refresh_token: None,
                refresh_token_expires_in: None,
            }
        }

        OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } => {
            validate_refresh_token(interaction_data, refresh_token)?;
            // we update both the access token and the refresh token
            OpenID4VCITokenResponseDTO {
                access_token: generate_new_token(),
                token_type: "bearer".to_string(),
                expires_in: Timestamp((now + access_token_expires_in).unix_timestamp()),
                refresh_token: Some(generate_new_token()),
                refresh_token_expires_in: Some(Timestamp(
                    (now + refresh_token_expires_in).unix_timestamp(),
                )),
            }
        }
        OpenID4VCITokenRequestDTO::AuthorizationCode { .. } => {
            return Err(OpenIDIssuanceError::OpenID4VCI(
                OpenID4VCIError::InvalidGrant,
            ));
        }
    })
}

pub(crate) fn parse_refresh_token(token: &str) -> Result<InteractionId, OpenID4VCIError> {
    parse_access_token(token)
}

pub(crate) fn parse_access_token(access_token: &str) -> Result<InteractionId, OpenID4VCIError> {
    let mut splitted_token = access_token.split('.');
    if splitted_token.to_owned().count() != 2 {
        return Err(OpenID4VCIError::InvalidToken);
    }

    Uuid::from_str(splitted_token.next().ok_or(OpenID4VCIError::InvalidToken)?)
        .map_err(|_| OpenID4VCIError::RuntimeError("Could not parse UUID".to_owned()))
}
