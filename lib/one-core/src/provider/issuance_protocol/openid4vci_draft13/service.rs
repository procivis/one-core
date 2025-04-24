use std::str::FromStr;

use indexmap::IndexMap;
use one_crypto::utilities;
use secrecy::SecretString;
use shared_types::{CredentialSchemaId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::error::{OpenID4VCIError, OpenIDIssuanceError};
use super::mapper::{
    credentials_supported_mdoc, map_cryptographic_binding_methods_supported,
    prepare_nested_representation,
};
use super::model::{
    ExtendedSubjectDTO, OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialOfferDTO,
    OpenID4VCICredentialSubjectItem, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIGrant,
    OpenID4VCIGrants, OpenID4VCIIssuerInteractionDataDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataDisplayResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCIProofTypeSupported, OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO, Timestamp,
};
use super::validator::throw_if_credential_state_not_eq;
use crate::config::core_config::CoreConfig;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, WalletStorageTypeEnum};
use crate::model::interaction::{Interaction, InteractionId};
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCICredentialConfigurationData;
use crate::provider::issuance_protocol::openid4vci_draft13::validator::{
    throw_if_interaction_created_date, throw_if_interaction_pre_authorized_code_used,
    throw_if_token_request_invalid, validate_refresh_token,
};

pub(crate) fn create_issuer_metadata_response(
    base_url: &str,
    oidc_format: &str,
    schema: &CredentialSchema,
    config: &CoreConfig,
    supported_did_methods: &[String],
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    credential_signing_alg_values_supported: Vec<String>,
) -> Result<OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCIError> {
    let credential_configurations_supported = credential_configurations_supported(
        oidc_format,
        schema,
        config,
        supported_did_methods,
        proof_types_supported,
        credential_signing_alg_values_supported,
    )?;
    Ok(OpenID4VCIIssuerMetadataResponseDTO {
        credential_issuer: base_url.to_owned(),
        credential_endpoint: format!("{base_url}/credential"),
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
) -> Result<IndexMap<String, OpenID4VCICredentialConfigurationData>, OpenID4VCIError> {
    let wallet_storage_type = credential_schema.wallet_storage_type.to_owned();
    let schema_id = credential_schema.schema_id.to_owned();

    let claims = prepare_nested_representation(credential_schema, config)?;
    let cryptographic_binding_methods_supported =
        map_cryptographic_binding_methods_supported(supported_did_methods);

    Ok(IndexMap::from([(
        schema_id.clone(),
        match oidc_format {
            "ldp_vc" => jsonld_configuration(
                wallet_storage_type,
                oidc_format,
                claims,
                credential_schema,
                cryptographic_binding_methods_supported,
                proof_types_supported,
            ),
            "jwt_vc_json" => jwt_configuration(
                wallet_storage_type,
                oidc_format,
                claims,
                credential_schema,
                cryptographic_binding_methods_supported,
                proof_types_supported,
                credential_signing_alg_values_supported,
            ),
            "vc+sd-jwt" => sdjwt_configuration(
                wallet_storage_type,
                oidc_format,
                claims,
                credential_schema,
                (credential_schema.format == "SD_JWT_VC").then_some(schema_id),
                cryptographic_binding_methods_supported,
                proof_types_supported,
                credential_signing_alg_values_supported,
            ),
            "mso_mdoc" => credentials_supported_mdoc(
                credential_schema.clone(),
                config,
                cryptographic_binding_methods_supported,
                proof_types_supported,
            )
            .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?,
            _ => jwt_configuration(
                wallet_storage_type,
                oidc_format,
                claims,
                credential_schema,
                cryptographic_binding_methods_supported,
                proof_types_supported,
                credential_signing_alg_values_supported,
            ),
        },
    )]))
}

fn jsonld_configuration(
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    oidc_format: &str,
    claims: OpenID4VCICredentialSubjectItem,
    credential_schema: &CredentialSchema,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
) -> OpenID4VCICredentialConfigurationData {
    let schema_name = credential_schema.name.to_owned();
    OpenID4VCICredentialConfigurationData {
        context: None, //TODO! Fill for json_ld
        wallet_storage_type,
        format: oidc_format.into(),
        credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
            r#type: vec!["VerifiableCredential".to_string()],
            credential_subject: Some(claims),
        }),
        display: Some(vec![
            OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO { name: schema_name },
        ]),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        proof_types_supported,
        ..Default::default()
    }
}

fn jwt_configuration(
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    oidc_format: &str,
    claims: OpenID4VCICredentialSubjectItem,
    credential_schema: &CredentialSchema,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    credential_signing_alg_values_supported: Vec<String>,
) -> OpenID4VCICredentialConfigurationData {
    let schema_name = credential_schema.name.to_owned();
    OpenID4VCICredentialConfigurationData {
        wallet_storage_type,
        format: oidc_format.into(),
        credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
            r#type: vec!["VerifiableCredential".to_string()],
            credential_subject: Some(claims),
        }),
        display: Some(vec![
            OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO { name: schema_name },
        ]),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        proof_types_supported,
        credential_signing_alg_values_supported: Some(credential_signing_alg_values_supported),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn sdjwt_configuration(
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    oidc_format: &str,
    claims: OpenID4VCICredentialSubjectItem,
    credential_schema: &CredentialSchema,
    vct: Option<String>,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
    credential_signing_alg_values_supported: Vec<String>,
) -> OpenID4VCICredentialConfigurationData {
    let schema_name = credential_schema.name.to_owned();
    OpenID4VCICredentialConfigurationData {
        wallet_storage_type,
        format: oidc_format.into(),
        credential_definition: Some(OpenID4VCICredentialDefinitionRequestDTO {
            r#type: vec!["VerifiableCredential".to_string()],
            credential_subject: Some(claims),
        }),
        display: Some(vec![
            OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO { name: schema_name },
        ]),
        vct: vct.clone(),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        proof_types_supported,
        scope: vct,
        credential_signing_alg_values_supported: Some(credential_signing_alg_values_supported),
        ..Default::default()
    }
}

pub(crate) fn create_service_discovery_response(
    base_url: &str,
) -> Result<OpenID4VCIDiscoveryResponseDTO, OpenID4VCIError> {
    Ok(OpenID4VCIDiscoveryResponseDTO {
        issuer: base_url.to_owned(),
        authorization_endpoint: Some(format!("{base_url}/authorize")),
        token_endpoint: format!("{base_url}/token"),
        jwks_uri: Some(format!("{base_url}/jwks")),
        response_types_supported: vec!["token".to_string()],
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            "refresh_token".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec![],
    })
}

pub(crate) fn get_credential_schema_base_url(
    credential_schema_id: &CredentialSchemaId,
    base_url: &str,
) -> Result<String, OpenID4VCIError> {
    Ok(format!(
        "{base_url}/ssi/openid4vci/draft-13/{credential_schema_id}"
    ))
}

pub(crate) fn create_credential_offer(
    base_url: &str,
    pre_authorized_code: &str,
    issuer_did: DidValue,
    credential_schema_uuid: &CredentialSchemaId,
    credential_schema_id: &str,
    credential_subject: ExtendedSubjectDTO,
) -> Result<OpenID4VCICredentialOfferDTO, OpenIDIssuanceError> {
    Ok(OpenID4VCICredentialOfferDTO {
        credential_issuer: format!(
            "{}/ssi/openid4vci/draft-13/{}",
            base_url, credential_schema_uuid
        ),
        issuer_did: Some(issuer_did),
        credential_configuration_ids: vec![credential_schema_id.to_string()],
        grants: OpenID4VCIGrants {
            code: OpenID4VCIGrant {
                pre_authorized_code: pre_authorized_code.to_owned(),
                tx_code: None,
            },
        },
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
                c_nonce: Some(utilities::generate_nonce()),
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
                c_nonce: None,
            }
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
