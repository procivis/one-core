use std::collections::HashMap;
use std::ops::Sub;
use std::str::FromStr;
use std::sync::Arc;

use one_crypto::utilities;
use shared_types::{CredentialSchemaId, KeyId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::error::{OpenID4VCError, OpenID4VCIError};
use super::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, OpenID4VCICredentialDefinition,
    OpenID4VCICredentialOfferCredentialDTO, OpenID4VCICredentialOfferDTO,
    OpenID4VCICredentialSubject, OpenID4VCICredentialValueDetails, OpenID4VCIDiscoveryResponseDTO,
    OpenID4VCIGrant, OpenID4VCIGrants, OpenID4VCIInteractionDataDTO,
    OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCITokenRequestDTO, OpenID4VPClientMetadata, OpenID4VPClientMetadataJwkDTO,
    OpenID4VPDirectPostResponseDTO, OpenID4VPFormat, PresentationSubmissionMappingDTO,
    ValidatedProofClaimDTO,
};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, WalletStorageTypeEnum};
use crate::model::did::KeyRole;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::MobileSecurityObject;
use crate::provider::credential_formatter::model::{DetailCredential, ExtractPresentationCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::openid4vc::mapper::{
    extract_presentation_ctx_from_interaction_content, extracted_credential_to_model,
    parse_interaction_content, vec_last_position_from_token_path,
};
use crate::provider::exchange_protocol::openid4vc::model::{
    AcceptProofResult, OpenID4VPInteractionContent, OpenID4VPPresentationDefinition, RequestData,
};
use crate::provider::exchange_protocol::openid4vc::validator::{
    peek_presentation, throw_if_interaction_created_date,
    throw_if_interaction_pre_authorized_code_used, throw_if_latest_credential_state_not_eq,
    throw_if_latest_proof_state_not_eq, throw_if_token_request_invalid, validate_claims,
    validate_credential, validate_presentation, validate_refresh_token,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::lvvc::util::is_lvvc_credential;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::util::key_verification::KeyVerification;

pub fn create_issuer_metadata_response(
    base_url: &str,
    oidc_format: &str,
    schema_id: &str,
    schema_type: &str,
    schema_name: &str,
    wallet_storage_type: Option<WalletStorageTypeEnum>,
) -> Result<OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCIError> {
    let credentials_supported = credentials_supported(
        wallet_storage_type,
        oidc_format,
        schema_id,
        schema_type,
        schema_name,
    )?;
    Ok(OpenID4VCIIssuerMetadataResponseDTO {
        credential_issuer: base_url.to_owned(),
        credential_endpoint: format!("{base_url}/credential"),
        credentials_supported,
    })
}

fn credentials_supported(
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    oidc_format: &str,
    schema_id: &str,
    schema_type: &str,
    schema_name: &str,
) -> Result<Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO>, OpenID4VCIError> {
    Ok(vec![
        OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
            wallet_storage_type,
            format: oidc_format.into(),
            claims: None,
            order: None,
            credential_definition: Some(OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
                r#type: vec!["VerifiableCredential".to_string()],
                credential_schema: Some(OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO {
                    id: schema_id.into(),
                    r#type: schema_type.into(),
                }),
            }),
            doctype: None,
            display: Some(vec![
                OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
                    name: schema_name.into(),
                },
            ]),
        },
    ])
}

pub fn create_open_id_for_vp_client_metadata(
    key_id: KeyId,
    jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VPFormat>,
) -> OpenID4VPClientMetadata {
    OpenID4VPClientMetadata {
        jwks: vec![OpenID4VPClientMetadataJwkDTO { key_id, jwk }],
        vp_formats,
        client_id_scheme: "redirect_uri".to_string(),
        authorization_encrypted_response_alg: Some(AuthorizationEncryptedResponseAlgorithm::EcdhEs),
        authorization_encrypted_response_enc: Some(
            AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM,
        ),
    }
}

pub fn create_service_discovery_response(
    base_url: &str,
) -> Result<OpenID4VCIDiscoveryResponseDTO, OpenID4VCIError> {
    Ok(OpenID4VCIDiscoveryResponseDTO {
        issuer: base_url.to_owned(),
        authorization_endpoint: format!("{base_url}/authorize"),
        token_endpoint: format!("{base_url}/token"),
        jwks_uri: format!("{base_url}/jwks"),
        response_types_supported: vec!["token".to_string()],
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            "refresh_token".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec![],
    })
}

pub fn get_credential_schema_base_url(
    credential_schema_id: &CredentialSchemaId,
    base_url: &str,
) -> Result<String, OpenID4VCIError> {
    Ok(format!(
        "{base_url}/ssi/oidc-issuer/v1/{credential_schema_id}"
    ))
}

pub fn oidc_verifier_presentation_definition(
    proof: Proof,
    mut interaction_content: OpenID4VPInteractionContent,
) -> Result<OpenID4VPPresentationDefinition, OpenID4VCError> {
    throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

    let proof_schema = proof.schema.as_ref().ok_or(OpenID4VCError::MappingError(
        "Proof schema not found".to_string(),
    ))?;

    let proof_schema_inputs = match proof_schema.input_schemas.as_ref() {
        Some(input_schemas) if !input_schemas.is_empty() => input_schemas.to_vec(),
        _ => {
            return Err(OpenID4VCError::MappingError(
                "input_schemas are missing".to_string(),
            ))
        }
    };

    if proof_schema_inputs.len()
        != interaction_content
            .presentation_definition
            .input_descriptors
            .len()
    {
        return Err(OpenID4VCError::Other(
            "Proof schema inputs length doesn't match interaction data input descriptors length"
                .to_owned(),
        ));
    }

    let now = OffsetDateTime::now_utc();
    interaction_content
        .presentation_definition
        .input_descriptors
        .iter_mut()
        .zip(proof_schema_inputs)
        .for_each(|(input_descriptor, proof_schema_input)| {
            if let Some(validity_constraint) = proof_schema_input.validity_constraint {
                input_descriptor.constraints.validity_credential_nbf =
                    Some(now.sub(Duration::seconds(validity_constraint)));
            }
        });

    Ok(interaction_content.presentation_definition)
}

#[allow(clippy::too_many_arguments)]
pub async fn oidc_verifier_direct_post(
    request: RequestData,
    proof: Proof,
    interaction_data: &[u8],
    did_method_provider: &Arc<dyn DidMethodProvider>,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    map_oidc_to_external: FnMapOidcFormatToExternalDetailed,
) -> Result<(AcceptProofResult, OpenID4VPDirectPostResponseDTO), OpenID4VCError> {
    throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending).or(
        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested),
    )?;

    let proved_claims = process_proof_submission(
        request,
        &proof,
        interaction_data,
        did_method_provider,
        formatter_provider,
        key_algorithm_provider,
        revocation_method_provider,
        map_oidc_to_external,
    )
    .await?;
    let redirect_uri: Option<String> = proof.redirect_uri.to_owned();
    let result = accept_proof(proof, proved_claims).await?;
    Ok((result, OpenID4VPDirectPostResponseDTO { redirect_uri }))
}

// This one is used
pub type FnMapOidcFormatToExternal = fn(&str) -> Result<String, OpenID4VCError>;
pub type FnMapOidcFormatToExternalDetailed =
    fn(&str, Option<&str>) -> Result<String, OpenID4VCError>;
pub type FnMapExternalFormatToExternalDetailed = fn(&str, &str) -> Result<String, OpenID4VCError>;

#[allow(clippy::too_many_arguments)]
async fn process_proof_submission(
    submission: RequestData,
    proof: &Proof,
    interaction_data: &[u8],
    did_method_provider: &Arc<dyn DidMethodProvider>,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    map_oidc_format_to_external: FnMapOidcFormatToExternalDetailed,
) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
    let interaction_data = parse_interaction_content(interaction_data)?;

    let presentation_submission = &submission.presentation_submission;

    let definition_id = presentation_submission.definition_id.clone();
    let vp_token = submission.vp_token;
    let state = submission.state;

    if definition_id != state.to_string() {
        return Err(OpenID4VCIError::InvalidRequest.into());
    }

    let presentation_strings: Vec<String> = if vp_token.starts_with('[') {
        serde_json::from_str(&vp_token).map_err(|_| OpenID4VCIError::InvalidRequest)?
    } else {
        vec![vp_token]
    };

    // collect expected credentials
    let proof_schema = proof.schema.as_ref().ok_or(OpenID4VCError::MappingError(
        "missing proof schema".to_string(),
    ))?;

    let proof_schema_inputs = match proof_schema.input_schemas.as_ref() {
        Some(input_schemas) if !input_schemas.is_empty() => input_schemas.to_vec(),
        _ => {
            return Err(OpenID4VCError::Other(
                "Missing proof input schema".to_owned(),
            ));
        }
    };

    let extracted_lvvcs = extract_lvvcs(
        &presentation_strings,
        presentation_submission,
        formatter_provider,
        map_oidc_format_to_external,
    )
    .await?;

    if presentation_submission.descriptor_map.len()
        != (interaction_data
            .presentation_definition
            .input_descriptors
            .len()
            + extracted_lvvcs.len())
    {
        // different count of requested and submitted credentials
        return Err(OpenID4VCIError::InvalidRequest.into());
    }

    let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();
    // Unpack presentations and credentials
    for presentation_submitted in &presentation_submission.descriptor_map {
        let input_descriptor = interaction_data
            .presentation_definition
            .input_descriptors
            .iter()
            .find(|descriptor| descriptor.id == presentation_submitted.id)
            .ok_or(OpenID4VCIError::InvalidRequest)?;

        let presentation_string_index =
            vec_last_position_from_token_path(&presentation_submitted.path)?;

        let presentation_string = presentation_strings
            .get(presentation_string_index)
            .ok_or(OpenID4VCIError::InvalidRequest)?;

        let context = if &presentation_submitted.format == "mso_mdoc" {
            ExtractPresentationCtx {
                format_nonce: submission.mdoc_generated_nonce.clone(),
                ..extract_presentation_ctx_from_interaction_content(interaction_data.clone())
            }
        } else {
            ExtractPresentationCtx::default()
        };

        let presentation = validate_presentation(
            presentation_string,
            &interaction_data.nonce,
            &presentation_submitted.format,
            formatter_provider,
            build_key_verification(
                KeyRole::Authentication,
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
            ),
            context,
            map_oidc_format_to_external,
        )
        .await?;

        let path_nested = presentation_submitted
            .path_nested
            .as_ref()
            .ok_or(OpenID4VCIError::InvalidRequest)?;

        // ONE-1924: there must be a specific schemaId filter
        let schema_id_filter = input_descriptor
            .constraints
            .fields
            .iter()
            .find(|field| {
                field.filter.is_some() && field.path.contains(&"$.credentialSchema.id".to_string())
            })
            .ok_or(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest))?
            .filter
            .as_ref()
            .ok_or(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest))?;

        let proof_schema_input = proof_schema_inputs
            .iter()
            .find(|input| {
                input
                    .credential_schema
                    .as_ref()
                    .is_some_and(|schema| schema.schema_id == schema_id_filter.r#const)
            })
            .ok_or(OpenID4VCError::Other(
                "Missing proof input schema for credential schema".to_owned(),
            ))?;

        let (credential, mso) = validate_credential(
            presentation,
            path_nested,
            &extracted_lvvcs,
            proof_schema_input,
            formatter_provider,
            build_key_verification(
                KeyRole::AssertionMethod,
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
            ),
            did_method_provider,
            revocation_method_provider,
            map_oidc_format_to_external,
        )
        .await?;

        if is_lvvc_credential(&credential) {
            continue;
        }

        let proved_claims: Vec<ValidatedProofClaimDTO> =
            validate_claims(credential, proof_schema_input, mso)?;

        total_proved_claims.extend(proved_claims);
    }

    Ok(total_proved_claims)
}

async fn extract_lvvcs(
    presentation_strings: &[String],
    presentation_submission: &PresentationSubmissionMappingDTO,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    map_oidc_format_to_external: FnMapOidcFormatToExternalDetailed,
) -> Result<Vec<DetailCredential>, OpenID4VCError> {
    let mut result = vec![];

    for presentation_submitted in &presentation_submission.descriptor_map {
        let presentation_string_index =
            vec_last_position_from_token_path(&presentation_submitted.path)?;
        let presentation_string = presentation_strings
            .get(presentation_string_index)
            .ok_or(OpenID4VCIError::InvalidRequest)?;

        let presentation = peek_presentation(
            presentation_string,
            &presentation_submitted.format,
            formatter_provider,
            map_oidc_format_to_external,
        )
        .await?;

        let path_nested = presentation_submitted
            .path_nested
            .as_ref()
            .ok_or(OpenID4VCIError::InvalidRequest)?;

        let credential_index = vec_last_position_from_token_path(&path_nested.path)?;
        let credential = presentation
            .credentials
            .get(credential_index)
            .ok_or(OpenID4VCIError::InvalidRequest)?;

        let oidc_format = &path_nested.format;
        let format = map_oidc_format_to_external(oidc_format, Some(credential))?;
        let formatter = formatter_provider
            .get_formatter(&format)
            .ok_or(OpenID4VCIError::VCFormatsNotSupported)?;

        let credential = formatter
            .extract_credentials_unverified(credential)
            .await
            .map_err(|e| {
                if matches!(e, FormatterError::CouldNotExtractCredentials(_)) {
                    OpenID4VCIError::VCFormatsNotSupported.into()
                } else {
                    OpenID4VCError::Other(e.to_string())
                }
            })?;

        if is_lvvc_credential(&credential) {
            result.push(credential);
        }
    }

    Ok(result)
}

fn build_key_verification(
    key_role: KeyRole,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
) -> Box<KeyVerification> {
    Box::new(KeyVerification {
        key_algorithm_provider,
        did_method_provider,
        key_role,
    })
}

async fn accept_proof(
    proof: Proof,
    proved_claims: Vec<ValidatedProofClaimDTO>,
) -> Result<AcceptProofResult, OpenID4VCError> {
    let proof_schema = proof.schema.ok_or(OpenID4VCError::MappingError(
        "proof schema is None".to_string(),
    ))?;

    let input_schemas = proof_schema
        .input_schemas
        .ok_or(OpenID4VCError::MappingError(
            "input schemas is None".to_string(),
        ))?;

    let mut claim_schemas_for_credential_schema = HashMap::new();
    for input_schema in input_schemas {
        let credential_schema =
            input_schema
                .credential_schema
                .ok_or(OpenID4VCError::MappingError(
                    "credential_schema is None".to_string(),
                ))?;

        let claim_schemas = credential_schema
            .claim_schemas
            .ok_or(OpenID4VCError::MappingError(
                "claim schemas is None".to_string(),
            ))?;

        claim_schemas_for_credential_schema
            .entry(credential_schema.id)
            .or_insert(vec![])
            .extend(claim_schemas);
    }

    #[derive(Debug)]
    struct ProvedClaim {
        claim_schema: ClaimSchema,
        value: serde_json::Value,
        credential: DetailCredential,
        credential_schema: CredentialSchema,
        mdoc_mso: Option<MobileSecurityObject>,
    }
    let proved_claims = proved_claims
        .into_iter()
        .map(|proved_claim| {
            Ok(ProvedClaim {
                value: proved_claim.value,
                credential: proved_claim.credential,
                credential_schema: proved_claim.credential_schema,
                claim_schema: proved_claim.proof_input_claim.schema,
                mdoc_mso: proved_claim.mdoc_mso,
            })
        })
        .collect::<Result<Vec<ProvedClaim>, OpenID4VCError>>()?;

    let mut claims_per_credential: HashMap<CredentialSchemaId, Vec<ProvedClaim>> = HashMap::new();
    for proved_claim in proved_claims {
        claims_per_credential
            .entry(proved_claim.credential_schema.id)
            .or_default()
            .push(proved_claim);
    }

    let mut proved_credentials = vec![];

    let mut proof_claims: Vec<Claim> = vec![];
    for (credential_schema_id, credential_claims) in claims_per_credential {
        let claims: Vec<(serde_json::Value, ClaimSchema)> = credential_claims
            .iter()
            .map(|claim| (claim.value.to_owned(), claim.claim_schema.to_owned()))
            .collect();

        let first_claim = credential_claims
            .first()
            .ok_or(OpenID4VCError::MappingError("claims are empty".to_string()))?;
        let credential = &first_claim.credential;
        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "issuer_did is missing".to_string(),
            ))?;

        let holder_did = credential
            .subject
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "credential subject is missing".to_string(),
            ))
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;

        let claim_schemas = claim_schemas_for_credential_schema
            .get(&credential_schema_id)
            .ok_or_else(|| {
                OpenID4VCError::MappingError(format!(
                    "Claim schemas are missing for credential schema {credential_schema_id}"
                ))
            })?;
        let proved_credential = extracted_credential_to_model(
            claim_schemas,
            first_claim.credential_schema.to_owned(),
            claims,
            issuer_did,
            holder_did,
            first_claim.mdoc_mso.to_owned(),
        )?;

        proof_claims.append(
            &mut proved_credential
                .credential
                .claims
                .as_ref()
                .ok_or(OpenID4VCError::MappingError("claims missing".to_string()))?
                .to_owned(),
        );

        proved_credentials.push(proved_credential);
    }

    Ok(AcceptProofResult {
        proved_credentials,
        proved_claims: proof_claims,
    })
}

pub fn create_credential_offer(
    base_url: &str,
    pre_authorized_code: &str,
    credential_schema_id: &CredentialSchemaId,
    credentials: Vec<OpenID4VCICredentialOfferCredentialDTO>,
) -> Result<OpenID4VCICredentialOfferDTO, OpenID4VCError> {
    Ok(OpenID4VCICredentialOfferDTO {
        credential_issuer: format!("{}/ssi/oidc-issuer/v1/{}", base_url, credential_schema_id),
        credentials,
        grants: OpenID4VCIGrants {
            code: OpenID4VCIGrant {
                pre_authorized_code: pre_authorized_code.to_owned(),
            },
        },
    })
}

pub fn credentials_format(
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    oidc_format: &str,
    claims: &[Claim],
) -> Result<Vec<OpenID4VCICredentialOfferCredentialDTO>, OpenID4VCError> {
    Ok(vec![OpenID4VCICredentialOfferCredentialDTO {
        wallet_storage_type,
        format: oidc_format.to_owned(),
        credential_definition: Some(OpenID4VCICredentialDefinition {
            r#type: vec!["VerifiableCredential".to_string()],
            credential_subject: Some(OpenID4VCICredentialSubject {
                keys: HashMap::from_iter(claims.iter().filter_map(|claim| {
                    claim.schema.as_ref().map(|schema| {
                        (
                            claim.path.clone(),
                            OpenID4VCICredentialValueDetails {
                                value: claim.value.clone(),
                                value_type: schema.data_type.clone(),
                            },
                        )
                    })
                })),
            }),
        }),
        doctype: None,
        claims: Default::default(),
    }])
}

pub fn oidc_create_token(
    mut interaction_data: OpenID4VCIInteractionDataDTO,
    credentials: &[Credential],
    interaction: &Interaction,
    request: &OpenID4VCITokenRequestDTO,
    pre_authorization_expires_in: Duration,
    access_token_expires_in: Duration,
    refresh_token_expires_in: Duration,
) -> Result<OpenID4VCIInteractionDataDTO, OpenID4VCError> {
    throw_if_token_request_invalid(request)?;

    let generate_new_token = || {
        format!(
            "{}.{}",
            interaction.id,
            utilities::generate_alphanumeric(32)
        )
    };

    let now = OffsetDateTime::now_utc();
    match request {
        OpenID4VCITokenRequestDTO::PreAuthorizedCode { .. } => {
            throw_if_interaction_created_date(pre_authorization_expires_in, interaction)?;
            throw_if_interaction_pre_authorized_code_used(&interaction_data)?;

            credentials.iter().try_for_each(|credential| {
                throw_if_latest_credential_state_not_eq(credential, CredentialStateEnum::Pending)
            })?;

            interaction_data.pre_authorized_code_used = true;
            interaction_data.access_token_expires_at = Some(now + access_token_expires_in);
        }

        OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } => {
            validate_refresh_token(&interaction_data, refresh_token)?;
            // we update both the access token and the refresh token
            interaction_data.access_token = generate_new_token();
            interaction_data.access_token_expires_at = Some(now + access_token_expires_in);

            interaction_data.refresh_token = Some(generate_new_token());
            interaction_data.refresh_token_expires_at = Some(now + refresh_token_expires_in);
        }
    };

    Ok(interaction_data)
}

pub fn parse_refresh_token(token: &str) -> Result<InteractionId, OpenID4VCIError> {
    parse_access_token(token)
}

pub fn parse_access_token(access_token: &str) -> Result<InteractionId, OpenID4VCIError> {
    let mut splitted_token = access_token.split('.');
    if splitted_token.to_owned().count() != 2 {
        return Err(OpenID4VCIError::InvalidToken);
    }

    Uuid::from_str(splitted_token.next().ok_or(OpenID4VCIError::InvalidToken)?)
        .map_err(|_| OpenID4VCIError::RuntimeError("Could not parse UUID".to_owned()))
}

pub fn is_interaction_data_valid(
    interaction_data: &OpenID4VCIInteractionDataDTO,
    access_token: &str,
) -> bool {
    interaction_data.pre_authorized_code_used
        && interaction_data.access_token == access_token
        && interaction_data
            .access_token_expires_at
            .is_some_and(|expires_at| expires_at > OffsetDateTime::now_utc())
}
