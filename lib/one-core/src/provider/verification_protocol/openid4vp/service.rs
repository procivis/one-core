use std::collections::HashMap;
use std::sync::Arc;

use shared_types::CredentialSchemaId;
use time::{Duration, OffsetDateTime};

use super::draft25::mappers::encode_client_id_with_scheme;
use super::error::OpenID4VCError;
use super::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, OpenID4VPClientMetadata,
    OpenID4VPClientMetadataJwkDTO, OpenID4VPClientMetadataJwks, OpenID4VPDirectPostResponseDTO,
    OpenID4VpPresentationFormat, PresentationSubmissionMappingDTO, ValidatedProofClaimDTO,
};
use crate::common_mapper::PublicKeyWithJwk;
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::{CoreConfig, VerificationProtocolType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::KeyRole;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::MobileSecurityObject;
use crate::provider::credential_formatter::model::{
    DetailCredential, ExtractPresentationCtx, HolderBindingCtx,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::lvvc::util::is_lvvc_credential;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::openid4vp::mapper::{
    extract_presentation_ctx_from_interaction_content, extracted_credential_to_model,
    parse_interaction_content, vec_last_position_from_token_path,
};
use crate::provider::verification_protocol::openid4vp::model::{
    AcceptProofResult, OpenID4VPPresentationDefinition, SubmissionRequestData,
};
use crate::provider::verification_protocol::openid4vp::validator::{
    peek_presentation, validate_claims, validate_credential, validate_presentation,
};
use crate::util::key_verification::KeyVerification;
use crate::util::oidc::map_from_oidc_format_to_core_detailed;

pub(crate) fn create_open_id_for_vp_client_metadata(
    jwk: Option<PublicKeyWithJwk>,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
) -> OpenID4VPClientMetadata {
    let mut metadata = OpenID4VPClientMetadata {
        vp_formats,
        ..Default::default()
    };
    if let Some(jwk) = jwk {
        metadata.jwks = Some(OpenID4VPClientMetadataJwks {
            keys: vec![OpenID4VPClientMetadataJwkDTO {
                key_id: jwk.key_id.to_string(),
                jwk: jwk.jwk.into(),
            }],
        });
        metadata.authorization_encrypted_response_alg =
            Some(AuthorizationEncryptedResponseAlgorithm::EcdhEs);
        metadata.authorization_encrypted_response_enc =
            Some(AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM);
    }

    metadata
}

pub(crate) fn oidc_verifier_presentation_definition(
    proof: &Proof,
    mut presentation_definition: OpenID4VPPresentationDefinition,
) -> Result<OpenID4VPPresentationDefinition, OpenID4VCError> {
    let proof_schema = proof.schema.as_ref().ok_or(OpenID4VCError::MappingError(
        "Proof schema not found".to_string(),
    ))?;

    let proof_schema_inputs = match proof_schema.input_schemas.as_ref() {
        Some(input_schemas) if !input_schemas.is_empty() => input_schemas.to_vec(),
        _ => {
            return Err(OpenID4VCError::MappingError(
                "input_schemas are missing".to_string(),
            ));
        }
    };

    if proof_schema_inputs.len() != presentation_definition.input_descriptors.len() {
        return Err(OpenID4VCError::Other(
            "Proof schema inputs length doesn't match interaction data input descriptors length"
                .to_owned(),
        ));
    }

    let now = OffsetDateTime::now_utc();
    for (input_descriptor, proof_schema_input) in presentation_definition
        .input_descriptors
        .iter_mut()
        .zip(proof_schema_inputs)
    {
        if let Some(validity_constraint) = proof_schema_input.validity_constraint {
            input_descriptor.constraints.validity_credential_nbf =
                Some(now - Duration::seconds(validity_constraint));
        }
    }

    Ok(presentation_definition)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn oid4vp_verifier_process_submission(
    request: SubmissionRequestData,
    proof: Proof,
    interaction_data: &[u8],
    did_method_provider: &Arc<dyn DidMethodProvider>,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    config: &CoreConfig,
) -> Result<(AcceptProofResult, OpenID4VPDirectPostResponseDTO), OpenID4VCError> {
    throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)
        .or(throw_if_latest_proof_state_not_eq(
            &proof,
            ProofStateEnum::Requested,
        ))
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    let proved_claims = process_proof_submission(
        request,
        &proof,
        interaction_data,
        did_method_provider,
        formatter_provider,
        key_algorithm_provider,
        revocation_method_provider,
        config,
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
    submission: SubmissionRequestData,
    proof: &Proof,
    interaction_data: &[u8],
    did_method_provider: &Arc<dyn DidMethodProvider>,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    config: &CoreConfig,
) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
    let interaction_data = parse_interaction_content(interaction_data)?;

    let presentation_submission = &submission.presentation_submission;

    let definition_id = presentation_submission.definition_id.clone();
    let vp_token = submission.vp_token;
    let state = submission.state;

    if definition_id != state.to_string() {
        return Err(OpenID4VCError::ValidationError(
            "Invalid submission state".to_string(),
        ));
    }

    let presentation_strings: Vec<String> = if vp_token.starts_with('[') {
        serde_json::from_str(&vp_token)
            .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?
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
    )
    .await?;

    if presentation_submission.descriptor_map.len()
        != (interaction_data
            .presentation_definition
            .input_descriptors
            .len()
            + extracted_lvvcs.len())
    {
        return Err(OpenID4VCError::ValidationError(
            "different count of requested and submitted credentials".to_string(),
        ));
    }

    let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

    // Unpack presentations and credentials
    for presentation_submitted in &presentation_submission.descriptor_map {
        let input_descriptor = interaction_data
            .presentation_definition
            .input_descriptors
            .iter()
            .find(|descriptor| descriptor.id == presentation_submitted.id)
            .ok_or(OpenID4VCError::ValidationError(format!(
                "Could not find input descriptor id: {}",
                presentation_submitted.id
            )))?;

        let presentation_string_index =
            vec_last_position_from_token_path(&presentation_submitted.path)?;

        let presentation_string = presentation_strings.get(presentation_string_index).ok_or(
            OpenID4VCError::ValidationError(format!(
                "Could not find presentation at index: {presentation_string_index}",
            )),
        )?;

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
        )
        .await?;

        let path_nested = presentation_submitted.path_nested.as_ref();
        if path_nested.is_none()
            && (presentation_submission.descriptor_map.len() > 1
                && presentation_submitted.format != "ldp_vp"
                && presentation_submitted.format != "jwt_vp_json")
        {
            return Err(OpenID4VCError::ValidationError(
                "Path nested missing".to_string(),
            ));
        }

        if let Some(path_nested) = path_nested {
            if !input_descriptor
                .format
                .keys()
                .any(|format| *format == path_nested.format)
            {
                return Err(OpenID4VCError::ValidationError(format!(
                    "Could not find entry for format: {}",
                    path_nested.format
                )));
            }
        }

        let target_schema_id = if input_descriptor.format.contains_key("mso_mdoc") {
            input_descriptor.id.to_owned()
        } else {
            // ONE-1924: there must be a specific schemaId filter
            let schema_id_filter = input_descriptor
                .constraints
                .fields
                .iter()
                .find(|field| {
                    field.filter.is_some()
                        && field.path.contains(&"$.credentialSchema.id".to_string())
                        || field.path.contains(&"$.vct".to_string())
                })
                .ok_or(OpenID4VCError::ValidationError(
                    "Cannot find filter for schemaId".to_string(),
                ))?
                .filter
                .as_ref()
                .ok_or(OpenID4VCError::ValidationError(
                    "Cannot find filter for schemaId".to_string(),
                ))?;

            schema_id_filter.r#const.to_owned()
        };

        let proof_schema_input = proof_schema_inputs
            .iter()
            .find(|input| {
                input
                    .credential_schema
                    .as_ref()
                    .is_some_and(|schema| schema.schema_id == target_schema_id)
            })
            .ok_or(OpenID4VCError::Other(
                "Missing proof input schema for credential schema".to_owned(),
            ))?;

        let holder_binding_token_audience = {
            let proof_verification_protocol = config
                .verification_protocol
                .get_fields(&proof.exchange)
                .map_err(|_| {
                    OpenID4VCError::ValidationError(format!(
                        "Verification Protocol {} not found in config",
                        proof.exchange
                    ))
                })?;

            match proof_verification_protocol.r#type {
                VerificationProtocolType::OpenId4VpDraft25 => encode_client_id_with_scheme(
                    interaction_data.client_id.clone(),
                    interaction_data
                        .client_id_scheme
                        .ok_or(OpenID4VCError::ValidationError(
                            "Client ID scheme is missing".to_string(),
                        ))?,
                ),
                VerificationProtocolType::OpenId4VpDraft20Swiyu => interaction_data
                    .response_uri
                    .clone()
                    .ok_or(OpenID4VCError::ValidationError(
                        "response uri is missing".to_string(),
                    ))?,
                _ => interaction_data.client_id.clone(),
            }
        };

        let holder_binding_ctx = HolderBindingCtx {
            nonce: interaction_data.nonce.clone(),
            audience: holder_binding_token_audience,
        };

        let (credential, mso) = validate_credential(
            presentation,
            presentation_submitted,
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
            holder_binding_ctx,
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
) -> Result<Vec<DetailCredential>, OpenID4VCError> {
    let mut result = vec![];

    for presentation_submitted in &presentation_submission.descriptor_map {
        let presentation_string_index =
            vec_last_position_from_token_path(&presentation_submitted.path)?;
        let presentation_string = presentation_strings.get(presentation_string_index).ok_or(
            OpenID4VCError::ValidationError(format!(
                "Could not find presentation at index: {presentation_string_index}",
            )),
        )?;

        let presentation = peek_presentation(
            presentation_string,
            &presentation_submitted.format,
            formatter_provider,
        )
        .await?;

        let Some(ref path_nested) = presentation_submitted.path_nested else {
            // no path_nested means mso_mdoc so there is no LVVC
            continue;
        };

        let credential_index = vec_last_position_from_token_path(&path_nested.path)?;
        let credential = presentation.credentials.get(credential_index).ok_or(
            OpenID4VCError::ValidationError(format!(
                "Could not find presentation credential at index: {credential_index}",
            )),
        )?;

        let oidc_format = &path_nested.format;
        let format = map_from_oidc_format_to_core_detailed(oidc_format, Some(credential))
            .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?;
        let formatter =
            formatter_provider
                .get_formatter(&format)
                .ok_or(OpenID4VCError::ValidationError(format!(
                    "Could not find format: {format}",
                )))?;

        let credential = formatter
            .extract_credentials_unverified(credential, None)
            .await
            .map_err(|e| OpenID4VCError::Other(e.to_string()))?;

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
            &proof.exchange,
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
