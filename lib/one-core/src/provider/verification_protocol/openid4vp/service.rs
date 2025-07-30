use std::collections::HashMap;
use std::sync::Arc;

use dcql::CredentialFormat;
use shared_types::CredentialSchemaId;
use time::{Duration, OffsetDateTime};

use super::error::OpenID4VCError;
use super::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, OpenID4VPClientMetadataJwkDTO,
    OpenID4VPClientMetadataJwks, OpenID4VPDirectPostResponseDTO,
    OpenID4VPVerifierInteractionContent, OpenID4VpPresentationFormat,
    PresentationSubmissionMappingDTO, ValidatedProofClaimDTO,
};
use crate::common_mapper::PublicKeyWithJwk;
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::VerificationProtocolType;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::KeyRole;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::model::{DetailCredential, HolderBindingCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::model::ExtractPresentationCtx;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::lvvc::util::is_lvvc_credential;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::openid4vp::mapper::{
    extract_presentation_ctx_from_interaction_content, extracted_credential_to_model,
    vec_last_position_from_token_path,
};
use crate::provider::verification_protocol::openid4vp::model::{
    AcceptProofResult, DcqlSubmission, OpenID4VPDraftClientMetadata,
    OpenID4VPPresentationDefinition, PexSubmission, SubmissionRequestData, VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::validator::{
    peek_presentation, validate_claims, validate_credential, validate_presentation,
};
use crate::service::certificate::validator::CertificateValidator;
use crate::util::key_verification::KeyVerification;
use crate::util::mdoc::MobileSecurityObject;
use crate::util::oidc::map_from_oidc_format_to_core_detailed;

pub(crate) fn create_open_id_for_vp_client_metadata_draft(
    jwk: Option<PublicKeyWithJwk>,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
) -> OpenID4VPDraftClientMetadata {
    let mut metadata = OpenID4VPDraftClientMetadata {
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
        "missing proof schema".to_string(),
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
    interaction_data: OpenID4VPVerifierInteractionContent,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    credential_formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: &Arc<dyn PresentationFormatterProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    protocol_type: VerificationProtocolType,
) -> Result<(AcceptProofResult, OpenID4VPDirectPostResponseDTO), OpenID4VCError> {
    throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)
        .or(throw_if_latest_proof_state_not_eq(
            &proof,
            ProofStateEnum::Requested,
        ))
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    let proved_claims = match (
        &interaction_data.dcql_query,
        &interaction_data.presentation_definition,
    ) {
        (Some(_), Some(_)) => Err(OpenID4VCError::ValidationError(
            "DCQL query and presentation submission are not allowed at the same time".to_string(),
        )),
        (Some(_dcql_query), None) => {
            process_proof_submission_dcql_query(
                request,
                &proof,
                interaction_data,
                did_method_provider,
                credential_formatter_provider,
                presentation_formatter_provider,
                key_algorithm_provider,
                revocation_method_provider,
                certificate_validator,
                protocol_type,
            )
            .await
        }
        (None, Some(_)) => {
            process_proof_submission_presentation_exchange(
                request,
                &proof,
                interaction_data,
                did_method_provider,
                credential_formatter_provider,
                presentation_formatter_provider,
                key_algorithm_provider,
                revocation_method_provider,
                certificate_validator,
                protocol_type,
            )
            .await
        }
        (None, None) => Err(OpenID4VCError::ValidationError(
            "Missing DCQL query and presentation submission".to_string(),
        )),
    }?;

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
async fn process_proof_submission_dcql_query(
    submission: SubmissionRequestData,
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    credential_formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: &Arc<dyn PresentationFormatterProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    protocol_type: VerificationProtocolType,
) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
    let VpSubmissionData::Dcql(DcqlSubmission { vp_token }) = submission.submission_data else {
        return Err(OpenID4VCError::ValidationError(
            "Missing DCQL VP token".to_string(),
        ));
    };

    let Some(dcql_query) = interaction_data.dcql_query.as_ref() else {
        return Err(OpenID4VCError::ValidationError(
            "Missing DCQL query in interaction data".to_string(),
        ));
    };

    let Some(proof_input_schemas) = proof
        .schema
        .as_ref()
        .and_then(|schema| schema.input_schemas.as_ref())
    else {
        return Err(OpenID4VCError::MappingError(
            "Missing proof schema".to_string(),
        ));
    };

    if vp_token.len() != dcql_query.credentials.len() {
        return Err(OpenID4VCError::ValidationError(
            "Different count of requested and submitted credentials".to_string(),
        ));
    }

    let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

    for credential_query in &dcql_query.credentials {
        let Some(presentation_strings) = vp_token.get(&credential_query.id.to_string()) else {
            return Err(OpenID4VCError::ValidationError(format!(
                "No presentation found for credential query {}",
                credential_query.id
            )));
        };

        let proof_input_schema = proof_input_schemas
            .iter()
            .find(|input| {
                input
                    .credential_schema
                    .as_ref()
                    .is_some_and(|schema| schema.id.to_string() == credential_query.id.to_string())
            })
            .ok_or(OpenID4VCError::Other(
                "Missing proof input schema for credential schema".to_owned(),
            ))?;

        let requested_credential_schema =
            proof_input_schema
                .credential_schema
                .as_ref()
                .ok_or(OpenID4VCError::Other(
                    "Missing credential schema".to_owned(),
                ))?;

        let [credential_presentation] = presentation_strings.as_slice() else {
            return Err(OpenID4VCError::ValidationError(format!(
                "Expected one presentation for credential query {}",
                credential_query.id
            )));
        };

        let context = if credential_query.format == CredentialFormat::MsoMdoc {
            ExtractPresentationCtx {
                format_nonce: submission.mdoc_generated_nonce.clone(),
                ..extract_presentation_ctx_from_interaction_content(
                    interaction_data.clone(),
                    protocol_type,
                )
            }
        } else {
            ExtractPresentationCtx {
                verification_protocol_type: protocol_type,
                nonce: None,
                format_nonce: None,
                issuance_date: None,
                expiration_date: None,
                client_id: None,
                response_uri: None,
                mdoc_session_transcript: None,
                verifier_key: None,
            }
        };

        let key_verification = build_key_verification(
            KeyRole::Authentication,
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            certificate_validator.clone(),
        );

        // Our existing implementation conflated the vc+sd-jwt and dc+sd-jwt formats.
        // The SD_JWT(_VC) presentation formatter was used for both W3C and IETF SD-JWTs.
        // This match ensures the correct w3c presentation format is used for W3C SD-JWTs.
        let presentation_format = match credential_query.format {
            CredentialFormat::W3cSdJwt => "JWT".to_string(),
            _ => map_from_oidc_format_to_core_detailed(
                &credential_query.format.to_string(),
                Some(credential_presentation),
            )
            .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?,
        };

        let credential_presentation = validate_presentation(
            credential_presentation,
            &interaction_data.nonce,
            &presentation_format,
            presentation_formatter_provider,
            key_verification.clone(),
            context,
        )
        .await?;

        let holder_binding_ctx = HolderBindingCtx {
            nonce: interaction_data.nonce.clone(),
            audience: interaction_data.client_id.clone(),
        };

        let holder_details =
            credential_presentation
                .issuer
                .as_ref()
                .ok_or(OpenID4VCError::ValidationError(
                    "Presentation missing holder id".to_string(),
                ))?;

        let (credential_token, lvvc_credential) = {
            let lvvc_credential_expected = requested_credential_schema.revocation_method == "LVVC";

            match credential_presentation.credentials.as_slice() {
                [cred, lvvc] if lvvc_credential_expected => (cred, Some(lvvc)),
                [cred] if !lvvc_credential_expected => (cred, None),
                _ if lvvc_credential_expected => {
                    return Err(OpenID4VCError::ValidationError(
                        "Missing LVVC credential presentation".to_string(),
                    ));
                }
                _ => {
                    return Err(OpenID4VCError::ValidationError(
                        "Expected one presentation".to_string(),
                    ));
                }
            }
        };

        let lvvc_credential = {
            if let Some(lvvc) = lvvc_credential {
                let formatter = credential_formatter_provider
                    .get_credential_formatter(requested_credential_schema.format.as_str())
                    .ok_or(OpenID4VCError::ValidationError(format!(
                        "Could not find format: {}",
                        requested_credential_schema.format
                    )))?;
                let lvvc_credential = formatter
                    .extract_credentials_unverified(lvvc, None)
                    .await
                    .map_err(|e| OpenID4VCError::Other(e.to_string()))?;
                vec![lvvc_credential]
            } else {
                vec![]
            }
        };

        let (credential, mso) = validate_credential(
            holder_details,
            credential_token,
            &lvvc_credential,
            proof_input_schema,
            credential_formatter_provider,
            key_verification,
            did_method_provider,
            revocation_method_provider,
            holder_binding_ctx,
        )
        .await?;

        let proved_claims: Vec<ValidatedProofClaimDTO> =
            validate_claims(credential, proof_input_schema, mso)?;

        if let Some(claim_sets) = credential_query.claim_sets.as_ref() {
            if claim_sets.iter().any(|claim_set| {
                claim_set.iter().all(|claim| {
                    proved_claims.iter().any(|proved_claim| {
                        proved_claim.proof_input_claim.schema.key == claim.to_string()
                    })
                })
            }) {
                return Err(OpenID4VCError::ValidationError(
                    "Claim set is not satisfied".to_string(),
                ));
            }
        }
        total_proved_claims.extend(proved_claims);
    }

    Ok(total_proved_claims)
}

#[allow(clippy::too_many_arguments)]
async fn process_proof_submission_presentation_exchange(
    submission: SubmissionRequestData,
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    credential_formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: &Arc<dyn PresentationFormatterProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    protocol_type: VerificationProtocolType,
) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
    let VpSubmissionData::Pex(PexSubmission {
        presentation_submission,
        vp_token,
    }) = submission.submission_data
    else {
        return Err(OpenID4VCError::ValidationError(
            "Missing presentation submission".to_string(),
        ));
    };

    let definition_id = presentation_submission.definition_id.clone();
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
        &presentation_submission,
        credential_formatter_provider,
        presentation_formatter_provider,
        protocol_type,
    )
    .await?;

    let Some(presentation_definition) = interaction_data.presentation_definition.clone() else {
        return Err(OpenID4VCError::ValidationError(
            "Missing presentation definition".to_string(),
        ));
    };

    if presentation_submission.descriptor_map.len()
        != (presentation_definition.input_descriptors.len() + extracted_lvvcs.len())
    {
        return Err(OpenID4VCError::ValidationError(
            "different count of requested and submitted credentials".to_string(),
        ));
    }

    let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

    // Unpack presentations and credentials
    for presentation_submitted in &presentation_submission.descriptor_map {
        let input_descriptor = presentation_definition
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
                ..extract_presentation_ctx_from_interaction_content(
                    interaction_data.clone(),
                    protocol_type,
                )
            }
        } else {
            ExtractPresentationCtx {
                verification_protocol_type: protocol_type,
                nonce: None,
                format_nonce: None,
                issuance_date: None,
                expiration_date: None,
                client_id: None,
                response_uri: None,
                mdoc_session_transcript: None,
                verifier_key: None,
            }
        };

        let presentation_format = map_from_oidc_format_to_core_detailed(
            &presentation_submitted.format,
            Some(presentation_string),
        )
        .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?;

        let presentation = validate_presentation(
            presentation_string,
            &interaction_data.nonce,
            &presentation_format,
            presentation_formatter_provider,
            build_key_verification(
                KeyRole::Authentication,
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                certificate_validator.clone(),
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

        let holder_binding_ctx = HolderBindingCtx {
            nonce: interaction_data.nonce.clone(),
            audience: interaction_data.client_id.clone(),
        };

        let holder_details =
            presentation
                .issuer
                .as_ref()
                .ok_or(OpenID4VCError::ValidationError(
                    "Presentation missing holder id".to_string(),
                ))?;

        let credential_index = presentation_submitted
            .path_nested
            .as_ref()
            .map(|p| vec_last_position_from_token_path(&p.path))
            .transpose()?
            .unwrap_or(0);

        let credential_token = presentation.credentials.get(credential_index).ok_or(
            OpenID4VCError::ValidationError(format!(
                "Credential at index {credential_index} not found",
            )),
        )?;

        let (credential, mso) = validate_credential(
            holder_details,
            credential_token,
            &extracted_lvvcs,
            proof_schema_input,
            credential_formatter_provider,
            build_key_verification(
                KeyRole::AssertionMethod,
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                certificate_validator.clone(),
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
    credential_formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: &Arc<dyn PresentationFormatterProvider>,
    protocol_type: VerificationProtocolType,
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
            presentation_formatter_provider,
            protocol_type,
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
        let formatter = credential_formatter_provider
            .get_credential_formatter(&format)
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
    certificate_validator: Arc<dyn CertificateValidator>,
) -> Box<KeyVerification> {
    Box::new(KeyVerification {
        key_algorithm_provider,
        did_method_provider,
        key_role,
        certificate_validator,
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

        let holder_details = credential
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
            credential.issuer.to_owned(),
            holder_details.to_owned(),
            first_claim.mdoc_mso.to_owned(),
            &proof.protocol,
            &proof.profile,
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
