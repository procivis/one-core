use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use dcql::{CredentialFormat, CredentialQuery, TrustedAuthority};
use shared_types::DidValue;

use crate::config::core_config::{DidType, FormatType, VerificationProtocolType};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::model::did::KeyRole;
use crate::model::key::PublicKeyJwk;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::model::proof_schema::ProofInputSchema;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::key_verification::KeyVerification;
use crate::proto::openid4vp_proof_validator::validated_proof_result::ValidatedProofClaimDTO;
use crate::proto::openid4vp_proof_validator::{OpenId4VpProofValidator, ValidatedProofResult};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::try_extracting_mso_from_token;
use crate::provider::credential_formatter::mdoc_formatter::util::MobileSecurityObject;
use crate::provider::credential_formatter::model::{
    CredentialClaim, DetailCredential, HolderBindingCtx, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::model::{
    ExtractPresentationCtx, ExtractedPresentation,
};
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::lvvc::util::is_lvvc_credential;
use crate::provider::revocation::model::{
    CredentialDataByRole, RevocationState, VerifierCredentialData,
};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::mapper::{
    extract_presentation_ctx_from_interaction_content, vec_last_position_from_token_path,
};
use crate::provider::verification_protocol::openid4vp::model::{
    DcqlSubmission, OpenID4VPDirectPostResponseDTO, OpenID4VPVerifierInteractionContent,
    PexSubmission, PresentationSubmissionMappingDTO, SubmissionRequestData, VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::validator::{
    validate_expiration_time, validate_issuance_time,
};
use crate::util::authority_key_identifier::get_aki_for_pem_chain;
use crate::validator::throw_if_proof_state_not_in;

pub(crate) struct OpenId4VpProofValidatorProto {
    did_method_provider: Arc<dyn DidMethodProvider>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

#[async_trait]
impl OpenId4VpProofValidator for OpenId4VpProofValidatorProto {
    async fn validate_submission(
        &self,
        request: SubmissionRequestData,
        proof: Proof,
        interaction_data: OpenID4VPVerifierInteractionContent,
        protocol_type: VerificationProtocolType,
    ) -> Result<(ValidatedProofResult, OpenID4VPDirectPostResponseDTO), OpenID4VCError> {
        throw_if_proof_state_not_in(
            &proof,
            &[ProofStateEnum::Pending, ProofStateEnum::Requested],
        )
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

        let proved_claims = match (
            &interaction_data.dcql_query,
            &interaction_data.presentation_definition,
        ) {
            (Some(_), Some(_)) => Err(OpenID4VCError::ValidationError(
                "DCQL query and presentation submission are not allowed at the same time"
                    .to_string(),
            )),
            (Some(_dcql_query), None) => {
                self.process_proof_submission_dcql_query(
                    request,
                    &proof,
                    interaction_data,
                    protocol_type,
                )
                .await
            }
            (None, Some(_)) => {
                self.process_proof_submission_presentation_exchange(
                    request,
                    &proof,
                    interaction_data,
                    protocol_type,
                )
                .await
            }
            (None, None) => Err(OpenID4VCError::ValidationError(
                "Missing DCQL query and presentation submission".to_string(),
            )),
        }?;
        let redirect_uri: Option<String> = proof.redirect_uri.to_owned();
        Ok((
            ValidatedProofResult::new(&proof, proved_claims)?,
            OpenID4VPDirectPostResponseDTO { redirect_uri },
        ))
    }
}

impl OpenId4VpProofValidatorProto {
    pub(crate) fn new(
        did_method_provider: Arc<dyn DidMethodProvider>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            did_method_provider,
            credential_formatter_provider,
            presentation_formatter_provider,
            key_algorithm_provider,
            revocation_method_provider,
            certificate_validator,
        }
    }

    async fn process_proof_submission_dcql_query(
        &self,
        submission: SubmissionRequestData,
        proof: &Proof,
        interaction_data: OpenID4VPVerifierInteractionContent,
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

        let proof_input_schemas = proof
            .schema
            .as_ref()
            .and_then(|schema| schema.input_schemas.as_ref())
            .ok_or(OpenID4VCError::MappingError(
                "missing proof input schema".to_string(),
            ))?;

        if vp_token.len() != dcql_query.credentials.len() {
            return Err(OpenID4VCError::ValidationError(
                "Different count of requested and submitted credentials".to_string(),
            ));
        }

        let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

        // Iterate over each credential query, validate the associated presentation(s),
        // and extract the credential(s).
        for credential_query in &dcql_query.credentials {
            let dcql_credential_format = &credential_query.format;
            let query_id = credential_query.id.to_string();

            let proof_input_schema = proof_input_schemas
                .iter()
                .find(|input| {
                    input
                        .credential_schema
                        .as_ref()
                        .is_some_and(|schema| schema.id.to_string() == query_id)
                })
                .ok_or(OpenID4VCError::Other(
                    "Missing proof input schema for credential schema".to_owned(),
                ))?;

            let Some(presentation_strings) = vp_token.get(&query_id) else {
                return Err(OpenID4VCError::ValidationError(format!(
                    "No presentation found for credential query {query_id}"
                )));
            };

            let context = if dcql_credential_format == &CredentialFormat::MsoMdoc {
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

            let proved_claims = self
                .validate_credential_query(
                    credential_query,
                    &interaction_data,
                    proof_input_schema,
                    presentation_strings,
                    context,
                )
                .await?;

            total_proved_claims.extend(proved_claims);
        }

        Ok(total_proved_claims)
    }

    async fn validate_credential_query(
        &self,
        credential_query: &CredentialQuery,
        interaction_data: &OpenID4VPVerifierInteractionContent,
        proof_input_schema: &ProofInputSchema,
        presentation_strings: &[String],
        context: ExtractPresentationCtx,
    ) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
        let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

        // If multiple is true, then the verifier will accept multiple presentation tokens
        // for the same credential query.
        let multiple_presentations_allowed = credential_query.multiple;
        let dcql_credential_format = &credential_query.format;
        let query_id = &credential_query.id;
        let trusted_authorities = credential_query.trusted_authorities.as_deref();

        if !multiple_presentations_allowed && presentation_strings.len() != 1 {
            return Err(OpenID4VCError::ValidationError(format!(
                "Expected one presentation for credential query {query_id}"
            )));
        }

        for presentation_string in presentation_strings {
            let presentation_format_type = match dcql_credential_format {
                // Our existing implementation conflated the vc+sd-jwt and dc+sd-jwt formats.
                // The SD_JWT(_VC) presentation formatter was used for both W3C and IETF SD-JWTs.
                // This match ensures the correct w3c presentation format is used for W3C SD-JWTs.
                CredentialFormat::W3cSdJwt => FormatType::Jwt,
                _ => map_from_oidc_format_to_core_detailed(
                    &credential_query.format.to_string(),
                    Some(presentation_string),
                )
                .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?,
            };
            let (presentation_format, _) = self
                .presentation_formatter_provider
                .get_presentation_formatter_by_type(presentation_format_type)
                .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

            let ExtractedPresentation {
                issuer,
                credentials,
                ..
            } = self
                .validate_presentation(
                    presentation_string,
                    &interaction_data.nonce,
                    &presentation_format,
                    context.clone(),
                )
                .await?;

            let (lvvc_credentials, non_lvvc_credentials) = self
                .filter_lvvc_credentials(credential_query, proof_input_schema, credentials)
                .await?;

            for credential_token in non_lvvc_credentials {
                let (credential, mso) = self
                    .validate_credential(
                        issuer.as_ref().ok_or(OpenID4VCError::ValidationError(
                            "Presentation missing holder id".to_string(),
                        ))?,
                        &credential_token,
                        &lvvc_credentials,
                        proof_input_schema,
                        HolderBindingCtx {
                            nonce: interaction_data.nonce.clone(),
                            audience: interaction_data.client_id.clone(),
                        },
                        trusted_authorities,
                    )
                    .await?;

                let proved_claims: Vec<ValidatedProofClaimDTO> =
                    validate_claims(credential, proof_input_schema, mso)?;

                if let Some(claim_sets) = credential_query.claim_sets.as_ref()
                    && claim_sets.iter().any(|claim_set| {
                        claim_set.iter().all(|claim| {
                            proved_claims.iter().any(|proved_claim| {
                                proved_claim.proof_input_claim.schema.key == claim.to_string()
                            })
                        })
                    })
                {
                    return Err(OpenID4VCError::ValidationError(
                        "Claim set is not satisfied".to_string(),
                    ));
                }
                total_proved_claims.extend(proved_claims);
            }
        }

        Ok(total_proved_claims)
    }

    async fn filter_lvvc_credentials(
        &self,
        credential_query: &CredentialQuery,
        proof_input_schema: &ProofInputSchema,
        credentials: Vec<String>,
    ) -> Result<(Vec<DetailCredential>, Vec<String>), OpenID4VCError> {
        // If multiple is true, then the verifier will accept multiple presentation tokens
        // for the same credential query.
        let multiple_presentations_allowed = credential_query.multiple;

        let requested_credential_schema =
            proof_input_schema
                .credential_schema
                .as_ref()
                .ok_or(OpenID4VCError::Other(
                    "Missing credential schema".to_owned(),
                ))?;

        let lvvc_credential_expected = requested_credential_schema.revocation_method == "LVVC";

        if !multiple_presentations_allowed {
            if lvvc_credential_expected {
                if credentials.len() != 2 {
                    return Err(OpenID4VCError::ValidationError(
                        "Invalid number of credentials in presentation, expected 2".to_string(),
                    ));
                }
            } else if credentials.len() != 1 {
                return Err(OpenID4VCError::ValidationError(
                    "Invalid number of credentials in presentation, expected 1".to_string(),
                ));
            }
        };

        let mut lvvc_credentials = Vec::new();
        let mut non_lvvc_credentials = Vec::new();

        if lvvc_credential_expected {
            // We do not assume the LVVC is at any specific index in the presentation.
            // Instead we extract all credentials and then check if any of them are LVVCs,
            // This accounts for the case where the `multiple` flag is set to true
            // And more than one Credential + LVVC pairs are present.
            let credential_formatter = self
                .credential_formatter_provider
                .get_credential_formatter(requested_credential_schema.format.as_str())
                .ok_or(OpenID4VCError::ValidationError(format!(
                    "Could not find format: {}",
                    requested_credential_schema.format
                )))?;

            for credential_token in credentials {
                let potential_lvvc_credential = credential_formatter
                    .extract_credentials_unverified(&credential_token, None)
                    .await
                    .map_err(|e| OpenID4VCError::Other(e.to_string()))?;

                if is_lvvc_credential(&potential_lvvc_credential) {
                    lvvc_credentials.push(potential_lvvc_credential);
                } else {
                    non_lvvc_credentials.push(credential_token);
                }
            }
        } else {
            non_lvvc_credentials = credentials;
        };

        Ok((lvvc_credentials, non_lvvc_credentials))
    }

    async fn validate_credential(
        &self,
        holder_details: &IdentifierDetails,
        credential_token: &str,
        extracted_lvvcs: &[DetailCredential],
        proof_schema_input: &ProofInputSchema,
        holder_binding_ctx: HolderBindingCtx,
        trusted_authorities: Option<&[TrustedAuthority]>,
    ) -> Result<(DetailCredential, Option<MobileSecurityObject>), OpenID4VCError> {
        let format = proof_schema_input
            .credential_schema
            .as_ref()
            .map(|schema| schema.format.as_str())
            .ok_or(OpenID4VCError::VCFormatsNotSupported)?;
        let formatter = self
            .credential_formatter_provider
            .get_credential_formatter(format)
            .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

        let credential = formatter
            .extract_credentials(
                credential_token,
                proof_schema_input.credential_schema.as_ref(),
                self.key_verification(KeyRole::AssertionMethod),
                Some(holder_binding_ctx),
            )
            .await
            .map_err(|e| {
                if matches!(e, FormatterError::CouldNotExtractCredentials(_)) {
                    OpenID4VCError::VCFormatsNotSupported
                } else {
                    OpenID4VCError::Other(e.to_string())
                }
            })?;

        validate_issuance_time(&credential.valid_from, formatter.get_leeway())?;
        validate_expiration_time(&credential.valid_until, formatter.get_leeway())?;

        if is_revocation_credential(&credential) {
            return Ok((credential, None));
        };

        for credential_status in credential.status.iter() {
            let (revocation_method, _) = self
                .revocation_method_provider
                .get_revocation_method_by_status_type(&credential_status.r#type)
                .ok_or(OpenID4VCError::MissingRevocationProviderForType(
                    credential_status.r#type.clone(),
                ))?;

            match revocation_method
                .check_credential_revocation_status(
                    credential_status,
                    &credential.issuer,
                    Some(CredentialDataByRole::Verifier(Box::new(
                        VerifierCredentialData {
                            credential: credential.to_owned(),
                            extracted_lvvcs: extracted_lvvcs.to_owned(),
                            proof_input: proof_schema_input.to_owned(),
                        },
                    ))),
                    false,
                )
                .await?
            {
                RevocationState::Valid => {}
                RevocationState::Revoked | RevocationState::Suspended { .. } => {
                    return Err(OpenID4VCError::CredentialIsRevokedOrSuspended);
                }
            }
        }

        // Check if all subjects of the submitted VCs are matching the holder did.
        let Some(credential_subject) = &credential.subject else {
            return Err(OpenID4VCError::ValidationError(
                "Claim Holder DID missing".to_owned(),
            ));
        };

        check_matching_identifiers(
            credential_subject,
            holder_details,
            &*self.did_method_provider,
            &formatter.get_capabilities().holder_did_methods,
        )
        .await?;

        if let Some(authorities) = trusted_authorities {
            check_issuer_is_trusted_authority(&credential.issuer, authorities)?;
        }

        let mut mso = None;
        if format == "MDOC" {
            mso = Some(
                try_extracting_mso_from_token(credential_token)
                    .await
                    .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?,
            );
        }

        Ok((credential, mso))
    }

    async fn process_proof_submission_presentation_exchange(
        &self,
        submission: SubmissionRequestData,
        proof: &Proof,
        interaction_data: OpenID4VPVerifierInteractionContent,
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

        let presentation_strings: Vec<String> = if vp_token.len() == 1
            && let Some(token) = vp_token.first()
            && token.starts_with('[')
        {
            serde_json::from_str(token)
                .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?
        } else {
            vp_token
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

        let extracted_lvvcs = self
            .extract_lvvcs(
                &presentation_strings,
                &presentation_submission,
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

        for descriptor in &presentation_definition.input_descriptors {
            if presentation_submission
                .descriptor_map
                .iter()
                .all(|entry| entry.id != descriptor.id)
            {
                return Err(OpenID4VCError::ValidationError(format!(
                    "No descriptor map entry for input descriptor `{}`",
                    descriptor.id
                )));
            }
        }

        let mut total_proved_claims = Vec::new();

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

            let presentation_format_type = map_from_oidc_format_to_core_detailed(
                &presentation_submitted.format,
                Some(presentation_string),
            )
            .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?;
            let (presentation_format, _) = self
                .presentation_formatter_provider
                .get_presentation_formatter_by_type(presentation_format_type)
                .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

            let presentation = self
                .validate_presentation(
                    presentation_string,
                    &interaction_data.nonce,
                    &presentation_format,
                    context,
                )
                .await?;

            let path_nested = presentation_submitted.path_nested.as_ref();
            if let Some(path_nested) = path_nested
                && !input_descriptor
                    .format
                    .keys()
                    .any(|format| *format == path_nested.format)
            {
                return Err(OpenID4VCError::ValidationError(format!(
                    "Could not find entry for format: {}",
                    path_nested.format
                )));
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

            let (credential, mso) = self
                .validate_credential(
                    holder_details,
                    credential_token,
                    &extracted_lvvcs,
                    proof_schema_input,
                    holder_binding_ctx,
                    None,
                )
                .await?;

            if is_lvvc_credential(&credential) {
                continue;
            }

            let proved_claims = validate_claims(credential, proof_schema_input, mso)?;

            total_proved_claims.extend(proved_claims);
        }

        Ok(total_proved_claims)
    }

    async fn extract_lvvcs(
        &self,
        presentation_strings: &[String],
        presentation_submission: &PresentationSubmissionMappingDTO,
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

            let presentation = self
                .peek_presentation(
                    presentation_string,
                    &presentation_submitted.format,
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
            let format_type = map_from_oidc_format_to_core_detailed(oidc_format, Some(credential))
                .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?;
            let (_, formatter) = self
                .credential_formatter_provider
                .get_formatter_by_type(format_type)
                .ok_or(OpenID4VCError::ValidationError(format!(
                    "Could not find formatter for format type: {format_type}",
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

    async fn peek_presentation(
        &self,
        presentation_string: &str,
        oidc_format: &str,
        protocol_type: VerificationProtocolType,
    ) -> Result<ExtractedPresentation, OpenID4VCError> {
        let format_type =
            map_from_oidc_format_to_core_detailed(oidc_format, Some(presentation_string))
                .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?;
        let (_, presentation_formatter) = self
            .presentation_formatter_provider
            .get_presentation_formatter_by_type(format_type)
            .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

        let presentation = presentation_formatter
            .extract_presentation_unverified(
                presentation_string,
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
                },
            )
            .await
            .map_err(|e| {
                if matches!(e, FormatterError::CouldNotExtractPresentation(_)) {
                    OpenID4VCError::VPFormatsNotSupported
                } else {
                    OpenID4VCError::Other(e.to_string())
                }
            })?;

        Ok(presentation)
    }

    fn key_verification(&self, key_role: KeyRole) -> Box<KeyVerification> {
        Box::new(KeyVerification {
            key_role,
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            certificate_validator: self.certificate_validator.clone(),
        })
    }

    async fn validate_presentation(
        &self,
        presentation_string: &str,
        nonce: &str,
        presentation_format: &str,
        context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, OpenID4VCError> {
        let presentation_formatter = self
            .presentation_formatter_provider
            .get_presentation_formatter(presentation_format)
            .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

        let presentation = presentation_formatter
            .extract_presentation(
                presentation_string,
                self.key_verification(KeyRole::Authentication),
                context,
            )
            .await
            .map_err(|e| {
                if matches!(e, FormatterError::CouldNotExtractPresentation(_)) {
                    OpenID4VCError::VPFormatsNotSupported
                } else {
                    OpenID4VCError::Other(e.to_string())
                }
            })?;

        validate_issuance_time(&presentation.issued_at, presentation_formatter.get_leeway())?;
        validate_expiration_time(
            &presentation.expires_at,
            presentation_formatter.get_leeway(),
        )?;

        if presentation
            .nonce
            .as_ref()
            .is_none_or(|presentation_nonce| presentation_nonce != nonce)
        {
            return Err(OpenID4VCError::ValidationError(
                "Nonce not matched".to_string(),
            ));
        }
        Ok(presentation)
    }
}

fn is_revocation_credential(credential: &DetailCredential) -> bool {
    is_lvvc_credential(credential)
        || (credential.claims.claims.contains_key("encodedList")
            && credential.claims.claims.contains_key("statusPurpose"))
}

/// it can happen that credential holder binding is a key, while proof issuer is a did
/// we have to allow that combination if the same public key is used
async fn check_matching_identifiers(
    a: &IdentifierDetails,
    b: &IdentifierDetails,
    did_method_provider: &dyn DidMethodProvider,
    allowed_did_methods: &[DidType],
) -> Result<(), OpenID4VCError> {
    if a == b {
        return Ok(());
    }

    match (a, b) {
        (IdentifierDetails::Did(a), IdentifierDetails::Did(b)) => {
            check_did_method_allowed(a, allowed_did_methods)?;
            check_did_method_allowed(b, allowed_did_methods)?;
            check_matching_dids(a, b, did_method_provider).await?
        }
        (IdentifierDetails::Did(did_value), IdentifierDetails::Key(public_key_jwk))
        | (IdentifierDetails::Key(public_key_jwk), IdentifierDetails::Did(did_value)) => {
            check_did_method_allowed(did_value, allowed_did_methods)?;
            check_matching_key_with_did(public_key_jwk, did_value, did_method_provider).await?
        }
        _ => {
            return Err(OpenID4VCError::ValidationError(
                "Mismatching holder identifiers".to_owned(),
            ));
        }
    };

    Ok(())
}

fn check_did_method_allowed(
    did: &DidValue,
    allowed_did_methods: &[DidType],
) -> Result<(), OpenID4VCError> {
    let did_method = DidType::from_str(did.method().to_uppercase().as_str()).map_err(|_| {
        OpenID4VCError::ValidationError(format!("Unsupported holder DID method: {}", did.method()))
    })?;

    if !allowed_did_methods.contains(&did_method) {
        return Err(OpenID4VCError::ValidationError(format!(
            "Unsupported holder DID method: {}",
            did.method()
        )));
    }

    Ok(())
}

async fn check_matching_key_with_did(
    key: &PublicKeyJwk,
    did: &DidValue,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<(), OpenID4VCError> {
    let did_document = did_method_provider
        .resolve(did)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    // Find matching key in did document
    did_document
        .verification_method
        .iter()
        .find(|vm| &vm.public_key_jwk == key)
        .ok_or(OpenID4VCError::ValidationError(
            "Presentation signer DID not matching credential holder binding key".to_owned(),
        ))?;

    Ok(())
}

async fn check_matching_dids(
    a: &DidValue,
    b: &DidValue,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<(), OpenID4VCError> {
    let claim_subject_did_document = did_method_provider
        .resolve(a)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    let holder_did_document = did_method_provider
        .resolve(b)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    // Simplest case, the DIDs (and resolved documents) are exactly the same
    let same_did_document = claim_subject_did_document == holder_did_document;

    if same_did_document {
        return Ok(());
    }

    // If did documents / DIDs are different, validate that holder has matching key in claim subject

    // Get the holder's verification key
    let holder_key = holder_did_document
        .find_verification_method(None, None)
        .ok_or(OpenID4VCError::ValidationError(
            "Presentation signer DID document contains no verification methods".to_owned(),
        ))?;

    // Find matching key in claim subject's verification methods
    claim_subject_did_document
        .verification_method
        .iter()
        .find(|vm| vm.public_key_jwk == holder_key.public_key_jwk)
        .ok_or(OpenID4VCError::ValidationError(
            "Presentation signer key not found in claim subject DID document".to_owned(),
        ))?;

    Ok(())
}

fn check_issuer_is_trusted_authority(
    issuer: &IdentifierDetails,
    authorities: &[TrustedAuthority],
) -> Result<(), OpenID4VCError> {
    let IdentifierDetails::Certificate(issuer_certificate) = issuer else {
        // Currently, we support only AuthorityKeyId trusted authorities.
        // Non-certificate issuers cannot pass an AKI check, so the code can bail out early here.
        return Err(OpenID4VCError::ValidationError(
            "Issuer is not in Trusted Authorities list".to_owned(),
        ));
    };

    let Some(issuer_aki) = get_aki_for_pem_chain(issuer_certificate.chain.as_bytes()) else {
        return Err(OpenID4VCError::ValidationError(
            "Failed to retrieve Authority Key Identifier for credential issuer".to_owned(),
        ));
    };

    let trusted_akis = get_trusted_akis(authorities);

    for trusted_aki in &trusted_akis {
        // This is very inefficient.
        // We could use something like `bstr::ByteSlice::contains_str()`,
        // or maybe `.contains_bytes()` once the following gets implemented:
        // https://github.com/rust-lang/rust/issues/134149
        for window in issuer_aki.windows(trusted_aki.len()) {
            if window.iter().eq(trusted_aki.iter()) {
                return Ok(());
            }
        }
    }

    Err(OpenID4VCError::ValidationError(
        "Issuer is not in Trusted Authorities list".to_owned(),
    ))
}

pub(crate) fn get_trusted_akis(authorities: &[TrustedAuthority]) -> Vec<Vec<u8>> {
    // DCQL spec says that AKI values should be provided as base64url-encoded strings.
    // We need to decode those before we can match them against stored AKIs.

    let mut akis: Vec<Vec<u8>> = Vec::new();
    for authority in authorities {
        if let TrustedAuthority::AuthorityKeyId { values } = &authority {
            for value in values {
                match Base64UrlSafeNoPadding::decode_to_vec(value.as_bytes(), None) {
                    Ok(bytes) => akis.push(bytes),
                    Err(_) => { /* Discard invalid values */ }
                }
            }
        }
    }
    akis
}

fn validate_claims(
    received_credential: DetailCredential,
    proof_input_schema: &ProofInputSchema,
    mso: Option<MobileSecurityObject>,
) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
    let expected_credential_claims =
        proof_input_schema
            .claim_schemas
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "Missing claim schemas".to_string(),
            ))?;

    let credential_schema =
        proof_input_schema
            .credential_schema
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "Missing credential schema".to_string(),
            ))?;
    let mut proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

    for expected_credential_claim in expected_credential_claims {
        let resolved = resolve_claim(
            &expected_credential_claim.schema.key,
            &received_credential.claims.claims,
        );
        if let Some(value) = resolved? {
            // Expected claim present in the presentation
            proved_claims.push(ValidatedProofClaimDTO {
                proof_input_claim: expected_credential_claim.to_owned(),
                credential: received_credential.to_owned(),
                value: value.to_owned(),
                credential_schema: credential_schema.to_owned(),
                mdoc_mso: mso.clone(),
            })
        } else if expected_credential_claim.required {
            // Fail as required claim was not sent
            return Err(OpenID4VCError::ValidationError(
                "Required claim not submitted".to_string(),
            ));
        } else {
            // Not present but also not required
            continue;
        }
    }
    Ok(proved_claims)
}

fn resolve_claim<'a>(
    claim_name: &str,
    claims: &'a HashMap<String, CredentialClaim>,
) -> Result<Option<&'a CredentialClaim>, OpenID4VCError> {
    // Simplest case - claim is not nested
    if let Some(value) = claims.get(claim_name) {
        return Ok(Some(value));
    }

    match claim_name.split_once(NESTED_CLAIM_MARKER) {
        None => Ok(None),
        Some((prefix, rest)) => match claims.get(prefix) {
            None => Ok(None),
            Some(value) => resolve_claim_inner(rest, value),
        },
    }
}

fn resolve_claim_inner<'a>(
    claim_name: &str,
    claims: &'a CredentialClaim,
) -> Result<Option<&'a CredentialClaim>, OpenID4VCError> {
    if let Some(value) = claims.value.as_object().and_then(|obj| obj.get(claim_name)) {
        return Ok(Some(value));
    }

    match claim_name.split_once(NESTED_CLAIM_MARKER) {
        Some((prefix, rest)) => match claims.value.as_object().and_then(|obj| obj.get(prefix)) {
            None => Ok(None),
            Some(value) => resolve_claim_inner(rest, value),
        },
        None => Ok(None),
    }
}
