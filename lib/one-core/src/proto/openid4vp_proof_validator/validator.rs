use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidValue, SerializedCredential};
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vp::dcql::{
    CredentialFormat, CredentialQuery, CredentialQueryId, TrustedAuthority,
};
use standardized_types::openid4vp::{DirectPostResponse, VpTokenResponse};
use standardized_types::x509::KeyIdentifier;

use crate::config::core_config::{DidType, FormatType, VerificationProtocolType};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::mapper::x509::pem_chain_to_authority_key_identifiers;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::KeyRole;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::model::proof_schema::ProofInputSchema;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::key_verification::KeyVerification;
use crate::proto::openid4vp_proof_validator::validated_proof_result::ValidatedProofClaimDTO;
use crate::proto::openid4vp_proof_validator::{OpenId4VpProofValidator, ValidatedProofResult};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialClaim, DetailCredential, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::model::{
    ExtractPresentationCtx, ExtractedPresentation, PresentedTransactionData,
};
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::model::{
    CredentialDataByRole, RevocationState, VerifierCredentialData,
};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::transaction_data::TransactionDataAuthorization;
use crate::provider::transaction_data::provider::TransactionDataProvider;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::mapper::{
    extract_presentation_ctx_from_interaction_content, vec_last_position_from_token_path,
};
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPVerifierInteractionContent, PexSubmission, SubmissionRequestData,
    TransactionDataRequest, VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::validator::{
    validate_expiration_time, validate_issuance_time,
};
use crate::validator::throw_if_proof_state_not_in;

pub(crate) struct OpenId4VpProofValidatorProto {
    did_method_provider: Arc<dyn DidMethodProvider>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    transaction_data_provider: Arc<dyn TransactionDataProvider>,
}

#[async_trait]
impl OpenId4VpProofValidator for OpenId4VpProofValidatorProto {
    async fn validate_submission(
        &self,
        request: SubmissionRequestData,
        proof: Proof,
        interaction_data: OpenID4VPVerifierInteractionContent,
        protocol_type: VerificationProtocolType,
    ) -> Result<(ValidatedProofResult, DirectPostResponse), OpenID4VCError> {
        throw_if_proof_state_not_in(
            &proof,
            &[ProofStateEnum::Pending, ProofStateEnum::Requested],
        )
        .map_err(|e| OpenID4VCError::InvalidProofState(e.to_string()))?;

        let proved_claims = match (
            &interaction_data.dcql_query,
            &interaction_data.presentation_definition,
        ) {
            (Some(_), Some(_)) => Err(OpenID4VCError::ValidationError(
                "DCQL query and presentation submission are not allowed at the same time"
                    .to_string(),
            )),
            (Some(_), None) => {
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
            ValidatedProofResult::new(&proof, proved_claims).await?,
            DirectPostResponse { redirect_uri },
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
        transaction_data_provider: Arc<dyn TransactionDataProvider>,
    ) -> Self {
        Self {
            did_method_provider,
            credential_formatter_provider,
            presentation_formatter_provider,
            key_algorithm_provider,
            revocation_method_provider,
            certificate_validator,
            transaction_data_provider,
        }
    }

    async fn process_proof_submission_dcql_query(
        &self,
        submission: SubmissionRequestData,
        proof: &Proof,
        interaction_data: OpenID4VPVerifierInteractionContent,
        protocol_type: VerificationProtocolType,
    ) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
        let VpSubmissionData::Dcql(VpTokenResponse { vp_token }) = submission.submission_data
        else {
            return Err(OpenID4VCError::ValidationError(
                "Missing DCQL VP token".to_string(),
            ));
        };

        let dcql_query = interaction_data
            .dcql_query
            .as_ref()
            .ok_or(OpenID4VCError::ValidationError(
                "Missing DCQL query".to_string(),
            ))?
            .to_owned();

        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "missing proof schema".to_string(),
            ))?
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;

        let proof_input_schemas = proof_schema
            .input_schemas
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;

        if vp_token.len() != dcql_query.credentials.len() {
            return Err(OpenID4VCError::ValidationError(
                "Different count of requested and submitted credentials".to_string(),
            ));
        }

        let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();
        let mut transaction_data_evidence = HashMap::new();

        // Iterate over each credential query, validate the associated presentation(s),
        // and extract the credential(s).
        for credential_query in &dcql_query.credentials {
            let dcql_credential_format = &credential_query.format;
            let query_id = credential_query.id.to_string();

            let proof_input_schema = proof_input_schemas
                .iter()
                .find(|input| input.credential_schema.id_ref().to_string() == query_id)
                .ok_or(OpenID4VCError::Other(
                    "Missing proof input schema for credential schema".to_owned(),
                ))?;

            let Some(presentation_strings) = vp_token.get(&query_id) else {
                return Err(OpenID4VCError::ValidationError(format!(
                    "No presentation found for credential query {query_id}"
                )));
            };

            let context = if let CredentialFormat::MsoMdoc(_) = dcql_credential_format {
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
                    nonce: Some(interaction_data.nonce.clone()),
                    format_nonce: None,
                    issuance_date: None,
                    expiration_date: None,
                    client_id: Some(interaction_data.client_id.clone()),
                    response_uri: None,
                    mdoc_session_transcript: None,
                    verifier_key: None,
                }
            };

            let (proved_claims, presented_transaction_data) = self
                .validate_credential_query(
                    credential_query,
                    &interaction_data,
                    proof_input_schema,
                    presentation_strings,
                    context,
                )
                .await?;

            let format = match dcql_credential_format {
                CredentialFormat::SdJwt(_) => Some(FormatType::SdJwtVc),
                CredentialFormat::MsoMdoc(_) => Some(FormatType::Mdoc),
                _ => None,
            };
            // formatters report `Some` even when the presentation carries no
            // transaction data (e.g. an mdoc without device-signed elements);
            // only non-empty values count as presented evidence
            if let (Some(format), Some(presented)) = (format, presented_transaction_data)
                && !presented.is_empty()
            {
                transaction_data_evidence.insert(credential_query.id.clone(), (format, presented));
            }

            total_proved_claims.extend(proved_claims);
        }

        self.validate_transaction_data(
            &interaction_data.common.transaction_data,
            &transaction_data_evidence,
        )
        .await?;

        Ok(total_proved_claims)
    }

    /// Validates a legacy Presentation Exchange submission. Only reachable via the verifier
    /// side of proximity protocol version 1; Presentation Exchange has no `transaction_data`,
    /// so no transaction data validation happens here.
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
        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "missing proof schema".to_string(),
            ))?
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;

        let proof_schema_inputs = match proof_schema
            .input_schemas
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?
        {
            input_schemas if !input_schemas.is_empty() => input_schemas.to_vec(),
            _ => {
                return Err(OpenID4VCError::Other(
                    "Missing proof input schema".to_owned(),
                ));
            }
        };

        let Some(presentation_definition) = interaction_data.presentation_definition.clone() else {
            return Err(OpenID4VCError::ValidationError(
                "Missing presentation definition".to_string(),
            ));
        };

        if presentation_submission.descriptor_map.len()
            != (presentation_definition.input_descriptors.len())
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
                    nonce: Some(interaction_data.nonce.clone()),
                    format_nonce: None,
                    issuance_date: None,
                    expiration_date: None,
                    client_id: Some(interaction_data.client_id.clone()),
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

            let mut proof_schema_input = None;
            for input in &proof_schema_inputs {
                let schema_id = input
                    .credential_schema
                    .as_ref()
                    .await
                    .map_err(|e| OpenID4VCError::Other(e.to_string()))?
                    .schema_id()
                    .await
                    .map_err(|e| OpenID4VCError::Other(e.to_string()))?;
                if schema_id == target_schema_id {
                    proof_schema_input = Some(input);
                    break;
                }
            }
            let proof_schema_input = proof_schema_input.ok_or(OpenID4VCError::Other(
                "Missing proof input schema for credential schema".to_owned(),
            ))?;

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

            let credential = self
                .validate_credential(
                    Some(holder_details),
                    credential_token,
                    proof_schema_input,
                    None,
                )
                .await?;

            let proved_claims = validate_claims(credential, proof_schema_input).await?;

            total_proved_claims.extend(proved_claims);
        }

        Ok(total_proved_claims)
    }

    /// Validates that each transaction data entry sent in the authorization request
    /// was authorized via exactly one of the credentials referenced in its `credential_ids`,
    /// and that no credential presented evidence without authorizing an entry
    async fn validate_transaction_data(
        &self,
        transaction_data: &[TransactionDataRequest],
        evidence: &HashMap<CredentialQueryId, (FormatType, PresentedTransactionData)>,
    ) -> Result<(), OpenID4VCError> {
        let mut seen_entries = HashSet::new();
        let mut authorizing_credentials = HashSet::new();

        for request in transaction_data {
            let provider = self
                .transaction_data_provider
                .get_transaction_data_by_name(&request.r#type)
                .map_err(|e| OpenID4VCError::Other(e.to_string()))?;

            // identical entries produce identical evidence, making their authorizations
            // indistinguishable
            if !seen_entries.insert(request.encoded.clone()) {
                return Err(OpenID4VCError::ValidationError(
                    "Duplicate transaction data entry in authorization request".to_string(),
                ));
            }

            let mut authorized_by = Vec::new();
            for credential_id in &request.credential_ids {
                let Some((format, presented)) = evidence.get(credential_id) else {
                    continue;
                };

                match provider
                    .verify_transaction_data(&request.encoded, *format, presented)
                    .await
                    .map_err(|e| OpenID4VCError::Other(e.to_string()))?
                {
                    TransactionDataAuthorization::Authorized => {
                        authorized_by.push(credential_id);
                    }
                    // the wallet did not use this referenced credential for authorization
                    TransactionDataAuthorization::NotAuthorized => {}
                }
            }

            // OpenID4VP section 5.1: the wallet MUST use exactly one of the referenced credentials
            let [authorizing_credential] = authorized_by.as_slice() else {
                return Err(OpenID4VCError::ValidationError(format!(
                    "Transaction data must be authorized by exactly one referenced credential, authorized by: {authorized_by:?}"
                )));
            };
            authorizing_credentials.insert((*authorizing_credential).clone());
        }

        // evidence is holder-signed data; reject any that matches no requested entry
        if let Some(stray) = evidence
            .keys()
            .find(|credential_id| !authorizing_credentials.contains(*credential_id))
        {
            return Err(OpenID4VCError::ValidationError(format!(
                "Credential {stray} presented transaction data evidence not matching any requested entry"
            )));
        }
        Ok(())
    }

    async fn validate_credential_query(
        &self,
        credential_query: &CredentialQuery,
        interaction_data: &OpenID4VPVerifierInteractionContent,
        proof_input_schema: &ProofInputSchema,
        presentation_strings: &[String],
        context: ExtractPresentationCtx,
    ) -> Result<
        (
            Vec<ValidatedProofClaimDTO>,
            Option<PresentedTransactionData>,
        ),
        OpenID4VCError,
    > {
        let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

        // If multiple is true, then the verifier will accept multiple presentation tokens
        // for the same credential query.
        let multiple_presentations_allowed = credential_query.multiple;
        let require_holder_binding = credential_query.require_cryptographic_holder_binding;
        let dcql_credential_format = &credential_query.format;
        let query_id = &credential_query.id;
        let trusted_authorities = credential_query.trusted_authorities.as_deref();

        // cryptographic holder binding is required, we expect verifialbe presentations (one or many, depending on `multiple` flag)
        let (holder_details, credentials, presented_transaction_data) = if require_holder_binding {
            if !multiple_presentations_allowed && presentation_strings.len() != 1 {
                return Err(OpenID4VCError::ValidationError(format!(
                    "Expected one presentation for credential query {query_id}"
                )));
            }

            let presentation_string = presentation_strings.first().ok_or_else(|| {
                OpenID4VCError::ValidationError(format!(
                    "No presentations for credential query {query_id}"
                ))
            })?;

            let presentation_format_type = match dcql_credential_format {
                // Our existing implementation conflated the vc+sd-jwt and dc+sd-jwt formats.
                // The SD_JWT(_VC) presentation formatter was used for both W3C and IETF SD-JWTs.
                // This match ensures the correct w3c presentation format is used for W3C SD-JWTs.
                CredentialFormat::W3cSdJwt(..) => FormatType::Jwt,
                _ => map_from_oidc_format_to_core_detailed(
                    credential_query.format.dcql_format(),
                    Some(&presentation_string.as_str().into()),
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
                transaction_data,
                ..
            } = self
                .validate_presentation(
                    presentation_string,
                    &interaction_data.nonce,
                    &presentation_format,
                    context.clone(),
                )
                .await?;

            let holder_details = issuer.ok_or(OpenID4VCError::ValidationError(
                "Presentation missing holder id".to_string(),
            ))?;

            (Some(holder_details), credentials, transaction_data)
        } else {
            // No holder binding — presentation_strings contains bare credential tokens
            let credential_tokens = presentation_strings
                .iter()
                .map(|token| token.as_str().into())
                .collect();

            (None, credential_tokens, None)
        };

        for credential_token in credentials {
            let credential = self
                .validate_credential(
                    holder_details.as_ref(),
                    &credential_token,
                    proof_input_schema,
                    trusted_authorities,
                )
                .await?;

            let proved_claims: Vec<ValidatedProofClaimDTO> =
                validate_claims(credential, proof_input_schema).await?;

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

        Ok((total_proved_claims, presented_transaction_data))
    }

    async fn validate_credential(
        &self,
        holder_details: Option<&IdentifierDetails>,
        credential_token: &SerializedCredential,
        proof_schema_input: &ProofInputSchema,
        trusted_authorities: Option<&[TrustedAuthority]>,
    ) -> Result<DetailCredential, OpenID4VCError> {
        let credential_schema = proof_schema_input
            .credential_schema
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;
        let format = credential_schema.format().await.map_err(|_| {
            OpenID4VCError::MappingError("missing credential schema format".to_string())
        })?;
        let formatter = self
            .credential_formatter_provider
            .get_credential_formatter(&format)
            .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?;

        let credential = formatter
            .extract_credentials(
                credential_token,
                Some(&credential_schema),
                self.key_verification(KeyRole::AssertionMethod),
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
                            proof_input: proof_schema_input.to_owned(),
                        },
                    ))),
                    false,
                )
                .await
                .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?
            {
                RevocationState::Valid => {}
                RevocationState::Revoked | RevocationState::Suspended { .. } => {
                    return Err(OpenID4VCError::CredentialIsRevokedOrSuspended);
                }
            }
        }

        // Check if all subjects of the submitted VCs are matching the holder did.
        if let Some(holder_details) = holder_details {
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
        }

        if let Some(authorities) = trusted_authorities {
            check_issuer_is_trusted_authority(&credential.issuer, authorities)?;
        }

        Ok(credential)
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
    let did_type = match did.method() {
        "tdw" => DidType::WebVh,
        method => DidType::from_str(method.to_uppercase().as_str()).map_err(|_| {
            OpenID4VCError::ValidationError(format!(
                "Unsupported holder DID method: {}",
                did.method()
            ))
        })?,
    };

    if !allowed_did_methods.contains(&did_type) {
        return Err(OpenID4VCError::ValidationError(format!(
            "Unsupported holder DID method: {}",
            did.method()
        )));
    }

    Ok(())
}

async fn check_matching_key_with_did(
    key: &PublicJwk,
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

    let issuer_akis =
        pem_chain_to_authority_key_identifiers(&issuer_certificate.chain).map_err(|e| {
            OpenID4VCError::ValidationError(format!(
                "Failed to retrieve Authority Key Identifier for credential issuer: {e}"
            ))
        })?;

    let trusted_akis = get_trusted_akis(authorities);

    for trusted_aki in &trusted_akis {
        for issuer_aki in &issuer_akis {
            if issuer_aki == trusted_aki {
                return Ok(());
            }
        }
    }

    Err(OpenID4VCError::ValidationError(
        "Issuer is not in Trusted Authorities list".to_owned(),
    ))
}

pub(crate) fn get_trusted_akis(authorities: &[TrustedAuthority]) -> Vec<KeyIdentifier> {
    let mut result = vec![];
    for authority in authorities {
        if let TrustedAuthority::AuthorityKeyId { values } = authority {
            result.extend_from_slice(values);
        }
    }
    result
}

async fn validate_claims(
    received_credential: DetailCredential,
    proof_input_schema: &ProofInputSchema,
) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
    let expected_credential_claims = proof_input_schema
        .claim_schemas
        .as_ref()
        .await
        .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;

    let credential_schema = proof_input_schema
        .credential_schema
        .as_ref()
        .await
        .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;
    let mut proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

    for expected_credential_claim in &expected_credential_claims {
        let resolved = resolve_claim(
            &expected_credential_claim.schema,
            &credential_schema,
            &received_credential.claims.claims,
        )
        .await?;
        if let Some(value) = resolved {
            // Expected claim present in the presentation
            proved_claims.push(ValidatedProofClaimDTO {
                proof_input_claim: expected_credential_claim.to_owned(),
                credential: received_credential.to_owned(),
                value: value.to_owned(),
                credential_schema: credential_schema.to_owned(),
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

async fn resolve_claim<'a>(
    claim_schema: &ClaimSchema,
    credential_schema: &CredentialSchema,
    claims: &'a HashMap<String, CredentialClaim>,
) -> Result<Option<&'a CredentialClaim>, OpenID4VCError> {
    let formats = credential_schema
        .formats
        .as_ref()
        .await
        .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;
    let format = formats
        .first()
        .ok_or(OpenID4VCError::MappingError("Missing format".to_string()))?;
    let mappings = format
        .claim_mappings
        .as_ref()
        .await
        .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;
    let mapping = mappings
        .iter()
        .find(|m| m.claim_schema_id == claim_schema.id)
        .ok_or(OpenID4VCError::MappingError(
            "Missing claim mapping".to_string(),
        ))?;

    let claim_schema_path = mapping.formatted_technical_key();

    // Simplest case - claim is not nested
    if let Some(value) = claims.get(&claim_schema_path) {
        return Ok(Some(value));
    }

    match claim_schema_path.split_once(NESTED_CLAIM_MARKER) {
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
