use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidValue, SerializedCredential};
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vp::dcql::{
    CredentialFormat, CredentialQuery, CredentialQueryId, DcqlQuery, TrustedAuthority,
};
use standardized_types::openid4vp::{DirectPostResponse, VpTokenResponse};
use standardized_types::x509::KeyIdentifier;

use crate::config::core_config::{DidType, FormatType, VerificationProtocolType};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::mapper::x509::pem_chain_to_authority_key_identifiers;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
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
use crate::provider::verification_protocol::openid4vp::mapper::extract_presentation_ctx_from_interaction_content;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPVerifierInteractionContent, SubmissionRequestData, TransactionDataRequest,
    VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::validator::{
    validate_expiration_time, validate_issuance_time,
};
use crate::validator::proof_schema::resolve_proof_input_schema_formats;
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

        let proved_claims = self
            .process_proof_submission_dcql_query(request, &proof, interaction_data, protocol_type)
            .await?;

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

        let dcql_query = interaction_data.dcql_query.to_owned();

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

        validate_dcql_submission(&dcql_query, &vp_token)?;

        let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();
        let mut transaction_data_evidence = HashMap::new();

        // Iterate over each credential query, validate the associated presentation(s),
        // and extract the credential(s).
        for credential_query in &dcql_query.credentials {
            let dcql_credential_format = &credential_query.format;
            let query_id = credential_query.id.to_string();

            let Some(presentation_strings) = vp_token.get(&query_id) else {
                continue;
            };
            let (proof_input_schema, schema_format) =
                resolve_credential_query_input(&proof_input_schemas, &query_id).await?;

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
                    &schema_format,
                    presentation_strings,
                    context,
                )
                .await?;

            let format = match dcql_credential_format {
                CredentialFormat::SdJwtVc(_) => Some(FormatType::SdJwtVc),
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
        schema_format: &CredentialSchemaFormat,
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

        if presentation_strings.is_empty()
            || (!multiple_presentations_allowed && presentation_strings.len() != 1)
        {
            return Err(OpenID4VCError::ValidationError(format!(
                "Invalid presentation count for credential query {query_id}"
            )));
        }

        let mut transaction_data_evidence = None;
        for presentation_string in presentation_strings {
            // With holder binding, the tokens are verifiable presentations.
            let (holder_details, credentials, presented_transaction_data) =
                if require_holder_binding {
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
                    // Without holder binding, each token is a bare credential.
                    (None, vec![presentation_string.as_str().into()], None)
                };

            if credentials.is_empty() {
                return Err(OpenID4VCError::ValidationError(format!(
                    "Presentation has no credentials for credential query {query_id}"
                )));
            }

            for credential_token in credentials {
                let credential = self
                    .validate_credential(
                        holder_details.as_ref(),
                        &credential_token,
                        proof_input_schema,
                        schema_format,
                        trusted_authorities,
                    )
                    .await?;

                let proved_claims: Vec<ValidatedProofClaimDTO> =
                    validate_claims(credential, proof_input_schema, schema_format).await?;

                if let Some(claim_sets) = credential_query.claim_sets.as_ref()
                    && !claim_sets.iter().any(|claim_set| {
                        claim_set.iter().all(|claim| {
                            proved_claims.iter().any(|proved_claim| {
                                proved_claim.proof_input_claim.schema.id.to_string()
                                    == claim.to_string()
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

            if let Some(presented) = presented_transaction_data
                && !presented.is_empty()
                && transaction_data_evidence.replace(presented).is_some()
            {
                return Err(OpenID4VCError::ValidationError(format!(
                    "Multiple presentations authorize transaction data for credential query {query_id}"
                )));
            }
        }

        Ok((total_proved_claims, transaction_data_evidence))
    }

    async fn validate_credential(
        &self,
        holder_details: Option<&IdentifierDetails>,
        credential_token: &SerializedCredential,
        proof_schema_input: &ProofInputSchema,
        schema_format: &CredentialSchemaFormat,
        trusted_authorities: Option<&[TrustedAuthority]>,
    ) -> Result<DetailCredential, OpenID4VCError> {
        let credential_schema = proof_schema_input
            .credential_schema
            .as_ref()
            .await
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;
        let formatter = self
            .credential_formatter_provider
            .get_credential_formatter(&schema_format.format)
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
        "tdw" => DidType::Tdw,
        "webvh" => DidType::Webvh,
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

pub(super) fn validate_dcql_submission(
    query: &DcqlQuery,
    vp_token: &HashMap<String, Vec<String>>,
) -> Result<(), OpenID4VCError> {
    if vp_token.is_empty() {
        return Err(OpenID4VCError::ValidationError(
            "Empty VP token".to_string(),
        ));
    }
    let requested: HashSet<_> = query.credentials.iter().map(|q| q.id.to_string()).collect();
    for (id, presentations) in vp_token {
        if !requested.contains(id) {
            return Err(OpenID4VCError::ValidationError(format!(
                "Unknown credential query {id}"
            )));
        }
        if presentations.is_empty() || presentations.iter().any(String::is_empty) {
            return Err(OpenID4VCError::ValidationError(format!(
                "No presentation for credential query {id}"
            )));
        }
    }
    if let Some(sets) = &query.credential_sets {
        for (index, set) in sets.iter().enumerate() {
            if set.required
                && !set.options.iter().any(|option| {
                    !option.is_empty()
                        && option
                            .iter()
                            .all(|id| vp_token.contains_key(&id.to_string()))
                })
            {
                let options: Vec<Vec<_>> = set
                    .options
                    .iter()
                    .map(|option| option.iter().map(ToString::to_string).collect())
                    .collect();
                return Err(OpenID4VCError::ValidationError(format!(
                    "Credential set at index {index} is not satisfied; expected one of {options:?}"
                )));
            }
        }
    } else {
        let missing: Vec<_> = query
            .credentials
            .iter()
            .map(|query| query.id.to_string())
            .filter(|id| !vp_token.contains_key(id))
            .collect();
        if !missing.is_empty() {
            return Err(OpenID4VCError::ValidationError(format!(
                "Missing requested credentials: {}",
                missing.join(", ")
            )));
        }
    }
    Ok(())
}

async fn resolve_credential_query_input<'a>(
    inputs: &'a [ProofInputSchema],
    query_id: &str,
) -> Result<(&'a ProofInputSchema, CredentialSchemaFormat), OpenID4VCError> {
    for input in inputs {
        let formats = resolve_proof_input_schema_formats(input)
            .await
            .map_err(|e| OpenID4VCError::MappingError(e.to_string()))?;
        if let Some(format) = formats
            .into_iter()
            .find(|format| format.id.to_string() == query_id)
        {
            return Ok((input, format));
        }
    }
    Err(OpenID4VCError::MappingError(format!(
        "Missing proof input format for credential query {query_id}"
    )))
}

async fn validate_claims(
    received_credential: DetailCredential,
    proof_input_schema: &ProofInputSchema,
    schema_format: &CredentialSchemaFormat,
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
    // Several presentations may satisfy the same query; their claims must stay
    // attached to the credential instance from which they were extracted.
    let credential_instance_id = uuid::Uuid::new_v4().into();

    for expected_credential_claim in &expected_credential_claims {
        let resolved = resolve_claim(
            &expected_credential_claim.schema,
            schema_format,
            &received_credential.claims,
        )
        .await?;
        if let Some(value) = resolved {
            // Expected claim present in the presentation
            proved_claims.push(ValidatedProofClaimDTO {
                credential_instance_id,
                proof_input_claim: expected_credential_claim.to_owned(),
                credential: received_credential.to_owned(),
                value: value.to_owned(),
                credential_schema: credential_schema.to_owned(),
                credential_schema_format: schema_format.clone(),
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
    format: &CredentialSchemaFormat,
    claims: &'a HashMap<String, CredentialClaim>,
) -> Result<Option<&'a CredentialClaim>, OpenID4VCError> {
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
