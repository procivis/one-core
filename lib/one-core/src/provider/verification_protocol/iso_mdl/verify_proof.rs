use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use shared_types::CredentialSchemaId;

use super::common::to_cbor;
use crate::config::core_config::VerificationProtocolType;
use crate::error::ContextWithErrorCode;
use crate::mapper::{ValidatedProofClaim, extracted_credential_to_model};
use crate::model::credential::Credential;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::did::KeyRole;
use crate::model::interaction::Interaction;
use crate::model::proof::{Proof, ProofClaim, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::model::relation::{OptionalRelatedExt, Related};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::ecosystem_resolver::EcosystemResolver;
use crate::proto::identifier_creator::{IdentifierCreator, IdentifierName, IdentifierRole};
use crate::proto::key_verification::KeyVerification;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::model::ExtractPresentationCtx;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::SessionTranscript;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::{MissingProviderError, ServiceError};
use crate::validator::{validate_expiration_time, validate_issuance_time};

#[cfg(test)]
mod test;

pub(super) struct ValidatedProofCredential {
    credential: DetailCredential,
    credential_schema_id: CredentialSchemaId,
    claims: Vec<ValidatedProofClaim>,
}

#[expect(clippy::too_many_arguments)]
/// validation on verifier's side
pub(super) async fn validate_proof(
    proof_schema: &ProofSchema,
    presentation: &str,
    session_transcript: SessionTranscript,
    credential_formatter_provider: &dyn CredentialFormatterProvider,
    presentation_formatter_provider: &dyn PresentationFormatterProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
) -> Result<Vec<ValidatedProofCredential>, ServiceError> {
    let key_verification_presentation = Box::new(KeyVerification {
        key_algorithm_provider: key_algorithm_provider.clone(),
        did_method_provider: did_method_provider.clone(),
        key_role: KeyRole::Authentication,
        certificate_validator: certificate_validator.clone(),
    });

    let key_verification_credentials = Box::new(KeyVerification {
        key_algorithm_provider: key_algorithm_provider.to_owned(),
        did_method_provider,
        key_role: KeyRole::AssertionMethod,
        certificate_validator: certificate_validator.clone(),
    });

    let format = "MDOC";
    let presentation_formatter = presentation_formatter_provider
        .get_presentation_formatter(format)
        .ok_or(MissingProviderError::Formatter(format.to_owned()))?;

    let presentation = presentation_formatter
        .extract_presentation(
            presentation,
            key_verification_presentation,
            ExtractPresentationCtx {
                mdoc_session_transcript: Some(
                    to_cbor(&session_transcript).error_while("serializing SessionTranscript")?,
                ),
                verification_protocol_type: VerificationProtocolType::IsoMdl,
                nonce: None,
                format_nonce: None,
                issuance_date: None,
                expiration_date: None,
                client_id: None,
                response_uri: None,
                verifier_key: None,
            },
        )
        .await
        .error_while("extracting presentation")?;

    let holder_identifier = presentation.issuer.ok_or(ServiceError::MappingError(
        "presentation issuer is None".to_string(),
    ))?;

    // Check if presentation is expired
    let leeway = presentation_formatter.get_leeway();
    validate_issuance_time(&presentation.issued_at, leeway)?;
    validate_expiration_time(&presentation.expires_at, leeway)?;

    let input_schemas = proof_schema.input_schemas.as_ref().await?;
    if input_schemas.is_empty() {
        return Err(ServiceError::MappingError(
            "input_schemas are empty".to_string(),
        ));
    }

    let mut remaining_requested_claims_with_mapping = HashMap::new();
    for input_schema in &input_schemas {
        let input_claims = input_schema.claim_schemas.as_ref().await?;
        let credential_schema = input_schema.credential_schema.as_ref().await?;
        let formats = credential_schema.formats.as_ref().await?;
        let format = formats.first().ok_or(ServiceError::MappingError(format!(
            "credential schema {} has no format",
            credential_schema.id
        )))?;
        let mappings = format.claim_mappings.as_ref().await?;
        let mut claims_with_mapping = Vec::with_capacity(input_claims.len());
        for input_claim_schema in &input_claims {
            let claim_schema = &input_claim_schema.schema;
            let mapping = mappings
                .iter()
                .find(|mapping| mapping.claim_schema_id == claim_schema.id)
                .ok_or(ServiceError::MappingError(format!(
                    "mapping not found for claim schema {} in format {}",
                    claim_schema.id, format.id
                )))?;
            claims_with_mapping.push((input_claim_schema.to_owned(), mapping.to_owned()));
        }
        remaining_requested_claims_with_mapping.insert(credential_schema.id, claims_with_mapping);
    }

    let credential_formatter =
        credential_formatter_provider.get_credential_formatter(&format.into())?;

    let mut proved_credentials = Vec::with_capacity(presentation.credentials.len());
    for credential in presentation.credentials {
        let received_credential = credential_formatter
            .extract_credentials(&credential, None, key_verification_credentials.clone())
            .await
            .error_while("extracting credential")?;

        // Check if "nbf" attribute of VCs and VP are valid. || Check if VCs are expired.
        validate_issuance_time(&received_credential.invalid_before, leeway)?;
        validate_expiration_time(&received_credential.valid_until, leeway)?;

        let (credential_schema_id, requested_proof_claims) = extract_matching_requested_schema(
            &received_credential,
            &remaining_requested_claims_with_mapping,
        )?;
        remaining_requested_claims_with_mapping.remove(&credential_schema_id);

        // Check if all subjects of the submitted VCs is matching the holder.
        let claim_subject = match &received_credential.subject {
            None => {
                return Err(ServiceError::ValidationError(
                    "Claim holder missing".to_owned(),
                ));
            }
            Some(identifier) => identifier,
        };

        if claim_subject != &holder_identifier {
            return Err(ServiceError::ValidationError(
                "Holder doesn't match.".to_owned(),
            ));
        }

        let mut claims = vec![];
        for (requested_proof_claim, mapping) in requested_proof_claims {
            if let Some(received_claim) = extract_matching_requested_claim(
                &received_credential,
                requested_proof_claim,
                mapping,
            )? {
                claims.push(received_claim);
            }
        }

        proved_credentials.push(ValidatedProofCredential {
            credential: received_credential,
            credential_schema_id,
            claims,
        });
    }

    if remaining_requested_claims_with_mapping
        .iter()
        .any(|(_, claims)| claims.iter().any(|(claim, _)| claim.required))
    {
        return Err(ServiceError::ValidationError(
            "Not all required claims fulfilled".to_owned(),
        ));
    }

    Ok(proved_credentials)
}

fn extract_matching_requested_schema(
    received_credential: &DetailCredential,
    remaining_requested_claims: &HashMap<
        CredentialSchemaId,
        Vec<(ProofInputClaimSchema, CredentialSchemaFormatClaimSchema)>,
    >,
) -> Result<
    (
        CredentialSchemaId,
        Vec<(ProofInputClaimSchema, CredentialSchemaFormatClaimSchema)>,
    ),
    ServiceError,
> {
    let (matching_credential_schema_id, matching_claim_schemas) = remaining_requested_claims
        .iter()
        .find(|(_, requested)| {
            requested
                .iter()
                .filter(|(schema, _)| schema.required)
                .all(|(_, mapping)| {
                    received_credential
                        .claims
                        .iter()
                        .any(|(namespace, element_value)| {
                            mapping.namespace.as_ref().is_some_and(|n| n == namespace)
                                && element_value.value.as_object().is_some_and(|value| {
                                    value.keys().any(|key| key == &mapping.technical_key)
                                })
                        })
                })
        })
        .ok_or(ServiceError::ValidationError(
            "Could not find matching requested credential schema".to_owned(),
        ))?;

    Ok((
        matching_credential_schema_id.to_owned(),
        matching_claim_schemas.to_owned(),
    ))
}

fn extract_matching_requested_claim(
    received_credential: &DetailCredential,
    requested_claim_schema: ProofInputClaimSchema,
    mapping: CredentialSchemaFormatClaimSchema,
) -> Result<Option<ValidatedProofClaim>, ServiceError> {
    let namespace = mapping.namespace.as_ref().ok_or_else(|| {
        ServiceError::MappingError(format!("missing namespace on mapping {}", mapping.id))
    })?;
    // NOTE: this only works because proof requests cannot request array elements
    // (otherwise the technical key would not match element paths)
    let found = received_credential
        .claims
        .get(namespace)
        .and_then(|elements| elements.value.as_object())
        .and_then(|elements| elements.get(&mapping.technical_key));

    // missing optional claim
    if !requested_claim_schema.required && found.is_none() {
        return Ok(None);
    }

    let value = found.ok_or(ServiceError::ValidationError(format!(
        "Required credential key '{}' missing",
        mapping.technical_key
    )))?;

    Ok(Some(ValidatedProofClaim {
        claim_schema: requested_claim_schema.schema,
        value: value.to_owned(),
    }))
}

/// proof processing on verifier's side
pub(super) async fn accept_proof(
    proof: &Proof,
    interaction: &Interaction,
    proved_credentials: Vec<ValidatedProofCredential>,
    credential_repository: &dyn CredentialRepository,
    proof_repository: &dyn ProofRepository,
    identifier_creator: &dyn IdentifierCreator,
    ecosystem_resolver: &dyn EcosystemResolver,
) -> Result<(), ServiceError> {
    let proof_schema = proof.schema.as_required_ref().await?;
    let organisation = proof_schema.organisation.as_ref().await?;

    let mut credential_schemas = HashMap::new();
    let input_schemas = proof_schema.input_schemas.as_ref().await?;
    for proof_input in &input_schemas {
        let credential_schema = proof_input.credential_schema.as_ref().await?;
        credential_schemas.insert(credential_schema.id, credential_schema.clone());
    }

    let mut model_credentials = Vec::with_capacity(proved_credentials.len());
    for ValidatedProofCredential {
        credential,
        credential_schema_id,
        claims,
    } in proved_credentials
    {
        let (issuer_identifier, issuer_identifier_relation) = identifier_creator
            .get_or_create_remote_identifier(
                &organisation,
                &credential.issuer,
                IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
                true,
                None,
                None,
            )
            .await
            .error_while("creating remote issuer identifier")?;

        let holder_details = credential
            .subject
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential subject is missing".to_string(),
            ))?;
        let (holder_identifier, _) = identifier_creator
            .get_or_create_remote_identifier(
                &organisation,
                holder_details,
                IdentifierName::PrefixForId(IdentifierRole::Holder.to_string()),
                true,
                None,
                None,
            )
            .await
            .error_while("creating remote holder identifier")?;

        let credential_schema =
            credential_schemas
                .get(&credential_schema_id)
                .ok_or(ServiceError::MappingError(
                    "credential schema not found".to_string(),
                ))?;
        let claim_schemas = credential_schema.claim_schemas.as_ref().await?;
        let formats = credential_schema
            .formats
            .as_ref()
            .await
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;
        let format = formats
            .first()
            .ok_or(ServiceError::MappingError("formats are empty".to_string()))?;
        let mappings = format
            .claim_mappings
            .as_ref()
            .await
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;
        let mappings_map = mappings.iter().map(|m| (m.claim_schema_id, m)).collect();

        let model_credential = extracted_credential_to_model(
            &claim_schemas,
            &mappings_map,
            credential_schema.to_owned(),
            claims,
            issuer_identifier,
            issuer_identifier_relation,
            Some(holder_identifier),
            proof.protocol.to_owned(),
            credential.issuance_date,
            Some(format),
        )?;

        model_credentials.push((model_credential, credential.issuer));
    }

    let ecosystems = {
        let artifacts = model_credentials
            .iter()
            .map(|(model_credential, issuer_details)| {
                let Credential::Verifier {
                    common,
                    verifier_data,
                } = model_credential
                else {
                    return Err(ServiceError::MappingError(
                        "Expected a verifier credential".into(),
                    ));
                };
                Ok(ProtocolArtifact::VerifierSubmission {
                    credential_id: common.id,
                    claims: Cow::Borrowed(&verifier_data.claims),
                    format: Cow::Borrowed(&verifier_data.format),
                    issuer_details: Cow::Borrowed(issuer_details),
                    proof_id: proof.id,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;

        ecosystem_resolver
            .resolve(interaction.id, &artifacts, None)
            .await
            .error_while("resolving ecosystems")?
    };

    let mut proof_claims = vec![];
    for ((mut model_credential, _), ecosystem) in
        model_credentials.into_iter().zip(ecosystems.per_credential)
    {
        model_credential.common_mut().ecosystem = ecosystem;

        let credential = Related::from(model_credential.clone());
        proof_claims.extend(
            model_credential
                .claims()
                .as_ref()
                .await?
                .iter()
                .cloned()
                .map(|claim| ProofClaim {
                    claim,
                    credential: credential.clone(),
                }),
        );

        credential_repository
            .create_credential(model_credential)
            .await
            .error_while("creating credential")?;
    }

    proof_repository
        .update_proof(
            &proof.id,
            UpdateProofRequest {
                state: Some(ProofStateEnum::Accepted),
                ecosystem: Some(ecosystems.ecosystem),
                ..Default::default()
            },
            None,
        )
        .await
        .error_while("updating proof")?;
    proof_repository
        .set_proof_claims(&proof.id, proof_claims)
        .await
        .error_while("setting proof claims")?;
    Ok(())
}
