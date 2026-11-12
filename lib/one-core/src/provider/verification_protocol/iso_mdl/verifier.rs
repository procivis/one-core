use std::collections::HashMap;
use std::sync::Arc;

use coset::iana::HeaderParameter;
use coset::{HeaderBuilder, ProtectedHeader};
use standardized_types::openid4vp::VerifierInfoAttestation;

use super::common::{DeviceRequest, DocRequest, ItemsRequest};
use crate::error::{ContextWithErrorCode, ErrorCode};
use crate::mapper::{NESTED_CLAIM_MARKER, encode_cbor_base64url};
use crate::model::certificate::Certificate;
use crate::model::history::HistoryErrorMetadata;
use crate::model::identifier::Identifier;
use crate::model::identifier_trust_information::IdentifierTrustInformation;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::model::relation::OptionalRelatedExt;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::cose::{CoseSign1, CoseSign1Builder};
use crate::proto::ecosystem_resolver::EcosystemResolver;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::mdoc_formatter::util::{
    EmbeddedCbor, build_algorithm_header_value,
};
use crate::provider::credential_formatter::mdoc_formatter::{
    HeaderBuilderExt, build_x5chain_header_value,
};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::mso_mdoc::model::{
    DeviceResponse, ReaderAuthentication,
};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::SessionTranscript;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::set_proof_to_error;
use crate::provider::verification_protocol::mapper::gather_registration_certificates;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::proof_repository::ProofRepository;

pub(crate) struct IsoMdlVerifier {
    pub identifier: Identifier,
    pub key: Key,
    pub certificate: Certificate,
    pub auth_fn: AuthenticationFn,
}

pub(super) async fn create_device_request(
    schema: &ProofSchema,
    verifier: Option<&IsoMdlVerifier>,
    session_transcript: &SessionTranscript,
    blob_storage_provider: &dyn BlobStorageProvider,
) -> Result<DeviceRequest, VerificationProtocolError> {
    let registration_certificates = if let Some(verifier) = &verifier {
        gather_registration_certificates(&verifier.identifier, blob_storage_provider).await?
    } else {
        vec![]
    };

    let mut doc_requests = vec![];
    let input_schemas = schema.input_schemas.as_ref().await?;
    for input_schema in &input_schemas {
        doc_requests.push(
            proof_input_schema_to_doc_request(
                input_schema,
                session_transcript,
                verifier,
                &registration_certificates,
            )
            .await?,
        );
    }

    Ok(DeviceRequest {
        version: Default::default(),
        doc_requests,
    })
}

async fn proof_input_schema_to_doc_request(
    input: &ProofInputSchema,
    session_transcript: &SessionTranscript,
    verifier: Option<&IsoMdlVerifier>,
    registration_certificates: &[(IdentifierTrustInformation, VerifierInfoAttestation)],
) -> Result<DocRequest, VerificationProtocolError> {
    let proof_claim_schemas = input.claim_schemas.as_ref().await?;
    let credential_schema = input.credential_schema.as_ref().await?;
    let formats = credential_schema.formats.as_ref().await?;
    let format = formats
        .iter()
        .find(|format| input.formats.contains(&format.format))
        .ok_or(VerificationProtocolError::Failed(
            "proof input has no format of its credential schema".to_string(),
        ))?;
    let mappings = format.claim_mappings.as_ref().await?;
    let mappings_by_schema_id: HashMap<_, _> = mappings
        .into_iter()
        .map(|m| (m.claim_schema_id, m))
        .collect();

    let mut name_spaces = HashMap::new();
    for proof_claim_schema in &proof_claim_schemas {
        let mapping = mappings_by_schema_id
            .get(&proof_claim_schema.schema.id)
            .ok_or_else(|| {
                VerificationProtocolError::Failed(format!(
                    "no mapping found for schema {} and format {}",
                    proof_claim_schema.schema.id, format.id
                ))
            })?;
        let Some(namespace) = &mapping.namespace else {
            return Err(VerificationProtocolError::Failed(format!(
                "mapping {} has no namespace",
                proof_claim_schema.schema.id
            )));
        };
        let element_identifier =
            if let Some((root, _)) = mapping.technical_key.rsplit_once(NESTED_CLAIM_MARKER) {
                root
            } else {
                &mapping.technical_key
            };

        name_spaces
            .entry(namespace.to_owned())
            .or_insert_with(HashMap::new)
            .insert(element_identifier.to_owned(), true);
    }

    let doc_type = format.ecosystem_schema_id.to_owned();
    let request_info = registration_certificates
        .iter()
        .find(|(info, _)| {
            info.allowed_verification_types.iter().any(|verification| {
                verification.format == "mso_mdoc" && verification.schema_id == doc_type
            })
        })
        .map(|(_, attestation)| {
            HashMap::from([(
                "eUWrprc".to_string(),
                ciborium::Value::Text(attestation.data.to_owned()),
            )])
        });

    let items_request = EmbeddedCbor::new(ItemsRequest {
        doc_type,
        name_spaces,
        request_info,
    })?;

    let reader_auth = match verifier {
        None => None,
        Some(verifier) => Some(
            prepare_reader_auth(
                session_transcript.to_owned(),
                items_request.clone(),
                verifier,
            )
            .await?,
        ),
    };

    Ok(DocRequest {
        items_request,
        reader_auth,
    })
}

pub(super) async fn prepare_reader_auth(
    session_transcript: SessionTranscript,
    items_request: EmbeddedCbor<ItemsRequest>,
    verifier: &IsoMdlVerifier,
) -> Result<CoseSign1, VerificationProtocolError> {
    let algorithm = verifier
        .auth_fn
        .get_key_algorithm()
        .error_while("getting key algorithm")?;

    let reader_authentication = ReaderAuthentication {
        session_transcript,
        items_request,
    };
    let reader_authentication_bytes = EmbeddedCbor::new(reader_authentication)?.into_bytes();

    let protected_headers = HeaderBuilder::new()
        .algorithm(
            build_algorithm_header_value(algorithm).error_while("creating algorithm header")?,
        )
        .build();

    let unprotected_headers = HeaderBuilder::new()
        .add_header(
            HeaderParameter::X5Chain,
            build_x5chain_header_value(&verifier.certificate.chain, None)
                .await
                .error_while("creating x5chain")?,
        )
        .build();

    let cose_sign1 = CoseSign1Builder::new()
        .protected(ProtectedHeader {
            original_data: None,
            header: protected_headers,
        })
        .unprotected(unprotected_headers)
        .try_create_detached_signature_with_provider(
            &reader_authentication_bytes,
            &[],
            verifier.auth_fn.as_ref(),
        )
        .await
        .error_while("creating signature")?
        .build();

    Ok(cose_sign1.into())
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn process_device_response(
    device_response: DeviceResponse,
    session_transcript: SessionTranscript,
    proof: &Proof,
    interaction: &Interaction,
    credential_formatter_provider: &dyn CredentialFormatterProvider,
    presentation_formatter_provider: &dyn PresentationFormatterProvider,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: &dyn CredentialRepository,
    proof_repository: &dyn ProofRepository,
    certificate_validator: Arc<dyn CertificateValidator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    ecosystem_resolver: &dyn EcosystemResolver,
    revocation_method_provider: &dyn RevocationMethodProvider,
) -> Result<(), VerificationProtocolError> {
    let empty_documents = device_response
        .documents
        .as_ref()
        .is_some_and(|documents| documents.is_empty());
    let has_errors = device_response
        .document_errors
        .as_ref()
        .is_some_and(|errors| !errors.is_empty());

    if !empty_documents && has_errors {
        let error_metadata = HistoryErrorMetadata {
            error_code: ErrorCode::BR_0000,
            message: format!(
                "Response received with documents and document errors: {device_response:?}"
            ),
        };
        set_proof_to_error(proof_repository, &proof.id, error_metadata).await;
        return Ok(());
    }

    if empty_documents {
        if has_errors {
            proof_repository
                .update_proof(
                    &proof.id,
                    UpdateProofRequest {
                        state: Some(ProofStateEnum::Rejected),
                        ..Default::default()
                    },
                    None,
                )
                .await
                .error_while("updating proof")?;
        } else {
            let error_metadata = HistoryErrorMetadata {
                error_code: ErrorCode::BR_0000,
                message: "Response documents are empty but no errors are provided".to_string(),
            };
            set_proof_to_error(proof_repository, &proof.id, error_metadata).await;
        }

        return Ok(());
    }

    if let Err(error) = fill_proof_claims_and_credentials(
        device_response,
        proof,
        interaction,
        session_transcript,
        credential_formatter_provider,
        presentation_formatter_provider,
        did_method_provider,
        key_algorithm_provider,
        credential_repository,
        proof_repository,
        certificate_validator,
        identifier_creator,
        ecosystem_resolver,
        revocation_method_provider,
    )
    .await
    {
        tracing::info!(%error, "mDL proof parsing failure");
        set_proof_to_error(proof_repository, &proof.id, (&error).into()).await;
    }

    Ok(())
}

#[expect(clippy::too_many_arguments)]
async fn fill_proof_claims_and_credentials(
    device_response: DeviceResponse,
    proof: &Proof,
    interaction: &Interaction,
    session_transcript: SessionTranscript,
    credential_formatter_provider: &dyn CredentialFormatterProvider,
    presentation_formatter_provider: &dyn PresentationFormatterProvider,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: &dyn CredentialRepository,
    proof_repository: &dyn ProofRepository,
    certificate_validator: Arc<dyn CertificateValidator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    ecosystem_resolver: &dyn EcosystemResolver,
    revocation_method_provider: &dyn RevocationMethodProvider,
) -> Result<(), VerificationProtocolError> {
    let proof_schema = proof.schema.as_required_ref().await?;

    let encoded =
        encode_cbor_base64url(&device_response).error_while("encoding device response")?;

    let proved_credentials = super::verify_proof::validate_proof(
        &proof_schema,
        &encoded,
        session_transcript,
        credential_formatter_provider,
        presentation_formatter_provider,
        key_algorithm_provider,
        did_method_provider,
        certificate_validator,
        revocation_method_provider,
    )
    .await
    .error_while("validating proof")?;

    super::verify_proof::accept_proof(
        proof,
        interaction,
        proved_credentials,
        credential_repository,
        proof_repository,
        identifier_creator.as_ref(),
        ecosystem_resolver,
    )
    .await
    .error_while("accepting proof")?;

    Ok(())
}
