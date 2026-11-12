use std::collections::HashMap;

use coset::iana::HeaderParameter;
use coset::{HeaderBuilder, ProtectedHeader};
use standardized_types::openid4vp::VerifierInfoAttestation;

use super::common::{DeviceRequest, DocRequest, ItemsRequest};
use crate::error::ContextWithErrorCode;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::certificate::Certificate;
use crate::model::identifier::Identifier;
use crate::model::identifier_trust_information::IdentifierTrustInformation;
use crate::model::key::Key;
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::proto::cose::{CoseSign1, CoseSign1Builder};
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::mdoc_formatter::util::{
    EmbeddedCbor, build_algorithm_header_value,
};
use crate::provider::credential_formatter::mdoc_formatter::{
    HeaderBuilderExt, build_x5chain_header_value,
};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::presentation_formatter::mso_mdoc::model::ReaderAuthentication;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::SessionTranscript;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::mapper::gather_registration_certificates;

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
