use futures::FutureExt;
use one_dto_mapper::convert_inner;
use shared_types::BlobId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::mapper::encode_cbor_base64;
use crate::mapper::openid4vp::credential_from_proved;
use crate::model::common::LockType;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRelations, ProofStateEnum, UpdateProofRequest};
use crate::model::validity_credential::Mdoc;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::AcceptProofResult;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::validator::throw_if_proof_state_not_in;

#[expect(clippy::too_many_arguments)]
pub(crate) async fn persist_accepted_proof(
    proof: &Proof,
    accept_proof_result: AcceptProofResult,
    organisation: &Organisation,
    proof_blob_id: BlobId,
    proof_repository: &dyn ProofRepository,
    did_repository: &dyn DidRepository,
    certificate_repository: &dyn CertificateRepository,
    identifier_repository: &dyn IdentifierRepository,
    certificate_validator: &dyn CertificateValidator,
    did_method_provider: &dyn DidMethodProvider,
    key_repository: &dyn KeyRepository,
    credential_repository: &dyn CredentialRepository,
    validity_credential_repository: &dyn ValidityCredentialRepository,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    transaction_manager: &dyn TransactionManager,
) -> Result<(), ServiceError> {
    transaction_manager
        .tx(async {
            // Lock proof to avoid concurrent updates
            let proof = proof_repository
                .get_proof(
                    &proof.id,
                    &ProofRelations::default(),
                    Some(LockType::Update),
                )
                .await?
                .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(
                    proof.id,
                )))?;
            // Double-check that proof is in the expected state
            throw_if_proof_state_not_in(
                &proof,
                &[ProofStateEnum::Pending, ProofStateEnum::Requested],
            )
            .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

            for proved_credential in accept_proof_result.proved_credentials {
                let credential_id = proved_credential.credential.id;
                let mdoc_mso = proved_credential.mdoc_mso.to_owned();

                let credential = credential_from_proved(
                    proved_credential,
                    organisation,
                    did_repository,
                    certificate_repository,
                    identifier_repository,
                    certificate_validator,
                    did_method_provider,
                    key_repository,
                    key_algorithm_provider,
                )
                .await?;

                credential_repository.create_credential(credential).await?;

                if let Some(mso) = mdoc_mso {
                    let mso_cbor = encode_cbor_base64(mso)
                        .map_err(|e| OpenID4VCError::Other(e.to_string()))?;

                    validity_credential_repository
                        .insert(
                            Mdoc {
                                id: Uuid::new_v4(),
                                created_date: OffsetDateTime::now_utc(),
                                credential: mso_cbor.into_bytes(),
                                linked_credential_id: credential_id,
                            }
                            .into(),
                        )
                        .await?;
                }
            }

            proof_repository
                .set_proof_claims(&proof.id, convert_inner(accept_proof_result.proved_claims))
                .await?;

            proof_repository
                .update_proof(
                    &proof.id,
                    UpdateProofRequest {
                        state: Some(ProofStateEnum::Accepted),
                        proof_blob_id: Some(Some(proof_blob_id)),
                        ..Default::default()
                    },
                    None,
                )
                .await?;
            Ok::<_, ServiceError>(())
        }
        .boxed())
        .await??;
    Ok(())
}
