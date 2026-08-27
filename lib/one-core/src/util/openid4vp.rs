use futures::FutureExt;
use one_dto_mapper::convert_inner;
use shared_types::{BlobId, EcosystemId};

use crate::error::ContextWithErrorCode;
use crate::mapper::openid4vp::credential_from_proved;
use crate::model::common::LockType;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::openid4vp_proof_validator::ValidatedProofResult;
use crate::proto::transaction_manager::{IsolationLevel, TransactionManager};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;
use crate::validator::throw_if_proof_state_not_in;

#[expect(clippy::too_many_arguments)]
pub(crate) async fn persist_accepted_proof(
    proof: &Proof,
    validated_proof_result: ValidatedProofResult,
    organisation: &Organisation,
    proof_blob_id: BlobId,
    ecosystem: Option<Option<EcosystemId>>,
    proof_repository: &dyn ProofRepository,
    credential_repository: &dyn CredentialRepository,
    transaction_manager: &dyn TransactionManager,
    identifier_creator: &dyn IdentifierCreator,
) -> Result<(), ServiceError> {
    transaction_manager
        .tx_with_config(
            async {
                // Lock proof to avoid concurrent updates
                let proof = proof_repository
                    .get_proof(&proof.id, Some(LockType::Update))
                    .await
                    .error_while("getting proof")?;
                // Double-check that proof is in the expected state
                throw_if_proof_state_not_in(
                    &proof,
                    &[ProofStateEnum::Pending, ProofStateEnum::Requested],
                )?;

                let (credentials, claims) = validated_proof_result.into_credentials_and_claims();
                for proved_credential in credentials {
                    let credential =
                        credential_from_proved(identifier_creator, proved_credential, organisation)
                            .await?;

                    credential_repository
                        .create_credential(credential)
                        .await
                        .error_while("crating credential")?;
                }

                proof_repository
                    .set_proof_claims(&proof.id, convert_inner(claims))
                    .await
                    .error_while("setting proof claims")?;

                proof_repository
                    .update_proof(
                        &proof.id,
                        UpdateProofRequest {
                            state: Some(ProofStateEnum::Accepted),
                            proof_blob_id: Some(Some(proof_blob_id)),
                            ecosystem,
                            ..Default::default()
                        },
                        None,
                    )
                    .await
                    .error_while("updating proof")?;
                Ok::<_, ServiceError>(())
            }
            .boxed(),
            Some(IsolationLevel::ReadCommitted),
            None,
        )
        .await
        .error_while("persisting proof")??;
    Ok(())
}
