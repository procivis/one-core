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
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::openid4vp_proof_validator::ValidatedProofResult;
use crate::proto::transaction_manager::{IsolationLevel, TransactionManager};
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::validator::throw_if_proof_state_not_in;

#[expect(clippy::too_many_arguments)]
pub(crate) async fn persist_accepted_proof(
    proof: &Proof,
    validated_proof_result: ValidatedProofResult,
    organisation: &Organisation,
    proof_blob_id: BlobId,
    proof_repository: &dyn ProofRepository,
    credential_repository: &dyn CredentialRepository,
    validity_credential_repository: &dyn ValidityCredentialRepository,
    transaction_manager: &dyn TransactionManager,
    identifier_creator: &dyn IdentifierCreator,
) -> Result<(), ServiceError> {
    transaction_manager
        .tx_with_config(
            async {
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

                let (credentials, claims) = validated_proof_result.into_credentials_and_claims();
                for proved_credential in credentials {
                    let credential_id = proved_credential.credential.id;
                    let mdoc_mso = proved_credential.mdoc_mso.to_owned();

                    let credential =
                        credential_from_proved(identifier_creator, proved_credential, organisation)
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
                    .set_proof_claims(&proof.id, convert_inner(claims))
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
            .boxed(),
            Some(IsolationLevel::ReadCommitted),
            None,
        )
        .await??;
    Ok(())
}
