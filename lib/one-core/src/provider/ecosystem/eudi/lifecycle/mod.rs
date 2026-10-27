use std::collections::HashMap;

use shared_types::{BlobId, CredentialId};

use self::dto::EudiLifecycleResultDTO;
use super::EudiEcosystem;
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialListQuery, CredentialRole, CredentialStateEnum,
    CredentialType,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::wallet_attestation::AttestationType;
use crate::proto::credential_validity_manager::dto::ChangeCredentialState;
use crate::proto::wallet_instance::WalletUnitStatusCheckResponse;
use crate::provider::blob_storage::BlobStorage;
use crate::provider::ecosystem::error::EcosystemError;
use crate::service::credential::dto::WalletUnitAttestationDTO;

mod dto;
#[cfg(test)]
mod test;

const PAGE_SIZE: u32 = 1000;

impl EudiEcosystem {
    /// Checks every accepted credential this core issued into the EUDI ecosystem whose schema
    /// opted into WUA lifetime monitoring: if the wallet instance attestation or the wallet unit
    /// attestation that was accepted at issuance time has since been revoked, the credential must
    /// not stay valid either.
    ///
    /// The two attestations differ in scope: a revoked WIA invalidates the wallet instance and
    /// with it a whole issued batch, while a revoked WUA only invalidates the single credential
    /// it was issued for.
    pub(super) async fn run_lifecycle_check(&self) -> Result<serde_json::Value, EcosystemError> {
        // batch items rather than batch parents: the WUA is written per issued credential, so
        // only the items carry one, while the WIA is taken from the parent
        let filtering = CredentialFilterValue::Roles(vec![CredentialRole::Issuer]).condition()
            & CredentialFilterValue::States(vec![
                CredentialStateEnum::Accepted,
                CredentialStateEnum::Suspended {
                    suspend_end_date: None,
                },
            ])
            & CredentialFilterValue::Types(vec![CredentialType::Single, CredentialType::BatchItem])
            & CredentialFilterValue::Deleted(false)
            & CredentialFilterValue::Ecosystems(vec![self.config_id.to_owned()])
            & CredentialFilterValue::WuaMonitorCredentialLifetime(true);

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let mut result = EudiLifecycleResultDTO::default();
        let mut cached_wia_status: HashMap<CredentialId, bool> = HashMap::new();
        let mut page = 0;

        loop {
            tracing::debug!("Checking credentials page {}", page);
            let credentials = self
                .credential_repository
                .get_credential_list(CredentialListQuery {
                    include_count: false,
                    pagination: Some(ListPagination {
                        page,
                        page_size: PAGE_SIZE,
                    }),
                    filtering: Some(filtering.clone()),
                    ..Default::default()
                })
                .await
                .error_while("getting issued credentials")?;

            if credentials.values.is_empty() {
                break;
            }

            for credential in &credentials.values {
                let issuer = credential.issuer_credential()?;
                result.total_checks += 1;

                // a batch shares one WIA and is revoked as a whole, through its parent
                let main_credential = match credential {
                    Credential::IssuerBatchItem { parent, .. } => &parent.as_ref().await?,
                    _ => credential,
                };

                let wia_revoked = match cached_wia_status.get(&main_credential.common().id) {
                    Some(revoked) => *revoked,
                    None => {
                        let wia_blob_id = match main_credential {
                            Credential::IssuerSingle {
                                wallet_instance_attestation_blob_id,
                                ..
                            }
                            | Credential::IssuerBatchParent {
                                wallet_instance_attestation_blob_id,
                                ..
                            } => *wallet_instance_attestation_blob_id,
                            _ => None,
                        };
                        let revoked = self
                            .attestation_revoked(
                                main_credential,
                                blob_storage.as_ref(),
                                wia_blob_id,
                                AttestationType::WalletInstanceAttestation,
                            )
                            .await?;
                        cached_wia_status.insert(main_credential.common().id, revoked);

                        if revoked {
                            self.revoke_credential(main_credential, &mut result).await;
                        }
                        revoked
                    }
                };

                // the whole batch is revoked already, the individual item does not matter
                if wia_revoked {
                    continue;
                }

                // the WUA belongs to this credential alone, so only it is revoked
                if self
                    .attestation_revoked(
                        credential,
                        blob_storage.as_ref(),
                        issuer.data.wallet_key_attestation_blob_id,
                        AttestationType::KeyAttestation,
                    )
                    .await?
                {
                    self.revoke_credential(credential, &mut result).await;
                }
            }

            page += 1;
        }
        result_to_value(result)
    }

    /// Revokes a credential whose wallet has been revoked. The revocation is published through the
    /// credential's revocation method, which for a batch parent also updates every batch item.
    ///
    /// A failure is only recorded in `failures`, the check moves on to the next credential and
    /// reports all failures once at the end of the run.
    async fn revoke_credential(
        &self,
        credential: &Credential,
        result: &mut EudiLifecycleResultDTO,
    ) {
        let credential_id = credential.common().id;
        match self
            .credential_validity_manager
            .change_credential_state(&credential_id, ChangeCredentialState::Revoked)
            .await
        {
            Ok(()) => result.revoked_credential_ids.push(credential_id),
            Err(error) => {
                tracing::warn!(
                    "Failed to revoke credential {}: `{:?}`",
                    credential_id,
                    error
                );
                result.failed_credential_ids.push(credential_id)
            }
        }
    }

    /// `true` only when the attestation stored in `blob_id` is known to be revoked. A missing or expired
    /// attestation, a missing status list entry or an inconclusive check (network failure,
    /// unresolvable issuer) never revokes a credential.
    async fn attestation_revoked(
        &self,
        credential: &Credential,
        blob_storage: &dyn BlobStorage,
        blob_id: Option<BlobId>,
        r#type: AttestationType,
    ) -> Result<bool, EcosystemError> {
        let Some(blob_id) = blob_id else {
            return Ok(false);
        };

        let Some(blob) = blob_storage
            .get(&blob_id)
            .await
            .error_while("getting attestation blob")?
        else {
            return Ok(false);
        };

        // both attestation blobs carry the token under the same key, the WIA just adds
        // display information on top, which is of no interest here
        let attestation = serde_json::from_slice::<WalletUnitAttestationDTO>(&blob.value)
            .map_err(|error| {
                EcosystemError::MappingError(format!(
                    "failed to deserialize attestation blob: {error}"
                ))
            })?
            .attestation;

        match self
            .wallet_unit_proto
            .check_attestation_status(&attestation, r#type)
            .await
            .map(|check_result| check_result.status)
        {
            Ok(WalletUnitStatusCheckResponse::Revoked) => Ok(true),
            Ok(WalletUnitStatusCheckResponse::Active)
            | Ok(WalletUnitStatusCheckResponse::Expired) => Ok(false),
            Err(error) => {
                tracing::warn!(
                    "Could not check {} status of credential `{}`: {error}",
                    r#type,
                    credential.common().id
                );
                Ok(false)
            }
        }
    }
}

fn result_to_value(result: EudiLifecycleResultDTO) -> Result<serde_json::Value, EcosystemError> {
    serde_json::to_value(result)
        .map_err(|error| EcosystemError::MappingError(format!("serializing result: {error}")))
}
