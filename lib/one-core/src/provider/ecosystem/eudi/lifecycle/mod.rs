use std::collections::{HashMap, HashSet};

use shared_types::{BlobId, CredentialId, CredentialSchemaId};

use self::dto::EudiLifecycleResultDTO;
use super::EudiEcosystem;
use crate::config::core_config::BlobStorageType;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin};
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialListQuery, CredentialRole, CredentialStateEnum,
    CredentialType,
};
use crate::model::list_filter::{ListFilterCondition, ListFilterValue};
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
    /// Checks every accepted PID this core issued into the EUDI ecosystem: if the wallet
    /// instance attestation or the wallet unit attestation that was accepted at issuance time
    /// has since been revoked, the PID must not stay valid either.
    ///
    /// The two attestations differ in scope: a revoked WIA invalidates the wallet instance and
    /// with it a whole issued batch, while a revoked WUA only invalidates the single credential
    /// it was issued for.
    pub(super) async fn run_lifecycle_check(&self) -> Result<serde_json::Value, EcosystemError> {
        let pid_schema_ids: Vec<_> = self
            .params
            .credential_schemas
            .iter()
            .flat_map(|schema| schema.pid_schema_ids.iter().cloned())
            .collect();

        if pid_schema_ids.is_empty() {
            return result_to_value(EudiLifecycleResultDTO::default());
        }

        // batch items rather than batch parents: the WUA is written per issued credential, so
        // only the items carry one, while the WIA is copied from the parent onto every item
        let filtering = CredentialFilterValue::Roles(vec![CredentialRole::Issuer]).condition()
            & CredentialFilterValue::States(vec![
                CredentialStateEnum::Accepted,
                CredentialStateEnum::Suspended,
            ])
            & CredentialFilterValue::Types(vec![CredentialType::Single, CredentialType::BatchItem])
            & CredentialFilterValue::Deleted(false)
            & CredentialFilterValue::Ecosystems(vec![self.config_id.to_owned()])
            & ListFilterCondition::Or(
                pid_schema_ids
                    .into_iter()
                    .map(|schema_id| CredentialFilterValue::SchemaId(schema_id).condition())
                    .collect(),
            );

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let mut result = EudiLifecycleResultDTO::default();
        let mut cached_wia_status: HashMap<CredentialId, bool> = HashMap::new();
        // schemas already reported as not supporting revocation, so that the warning is printed
        // once per run and schema rather than once per PID
        let mut schemas_without_revocation: HashSet<CredentialSchemaId> = HashSet::new();
        let mut page = 0;

        loop {
            tracing::debug!("Checking PIDs page {}", page);
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
                .error_while("getting issued PIDs")?;

            if credentials.values.is_empty() {
                break;
            }

            for credential in &credentials.values {
                result.total_checks += 1;

                // a batch shares one WIA and is revoked as a whole, through its parent
                let main_credential = match &credential.parent {
                    Some(parent) => &parent.as_ref().await?,
                    None => credential,
                };

                let wia_revoked = match cached_wia_status.get(&main_credential.id) {
                    Some(revoked) => *revoked,
                    None => {
                        let revoked = self
                            .attestation_revoked(
                                main_credential,
                                blob_storage.as_ref(),
                                credential.wallet_instance_attestation_blob_id,
                                AttestationType::WalletInstanceAttestation,
                            )
                            .await?;
                        cached_wia_status.insert(main_credential.id, revoked);

                        if revoked {
                            self.revoke_pid(
                                main_credential,
                                &mut result,
                                &mut schemas_without_revocation,
                            )
                            .await;
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
                        credential.wallet_key_attestation_blob_id,
                        AttestationType::KeyAttestation,
                    )
                    .await?
                {
                    self.revoke_pid(credential, &mut result, &mut schemas_without_revocation)
                        .await;
                }
            }

            page += 1;
        }

        result_to_value(result)
    }

    /// Revokes a PID whose wallet has been revoked. The revocation is published through the
    /// credential's revocation method, which for a batch parent also updates every batch item.
    async fn revoke_pid(
        &self,
        credential: &Credential,
        result: &mut EudiLifecycleResultDTO,
        schemas_without_revocation: &mut HashSet<CredentialSchemaId>,
    ) {
        let Err(error) = self
            .credential_validity_manager
            .change_credential_state(&credential.id, ChangeCredentialState::Revoked)
            .await
        else {
            result.revoked_credential_ids.push(credential.id);
            return;
        };

        result.failed_credential_ids.push(credential.id);

        if error.error_code() == ErrorCode::BR_0098 {
            let schema_id = credential.schema.id();
            if schemas_without_revocation.insert(schema_id) {
                tracing::warn!(
                    "PIDs of credential schema {schema_id} cannot be revoked because the schema does \
                     not support revocation - this is not EUDI compliant"
                );
            }
        } else {
            tracing::warn!("Failed to revoke PID `{}`: {error}", credential.id);
        }

        if credential.r#type != CredentialType::BatchParent {
            // Only batch parents can be flagged as expiring
            return;
        }

        if let Err(error) = self
            .credential_validity_manager
            .change_credential_state(&credential.id, ChangeCredentialState::Expiring)
            .await
        {
            tracing::warn!(
                "Failed to flag PID `{}` as expiring: {error}",
                credential.id
            );
        }
    }

    /// `true` only when the attestation stored in `blob_id` is known to be revoked. A missing or expired
    /// attestation, a missing status list entry or an inconclusive check (network failure,
    /// unresolvable issuer) never revokes a PID.
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
                    credential.id
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
