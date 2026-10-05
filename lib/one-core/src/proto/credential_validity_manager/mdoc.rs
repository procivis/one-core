use super::{CredentialValidityCheckResult, CredentialValidityManagerImpl, Error};
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::common::SortDirection;
use crate::model::credential::{
    Clearable, Credential, CredentialFilterValue, CredentialStateEnum, CredentialType,
    SortableCredentialColumn, UpdateCredentialRequest,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::{ListPagination, ListQuery, ListSorting};
use crate::model::relation::OptionalRelatedExt;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;

impl CredentialValidityManagerImpl {
    pub(crate) async fn update_mdoc(
        &self,
        credential: &Credential,
        force_refresh: bool,
    ) -> Result<CredentialValidityCheckResult, Error> {
        let detail_credential = self.credential_to_detail_credential(credential).await?;

        if !force_refresh && !credential_requires_update(&detail_credential) {
            return Ok(CredentialValidityCheckResult {
                credential_id: credential.common.id,
                status: CredentialStateEnum::Accepted,
                success: true,
                reason: None,
            });
        }

        let interaction = credential
            .common
            .interaction
            .as_ref()
            .ok_or(Error::MappingError("Missing interaction".to_string()))?
            .as_ref()
            .await?;

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&credential.common.protocol)?;

        let refresh_credential_id = if credential.r#type == CredentialType::BatchParent {
            None
        } else {
            Some(credential.common.id)
        };
        let new_state = match protocol
            .holder_refresh_credential(&interaction, refresh_credential_id)
            .await
        {
            Ok(_) => CredentialStateEnum::Accepted,
            Err(IssuanceProtocolError::RefreshNotPossible)
                if credential_expired(&detail_credential) =>
            {
                CredentialStateEnum::Expired
            }
            Err(err) => {
                tracing::warn!(%err, "Credential refresh failure");
                if credential_expired(&detail_credential) {
                    CredentialStateEnum::Suspended
                } else {
                    CredentialStateEnum::Accepted
                }
            }
        };

        if new_state != credential.common.state {
            self.credential_repository
                .update_credential(
                    credential.common.id,
                    UpdateCredentialRequest {
                        state: Some(new_state),
                        suspend_end_date: Clearable::DontTouch,
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating credential")?;
        }

        Ok(CredentialValidityCheckResult {
            credential_id: credential.common.id,
            status: new_state,
            success: true,
            reason: None,
        })
    }

    async fn credential_to_detail_credential(
        &self,
        credential: &Credential,
    ) -> Result<DetailCredential, Error> {
        let credential_schema = credential.common.schema.as_ref().await?;

        let (credential_blob_id, credential_format) = match credential.r#type {
            CredentialType::Single | CredentialType::BatchItem => {
                let credential_blob_id = credential.credential_blob_id.ok_or_else(|| {
                    Error::MappingError(format!(
                        "No credential blob found for credential {}",
                        credential.common.id
                    ))
                })?;
                let credential_format =
                    credential.format.as_required_ref().await?.format.to_owned();
                (credential_blob_id, credential_format)
            }
            CredentialType::BatchParent => {
                let batch_items = self
                    .credential_repository
                    .get_credential_list(ListQuery {
                        include_count: false,
                        filtering: Some(
                            CredentialFilterValue::ParentCredential(credential.common.id)
                                .condition()
                                & CredentialFilterValue::Deleted(false),
                        ),
                        sorting: Some(ListSorting {
                            column: SortableCredentialColumn::CreatedDate,
                            direction: Some(SortDirection::Descending),
                        }),
                        pagination: Some(ListPagination {
                            page: 0,
                            page_size: 1,
                        }),
                        ..Default::default()
                    })
                    .await
                    .error_while("getting batch items")?
                    .values;

                let Some(batch_item) = batch_items.first() else {
                    return Err(Error::MappingError(format!(
                        "No batch items found for credential {}",
                        credential.common.id
                    )));
                };
                let credential_blob_id = batch_item.credential_blob_id.ok_or_else(|| {
                    Error::MappingError(format!(
                        "Batch items {} has no credential blob id",
                        batch_item.common.id
                    ))
                })?;
                let credential_format =
                    batch_item.format.as_required_ref().await?.format.to_owned();
                (credential_blob_id, credential_format)
            }
        };
        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;
        let credential_bytes = blob_storage
            .get(&credential_blob_id)
            .await
            .error_while("getting credential blob")?
            .ok_or(Error::MappingError("credential blob missing".to_string()))?
            .value;
        let credential_str = String::from_utf8(credential_bytes)
            .map_err(|e| Error::MappingError(e.to_string()))?
            .into();

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&credential_format)?;

        let detail_credential = formatter
            .extract_credentials_unverified(&credential_str, Some(&credential_schema))
            .await
            .error_while("extracting credential")?;
        Ok(detail_credential)
    }
}

fn credential_expired(detail_credential: &DetailCredential) -> bool {
    let now = crate::clock::now_utc();

    if let Some(valid_until) = detail_credential.valid_until {
        return valid_until < now;
    }

    false
}

fn credential_requires_update(detail_credential: &DetailCredential) -> bool {
    let now = crate::clock::now_utc();

    if let Some(update_at) = detail_credential.update_at {
        return update_at < now;
    }

    credential_expired(detail_credential)
}
