use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use shared_types::SignerId;
use uuid::Uuid;

use super::SignatureService;
use crate::config::core_config::BlobStorageType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::blob::{Blob, BlobType};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::revocation_list::{RevocationListEntityInfo, RevocationListEntryFilterValue};
use crate::proto::session_provider::SessionExt;
use crate::provider::signer::dto::{CreateSignatureResponseDTO, Issuer};
use crate::repository::error::DataLayerError;
use crate::service::signature::dto::{CreateSignatureRequestDTO, SignatureStatusInfo};
use crate::service::signature::error::SignatureServiceError;
use crate::validator::permissions::RequiredPermissions;
use crate::validator::throw_if_org_id_not_matching_session;

impl SignatureService {
    pub async fn sign(
        &self,
        request: CreateSignatureRequestDTO,
    ) -> Result<CreateSignatureResponseDTO, SignatureServiceError> {
        let signer = self.signer_provider.get(&request.signer)?;
        let signature_type = request.signer.to_owned();
        let issuer = self
            .identifier_repository
            .get(request.issuer)
            .await
            .error_while("Loading issuer identifier")?;
        let organisation_id = issuer.organisation.id();
        throw_if_org_id_not_matching_session(&organisation_id, &*self.session_provider)
            .error_while("validating organisation")?;

        if !signer
            .get_capabilities()
            .supported_identifiers
            .contains(&issuer.data.r#type().into())
        {
            return Err(SignatureServiceError::UnsupportedIdentifierType(
                issuer.data.r#type(),
            ));
        }

        let issuer_id = issuer.id;

        // Sign permissions are enforced by the `PermissionChecked` wrapper
        // around each signer.
        let result = signer
            .sign(
                Issuer::Identifier {
                    identifier: Box::new(issuer),
                    certificate: request.issuer_certificate,
                    key: request.issuer_key,
                },
                request.into(),
            )
            .await
            .error_while("signing signature request")?;

        if let Err(error) = self
            .store_sign_history(&result, &signature_type, issuer_id, organisation_id)
            .await
        {
            tracing::warn!("Failed to write history entry: {}", error);
        }

        tracing::info!(
            "Created signature {} using identifier {}: signature type `{}`",
            result.id,
            issuer_id,
            signature_type
        );
        Ok(result)
    }

    pub async fn revoke(&self, id: Uuid) -> Result<(), SignatureServiceError> {
        let (signer_name, signer) = self.signer_provider.get_for_signature_id(id).await?;
        RequiredPermissions::at_least_one(signer.get_capabilities().revoke_required_permissions)
            .check(&*self.session_provider)
            .error_while("validating provider required permissions")?;

        let Some(revocation_method) = signer
            .revocation_method()
            .error_while("getting signer revocation method")?
        else {
            return Err(SignatureServiceError::RevocationNotSupported);
        };
        let list = self
            .revocation_list_repository
            .get_revocation_list_by_entry_id(id.into())
            .await
            .map_err(|error| match error {
                DataLayerError::EntityNotFound { .. } => {
                    SignatureServiceError::InvalidSignatureId(id)
                }
                error => error.error_while("getting revocation list entries").into(),
            })?;
        let issuer = list.issuer_identifier.as_ref().await?;
        throw_if_org_id_not_matching_session(&issuer.organisation.id(), &*self.session_provider)
            .error_while("validating organisation")?;

        revocation_method
            .revoke_signature(id.into())
            .await
            .error_while("revoking signature")?;

        if let Err(error) = self
            .history
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                source: HistorySource::Core,
                action: HistoryAction::Revoked,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::Signature,
                metadata: None,
                metadata_blob_id: None,
                name: signer_name.to_string(),
                target: Some(issuer.id.to_string()),
                organisation_id: None,
                user: self.session_provider.session().user(),
            })
            .await
        {
            tracing::warn!("Failed to write history entry: {}", error);
        }

        tracing::info!("Revoked signature {}", id);
        Ok(())
    }

    async fn store_sign_history(
        &self,
        create_signature_response: &CreateSignatureResponseDTO,
        signature_type: &SignerId,
        issuer_id: shared_types::IdentifierId,
        organisation_id: shared_types::OrganisationId,
    ) -> Result<(), SignatureServiceError> {
        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let blob = Blob::new(
            create_signature_response.result.clone(),
            BlobType::HistoryMetadata,
        );

        let blob_id = blob.id;
        blob_storage
            .create(blob)
            .await
            .error_while("creating history metadata blob")?;

        self.history
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                source: HistorySource::Core,
                action: HistoryAction::Created,
                entity_id: Some(create_signature_response.id.into()),
                entity_type: HistoryEntityType::Signature,
                metadata: None,
                metadata_blob_id: Some(blob_id),
                name: signature_type.to_string(),
                target: Some(issuer_id.to_string()),
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await
            .error_while("creating signature history entry")?;

        Ok(())
    }

    pub async fn revocation_check(
        &self,
        signature_ids: Vec<Uuid>,
    ) -> Result<HashMap<Uuid, SignatureStatusInfo>, SignatureServiceError> {
        let entries = self
            .revocation_list_repository
            .get_entries(ListQuery {
                include_count: false,
                filtering: Some(
                    RevocationListEntryFilterValue::Ids(convert_inner(signature_ids)).condition(),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting revocation list entries")?
            .values;
        let mut result = HashMap::new();
        for entry in entries {
            let RevocationListEntityInfo::Signature(r#type, _) = entry.entity_info else {
                return Err(SignatureServiceError::InvalidSignatureId(entry.id.into()));
            };
            result.insert(
                entry.id.into(),
                SignatureStatusInfo {
                    state: entry.state.try_into()?,
                    r#type,
                },
            );
        }
        Ok(result)
    }
}
