use std::collections::HashSet;

use anyhow::anyhow;
use autometrics::autometrics;
use futures::FutureExt;
use migration::supported_db_type::WithSupportedDbType;
use one_core::model::relation::Related;
use one_core::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntryList, RevocationListEntryListQuery,
    RevocationListPurpose, UpdateRevocationListEntryId, UpdateRevocationListEntryRequest,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::revocation_list_repository::RevocationListRepository;
use sea_orm::sea_query::{CaseStatement, Expr};
use sea_orm::{
    ActiveEnum, ColumnTrait, EntityTrait, ExprTrait, NotSet, QueryFilter, QueryOrder, Set,
    Unchanged,
};
use shared_types::{
    CertificateId, CredentialId, IdentifierId, RevocationListEntryId, RevocationListId,
    RevocationMethodId,
};
use uuid::Uuid;

use super::RevocationListProvider;
use super::mapper::revocation_list_entry_from_model;
use crate::common::list_query_with_custom_model;
use crate::entity::revocation_list_entry::{RevocationListEntryState, RevocationListEntryType};
use crate::entity::{managed_instance_attestation, revocation_list, revocation_list_entry};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

impl RevocationListProvider {
    fn entity_model_to_repository_model(
        &self,
        revocation_list: revocation_list::Model,
    ) -> RevocationList {
        RevocationList {
            id: revocation_list.id,
            created_date: revocation_list.created_date,
            last_modified: revocation_list.last_modified,
            formatted_list: revocation_list.formatted_list,
            purpose: revocation_list.purpose.into(),
            issuer_identifier: Related::new(
                revocation_list.issuer_identifier_id,
                self.identifier_repository.clone(),
            ),
            issuer_certificate: revocation_list.issuer_certificate_id.map(
                |issuer_certificate_id| {
                    Related::new(issuer_certificate_id, self.certificate_repository.clone())
                },
            ),
            format: revocation_list.format.into(),
            r#type: revocation_list.r#type,
            sequence_number: revocation_list.sequence_number as _,
            params: revocation_list.params,
        }
    }
}

#[autometrics]
#[async_trait::async_trait]
impl RevocationListRepository for RevocationListProvider {
    async fn create_revocation_list(
        &self,
        request: RevocationList,
    ) -> Result<RevocationListId, DataLayerError> {
        revocation_list::Entity::insert(revocation_list::ActiveModel {
            id: Set(request.id),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            formatted_list: Set(request.formatted_list),
            purpose: Set(request.purpose.into()),
            issuer_identifier_id: Set(request.issuer_identifier.id()),
            format: Set(request.format.into()),
            r#type: Set(request.r#type),
            issuer_certificate_id: Set(request.issuer_certificate.map(|c| c.id())),
            sequence_number: Set(request.sequence_number as _),
            params: Set(request.params),
        })
        .exec_without_returning(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        Ok(request.id)
    }

    async fn get_revocation_list(
        &self,
        id: &RevocationListId,
    ) -> Result<RevocationList, DataLayerError> {
        let revocation_list = revocation_list::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::RevocationList,
                id: (*id).into(),
            })?;

        Ok(self.entity_model_to_repository_model(revocation_list))
    }

    async fn get_revocation_list_by_entry_id(
        &self,
        entry_id: RevocationListEntryId,
    ) -> Result<RevocationList, DataLayerError> {
        let entry = revocation_list_entry::Entity::find_by_id(entry_id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::RevocationListEntry,
                id: entry_id.into(),
            })?;
        self.get_revocation_list(&entry.revocation_list_id).await
    }

    async fn get_revocation_lists_by_entity(
        &self,
        entity_id: RevocationListEntityId,
    ) -> Result<Vec<RevocationList>, DataLayerError> {
        let list_ids: HashSet<_> = match entity_id {
            RevocationListEntityId::Credential(credential_id) => {
                let Some(credential_id) = credential_id else {
                    return Err(DataLayerError::MappingError(anyhow!(
                        "Credential entry missing ID"
                    )));
                };

                revocation_list_entry::Entity::find()
                    .filter(
                        revocation_list_entry::Column::Type.eq(RevocationListEntryType::Credential),
                    )
                    .filter(revocation_list_entry::Column::CredentialId.eq(credential_id))
                    .all(&self.db)
                    .await
                    .map_err(to_data_layer_error)?
                    .into_iter()
                    .map(|entry| entry.revocation_list_id)
                    .collect()
            }
            RevocationListEntityId::Signature(_, _) => {
                return Err(DataLayerError::MappingError(anyhow!(
                    "Signature lookup not supported"
                )));
            }
            RevocationListEntityId::KeyAttestation(managed_instance_attestation_id)
            | RevocationListEntityId::WalletInstanceAttestation(managed_instance_attestation_id) => {
                let managed_instance_attestation =
                    managed_instance_attestation::Entity::find_by_id(
                        managed_instance_attestation_id,
                    )
                    .one(&self.db)
                    .await
                    .map_err(to_data_layer_error)?
                    .ok_or_else(|| DataLayerError::EntityNotFound {
                        kind: EntityKind::ManagedInstanceAttestation,
                        id: managed_instance_attestation_id.into(),
                    })?;

                let Some(revocation_list_entry_id) =
                    managed_instance_attestation.revocation_list_entry_id
                else {
                    return Ok(vec![]);
                };

                let entry = revocation_list_entry::Entity::find_by_id(revocation_list_entry_id)
                    .one(&self.db)
                    .await
                    .map_err(to_data_layer_error)?
                    .ok_or_else(|| DataLayerError::EntityNotFound {
                        kind: EntityKind::RevocationListEntry,
                        id: revocation_list_entry_id.into(),
                    })?;

                std::iter::once(entry.revocation_list_id).collect()
            }
        };

        let mut result = Vec::with_capacity(list_ids.len());
        for list_id in list_ids {
            result.push(self.get_revocation_list(&list_id).await?)
        }
        Ok(result)
    }

    async fn get_latest_list_by_issuer(
        &self,
        issuer_identifier_id: IdentifierId,
        issuer_certificate_id: Option<CertificateId>,
        purpose: RevocationListPurpose,
        status_list_type: &RevocationMethodId,
    ) -> Result<Option<RevocationList>, DataLayerError> {
        let purpose_as_db_type = revocation_list::RevocationListPurpose::from(purpose);

        let revocation_list = revocation_list::Entity::find()
            .filter(
                revocation_list::Column::IssuerIdentifierId
                    .eq(issuer_identifier_id)
                    .and(revocation_list::Column::Purpose.eq(purpose_as_db_type.into_value()))
                    .and(revocation_list::Column::Type.eq(status_list_type))
                    .and(if let Some(issuer_certificate_id) = issuer_certificate_id {
                        revocation_list::Column::IssuerCertificateId.eq(issuer_certificate_id)
                    } else {
                        revocation_list::Column::IssuerCertificateId.is_null()
                    }),
            )
            .order_by_desc(revocation_list::Column::SequenceNumber)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(revocation_list.map(|list| self.entity_model_to_repository_model(list)))
    }

    async fn update_formatted_list(
        &self,
        revocation_list_id: &RevocationListId,
        formatted_list: Vec<u8>,
        params: Option<Vec<u8>>,
    ) -> Result<(), DataLayerError> {
        let params = match params {
            Some(params) => Set(Some(params)),
            None => NotSet,
        };

        let update_model = revocation_list::ActiveModel {
            id: Unchanged(*revocation_list_id),
            last_modified: Set(one_core::clock::now_utc()),
            formatted_list: Set(formatted_list),
            params,
            ..Default::default()
        };

        revocation_list::Entity::update(update_model)
            .exec_without_returning(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn create_entry(
        &self,
        list_id: RevocationListId,
        entity_id: RevocationListEntityId,
        index_on_status_list: Option<usize>,
    ) -> Result<RevocationListEntryId, DataLayerError> {
        let credential_id = if let RevocationListEntityId::Credential(credential_id) = &entity_id {
            credential_id.to_owned()
        } else {
            None
        };

        // either serial set or index, not both, not none
        let signature_type = if let RevocationListEntityId::Signature(sig_type, _) = &entity_id {
            Some(sig_type.to_owned())
        } else {
            None
        };

        let serial = if let RevocationListEntityId::Signature(_, Some(serial)) = &entity_id {
            if index_on_status_list.is_some() {
                return Err(DataLayerError::IncorrectParameters(anyhow!(
                    "Serial and status list index cannot both be provided"
                )));
            }

            Some(serial.to_owned().into())
        } else {
            if index_on_status_list.is_none() {
                return Err(DataLayerError::IncorrectParameters(anyhow!(
                    "Either a serial or status list index is required"
                )));
            }

            None
        };

        let managed_instance_attestation_id = match &entity_id {
            RevocationListEntityId::Credential(_) | RevocationListEntityId::Signature(_, _) => None,
            RevocationListEntityId::KeyAttestation(attestation_id)
            | RevocationListEntityId::WalletInstanceAttestation(attestation_id) => {
                Some(*attestation_id)
            }
        };

        let now = one_core::clock::now_utc();
        let entry_id: RevocationListEntryId = Uuid::new_v4().into();

        self.db
            .tx(async move {
                revocation_list_entry::Entity::insert(revocation_list_entry::ActiveModel {
                    id: Set(entry_id),
                    created_date: Set(now),
                    last_modified: Set(now),
                    revocation_list_id: Set(list_id),
                    index: Set(index_on_status_list.map(|index| index as _)),
                    credential_id: Set(credential_id),
                    r#type: Set(RevocationListEntryType::from(&entity_id)),
                    signature_type: Set(signature_type.map(|t| t.to_string())),
                    state: Set(RevocationListEntryState::Active),
                    serial: Set(serial),
                })
                .exec_without_returning(&self.db)
                .await
                .map_err(to_data_layer_error)?;

                if let Some(managed_instance_attestation_id) = managed_instance_attestation_id {
                    managed_instance_attestation::Entity::update(
                        managed_instance_attestation::ActiveModel {
                            id: Unchanged(managed_instance_attestation_id),
                            last_modified: Set(now),
                            revocation_list_entry_id: Set(Some(entry_id)),
                            ..Default::default()
                        },
                    )
                    .exec_without_returning(&self.db)
                    .await
                    .map_err(to_update_data_layer_error)?;
                }

                Ok(entry_id)
            }
            .boxed())
            .await?
    }

    async fn update_entry(
        &self,
        id: UpdateRevocationListEntryId,
        request: UpdateRevocationListEntryRequest,
    ) -> Result<(), DataLayerError> {
        let state = match request.state {
            None => Unchanged(RevocationListEntryState::Active),
            Some(state) => Set(state.into()),
        };

        let credential_id = match &request.credential_id {
            None => NotSet,
            Some(credential_id) => Set(Some(*credential_id)),
        };

        let model = revocation_list_entry::ActiveModel {
            id: NotSet,
            last_modified: Set(one_core::clock::now_utc()),
            state,
            credential_id,
            ..Default::default()
        };

        let mut model = match id {
            UpdateRevocationListEntryId::Credential(credential_id) => {
                revocation_list_entry::Entity::update_many()
                    .set(model)
                    .filter(revocation_list_entry::Column::CredentialId.eq(credential_id))
            }
            UpdateRevocationListEntryId::Id(id) => revocation_list_entry::Entity::update_many()
                .set(model)
                .filter(revocation_list_entry::Column::Id.eq(id)),
            UpdateRevocationListEntryId::Index(revocation_list_id, index) => {
                revocation_list_entry::Entity::update_many()
                    .set(model)
                    .filter(revocation_list_entry::Column::RevocationListId.eq(revocation_list_id))
                    .filter(revocation_list_entry::Column::Index.eq(index as i32))
            }
        };

        if request.credential_id.is_some() {
            model = model.filter(
                revocation_list_entry::Column::Type.eq(RevocationListEntryType::Credential),
            );
        }

        model
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn link_credential_entries(
        &self,
        links: Vec<(RevocationListEntryId, CredentialId)>,
    ) -> Result<(), DataLayerError> {
        if links.is_empty() {
            return Ok(());
        }

        let credential_id =
            links
                .iter()
                .fold(CaseStatement::new(), |case, (entry_id, credential_id)| {
                    case.case(
                        revocation_list_entry::Column::Id.eq(*entry_id),
                        Expr::val(*credential_id),
                    )
                });
        // rolled back unless all entries are linked
        self.db
            .tx(async {
                let result = revocation_list_entry::Entity::update_many()
                    .col_expr(
                        revocation_list_entry::Column::CredentialId,
                        credential_id.into(),
                    )
                    .col_expr(
                        revocation_list_entry::Column::LastModified,
                        Expr::val(one_core::clock::now_utc()),
                    )
                    .filter(
                        revocation_list_entry::Column::Id.is_in(links.iter().map(|(id, _)| *id)),
                    )
                    .filter(
                        revocation_list_entry::Column::Type.eq(RevocationListEntryType::Credential),
                    )
                    .filter(revocation_list_entry::Column::CredentialId.is_null())
                    .exec(&self.db)
                    .await
                    .map_err(to_update_data_layer_error)?;

                if result.rows_affected != links.len() as u64 {
                    return Err(DataLayerError::RecordNotUpdated(anyhow!(
                        "linked {} of {} revocation list entries",
                        result.rows_affected,
                        links.len()
                    )));
                }
                Ok(())
            })
            .await?
    }

    async fn get_entries(
        &self,
        query_params: RevocationListEntryListQuery,
    ) -> Result<RevocationListEntryList, DataLayerError> {
        let mut query = revocation_list_entry::Entity::find()
            .with_list_query(&query_params, self.db.supported_db_type());

        if query_params.sorting.is_some() || query_params.pagination.is_some() {
            // fallback ordering
            query = query
                .order_by_desc(revocation_list_entry::Column::CreatedDate)
                .order_by_desc(revocation_list_entry::Column::Id);
        }

        list_query_with_custom_model(query, query_params, &self.db, |model| {
            revocation_list_entry_from_model(model)
        })
        .await
    }
}
