use autometrics::autometrics;
use futures::FutureExt;
use one_core::model::common::LockType;
use one_core::model::relation::Related;
use one_core::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntityInfo, RevocationListEntry,
    RevocationListPurpose, UpdateRevocationListEntryId, UpdateRevocationListEntryRequest,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::revocation_list_repository::RevocationListRepository;
use sea_orm::sea_query::IntoCondition;
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ColumnTrait, Condition, EntityTrait, ExprTrait, NotSet,
    QueryFilter, QueryOrder, QuerySelect, Set, Unchanged,
};
use shared_types::{
    CertificateId, IdentifierId, RevocationListEntryId, RevocationListId, RevocationMethodId,
};
use uuid::Uuid;

use crate::entity::revocation_list_entry::{RevocationListEntryState, RevocationListEntryType};
use crate::entity::{managed_instance_attestation, revocation_list, revocation_list_entry};
use crate::mapper::{map_lock_type, to_data_layer_error, to_update_data_layer_error};
use crate::revocation_list::RevocationListProvider;

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
        revocation_list::ActiveModel {
            id: Set(request.id),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            formatted_list: Set(request.formatted_list),
            purpose: Set(request.purpose.into()),
            issuer_identifier_id: Set(request.issuer_identifier.id()),
            format: Set(request.format.into()),
            r#type: Set(request.r#type),
            issuer_certificate_id: Set(request.issuer_certificate.map(|c| c.id())),
        }
        .insert(&self.db)
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
                kind: EntityKind::RevocationList,
                id: entry_id.into(),
            })?;
        self.get_revocation_list(&entry.revocation_list_id).await
    }

    async fn get_revocation_by_issuer_identifier_id(
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
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(revocation_list.map(|list| self.entity_model_to_repository_model(list)))
    }

    async fn update_formatted_list(
        &self,
        revocation_list_id: &RevocationListId,
        formatted_list: Vec<u8>,
    ) -> Result<(), DataLayerError> {
        let update_model = revocation_list::ActiveModel {
            id: Unchanged(*revocation_list_id),
            last_modified: Set(one_core::clock::now_utc()),
            formatted_list: Set(formatted_list),
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn next_free_index(
        &self,
        id: &RevocationListId,
        lock: Option<LockType>,
    ) -> Result<usize, DataLayerError> {
        // lock the list row, not the entries: a FOR UPDATE on the entries is a gap lock on MySQL,
        // two writers both get it and then deadlock on their inserts
        let mut list = revocation_list::Entity::find_by_id(id)
            .select_only()
            .column(revocation_list::Column::Id);

        if let Some(lock) = lock {
            list = list.lock(map_lock_type(lock));
        };

        if list
            .into_tuple::<RevocationListId>()
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .is_none()
        {
            return Err(DataLayerError::MissingRequiredRelation {
                relation: "revocation_list",
                id: id.to_string(),
            });
        }

        let max: Option<Option<i32>> = revocation_list_entry::Entity::find()
            .select_only()
            .column(revocation_list_entry::Column::Index)
            .filter(revocation_list_entry::Column::RevocationListId.eq(id))
            .order_by_desc(revocation_list_entry::Column::Index)
            .into_tuple()
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(max.flatten().map(|index| index + 1).unwrap_or(0) as _)
    }

    async fn create_entry(
        &self,
        list_id: RevocationListId,
        entity_id: RevocationListEntityId,
        index_on_status_list: Option<usize>,
    ) -> Result<RevocationListEntryId, DataLayerError> {
        let credential_id = if let RevocationListEntityId::Credential(credential_id) = &entity_id {
            Some(credential_id.to_owned())
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
                return Err(DataLayerError::IncorrectParameters);
            }

            Some(serial.to_owned().into())
        } else {
            if index_on_status_list.is_none() {
                return Err(DataLayerError::IncorrectParameters);
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

        let r#type = match &entity_id {
            RevocationListEntityId::Credential(_) => RevocationListEntryType::Credential,
            RevocationListEntityId::Signature(_, _) => RevocationListEntryType::Signature,
            RevocationListEntityId::KeyAttestation(_) => RevocationListEntryType::KeyAttestation,
            RevocationListEntityId::WalletInstanceAttestation(_) => {
                RevocationListEntryType::WalletInstanceAttestation
            }
        };

        let now = one_core::clock::now_utc();
        let entry_id: RevocationListEntryId = Uuid::new_v4().into();

        self.db
            .tx(async move {
                revocation_list_entry::ActiveModel {
                    id: Set(entry_id),
                    created_date: Set(now),
                    last_modified: Set(now),
                    revocation_list_id: Set(list_id),
                    index: Set(index_on_status_list.map(|index| index as _)),
                    credential_id: Set(credential_id),
                    r#type: Set(r#type),
                    signature_type: Set(signature_type.map(|t| t.to_string())),
                    state: Set(RevocationListEntryState::Active),
                    serial: Set(serial),
                }
                .insert(&self.db)
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
                    .exec(&self.db)
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

        let model = revocation_list_entry::ActiveModel {
            id: NotSet,
            last_modified: Set(one_core::clock::now_utc()),
            state,
            ..Default::default()
        };

        let model = match id {
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
                    .filter(
                        Condition::all()
                            .add(
                                revocation_list_entry::Column::RevocationListId
                                    .eq(revocation_list_id),
                            )
                            .add(revocation_list_entry::Column::Index.eq(index as i32)),
                    )
            }
        };
        model
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get_entry_by_id(
        &self,
        entry_id: RevocationListEntryId,
    ) -> Result<RevocationListEntry, DataLayerError> {
        let mut entries = self
            .get_filtered_entries(
                revocation_list_entry::Column::Id
                    .eq(entry_id)
                    .into_condition(),
            )
            .await?;
        entries.pop().ok_or_else(|| DataLayerError::EntityNotFound {
            kind: EntityKind::RevocationListEntry,
            id: entry_id.into(),
        })
    }

    async fn get_entries(
        &self,
        list_id: RevocationListId,
    ) -> Result<Vec<RevocationListEntry>, DataLayerError> {
        self.get_filtered_entries(
            revocation_list_entry::Column::RevocationListId
                .eq(list_id.to_string())
                .into_condition(),
        )
        .await
    }

    async fn get_entries_by_id(
        &self,
        entry_ids: Vec<RevocationListEntryId>,
    ) -> Result<Vec<RevocationListEntry>, DataLayerError> {
        self.get_filtered_entries(
            revocation_list_entry::Column::Id
                .is_in(entry_ids)
                .into_condition(),
        )
        .await
    }
}

impl RevocationListProvider {
    async fn get_filtered_entries(
        &self,
        filter: sea_orm::Condition,
    ) -> Result<Vec<RevocationListEntry>, DataLayerError> {
        let entries = revocation_list_entry::Entity::find()
            .filter(filter)
            .order_by_asc(revocation_list_entry::Column::Index)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        entries
            .into_iter()
            .map(|entry| {
                let entity_info = match entry.r#type {
                    RevocationListEntryType::Credential => match entry.credential_id {
                        Some(value) => Ok(RevocationListEntityInfo::Credential(value)),
                        None => Err(DataLayerError::MappingError),
                    },
                    RevocationListEntryType::KeyAttestation => {
                        Ok(RevocationListEntityInfo::KeyAttestation)
                    }
                    RevocationListEntryType::WalletInstanceAttestation => {
                        Ok(RevocationListEntityInfo::WalletInstanceAttestation)
                    }
                    RevocationListEntryType::Signature => match entry.signature_type {
                        Some(value) => {
                            let serial = if let Some(serial) = entry.serial {
                                Some(serial.try_into()?)
                            } else {
                                None
                            };
                            Ok(RevocationListEntityInfo::Signature(value.into(), serial))
                        }
                        None => Err(DataLayerError::MappingError),
                    },
                }?;
                Ok(RevocationListEntry {
                    id: entry.id,
                    created_date: entry.created_date,
                    last_modified: entry.last_modified,
                    entity_info,
                    index: entry.index.map(|index| index as _),
                    state: entry.state.into(),
                })
            })
            .collect::<Result<_, DataLayerError>>()
    }
}
