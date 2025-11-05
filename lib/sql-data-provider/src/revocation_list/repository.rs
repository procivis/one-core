use anyhow::anyhow;
use autometrics::autometrics;
use one_core::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntityInfo, RevocationListEntry,
    RevocationListPurpose, RevocationListRelations, StatusListType,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::revocation_list_repository::RevocationListRepository;
use sea_orm::{
    ActiveEnum, ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait, Set, Unchanged,
};
use shared_types::{CredentialId, IdentifierId, RevocationListId, WalletUnitAttestedKeyId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::entity::{
    credential, revocation_list, revocation_list_entry, wallet_unit, wallet_unit_attested_key,
};
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::revocation_list::RevocationListProvider;

impl RevocationListProvider {
    async fn entity_model_to_repository_model(
        &self,
        revocation_list: revocation_list::Model,
        relations: &RevocationListRelations,
    ) -> Result<RevocationList, DataLayerError> {
        let issuer_identifier = match relations.issuer_identifier.as_ref() {
            Some(relations) => Some(
                self.identifier_repository
                    .get(revocation_list.issuer_identifier_id, relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "revocation_list-identifier",
                        id: revocation_list.issuer_identifier_id.to_string(),
                    })?,
            ),
            None => None,
        };

        Ok(RevocationList {
            id: revocation_list.id,
            created_date: revocation_list.created_date,
            last_modified: revocation_list.last_modified,
            credentials: revocation_list.credentials,
            purpose: revocation_list.purpose.into(),
            issuer_identifier,
            format: revocation_list.format.into(),
            // TODO fix in ONE-3968
            r#type: match revocation_list.r#type.as_str() {
                "BITSTRING_STATUS_LIST" | "BITSTRINGSTATUSLIST" => {
                    StatusListType::BitstringStatusList
                }
                "TOKENSTATUSLIST" => StatusListType::TokenStatusList,
                _ => return Err(DataLayerError::Db(anyhow!("Invalid revocation list type"))),
            },
        })
    }
}

#[autometrics]
#[async_trait::async_trait]
impl RevocationListRepository for RevocationListProvider {
    async fn create_revocation_list(
        &self,
        request: RevocationList,
    ) -> Result<RevocationListId, DataLayerError> {
        let issuer_identifier = request
            .issuer_identifier
            .ok_or(DataLayerError::MappingError)?;

        revocation_list::ActiveModel {
            id: Set(request.id),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            credentials: Set(request.credentials),
            purpose: Set(request.purpose.into()),
            issuer_identifier_id: Set(issuer_identifier.id),
            format: Set(request.format.into()),
            r#type: Set(request.r#type.to_string()),
        }
        .insert(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        Ok(request.id)
    }

    async fn get_revocation_list(
        &self,
        id: &RevocationListId,
        relations: &RevocationListRelations,
    ) -> Result<Option<RevocationList>, DataLayerError> {
        let revocation_list = revocation_list::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        match revocation_list {
            None => Ok(None),
            Some(revocation_list) => {
                let revocation_list = self
                    .entity_model_to_repository_model(revocation_list, relations)
                    .await?;

                Ok(Some(revocation_list))
            }
        }
    }

    async fn get_revocation_by_issuer_identifier_id(
        &self,
        issuer_identifier_id: IdentifierId,
        purpose: RevocationListPurpose,
        status_list_type: StatusListType,
        relations: &RevocationListRelations,
    ) -> Result<Option<RevocationList>, DataLayerError> {
        let purpose_as_db_type = revocation_list::RevocationListPurpose::from(purpose);

        let revocation_list = revocation_list::Entity::find()
            .filter(
                revocation_list::Column::IssuerIdentifierId
                    .eq(issuer_identifier_id)
                    .and(revocation_list::Column::Purpose.eq(purpose_as_db_type.into_value()))
                    .and(revocation_list::Column::Type.eq(status_list_type.to_string())),
            )
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        match revocation_list {
            None => Ok(None),
            Some(revocation_list) => {
                let revocation_list = self
                    .entity_model_to_repository_model(revocation_list, relations)
                    .await?;

                Ok(Some(revocation_list))
            }
        }
    }

    async fn update_credentials(
        &self,
        revocation_list_id: &RevocationListId,
        credentials: Vec<u8>,
    ) -> Result<(), DataLayerError> {
        let update_model = revocation_list::ActiveModel {
            id: Unchanged(*revocation_list_id),
            last_modified: Set(OffsetDateTime::now_utc()),
            credentials: Set(credentials),
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn get_max_used_index(
        &self,
        id: &RevocationListId,
    ) -> Result<Option<usize>, DataLayerError> {
        let max: Option<Option<u32>> = revocation_list_entry::Entity::find()
            .select_only()
            .column_as(revocation_list_entry::Column::Index.max(), "index")
            .filter(revocation_list_entry::Column::RevocationListId.eq(id))
            .into_tuple()
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(max.flatten().map(|index| index as _))
    }

    async fn create_entry(
        &self,
        list_id: RevocationListId,
        entity_id: RevocationListEntityId,
        index_on_status_list: usize,
    ) -> Result<(), DataLayerError> {
        let credential_id = if let RevocationListEntityId::Credential(credential_id) = &entity_id {
            Some(credential_id.to_owned())
        } else {
            None
        };

        let now = OffsetDateTime::now_utc();
        let entry_id = Uuid::new_v4();
        revocation_list_entry::ActiveModel {
            id: Set(entry_id.to_string()),
            created_date: Set(now),
            revocation_list_id: Set(list_id),
            index: Set(index_on_status_list as _),
            credential_id: Set(credential_id),
        }
        .insert(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        if let RevocationListEntityId::WalletUnitAttestedKey(key_id) = entity_id {
            wallet_unit_attested_key::Entity::update(wallet_unit_attested_key::ActiveModel {
                id: Unchanged(key_id),
                last_modified: Set(now),
                revocation_list_entry_id: Set(Some(entry_id.to_string())),
                ..Default::default()
            })
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        }

        Ok(())
    }

    async fn get_entries(
        &self,
        list_id: RevocationListId,
    ) -> Result<Vec<RevocationListEntry>, DataLayerError> {
        #[derive(FromQueryResult)]
        struct Entry {
            pub credential_id: Option<CredentialId>,
            pub state: Option<credential::CredentialState>,
            pub index: u32,
            pub id: Option<WalletUnitAttestedKeyId>,
            pub status: Option<wallet_unit::WalletUnitStatus>,
        }

        let entries = revocation_list_entry::Entity::find()
            .select_only()
            .column(revocation_list_entry::Column::Index)
            .column(revocation_list_entry::Column::CredentialId)
            .join(
                sea_orm::JoinType::LeftJoin,
                revocation_list_entry::Relation::Credential.def(),
            )
            .column(credential::Column::State)
            .join(
                sea_orm::JoinType::LeftJoin,
                revocation_list_entry::Relation::WalletUnitAttestedKey.def(),
            )
            .column(wallet_unit_attested_key::Column::Id)
            .join(
                sea_orm::JoinType::LeftJoin,
                wallet_unit_attested_key::Relation::WalletUnit.def(),
            )
            .column(wallet_unit::Column::Status)
            .filter(revocation_list_entry::Column::RevocationListId.eq(list_id.to_string()))
            .order_by_asc(revocation_list_entry::Column::Index)
            .into_model::<Entry>()
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        entries
            .into_iter()
            .map(|entry| {
                let index = entry.index as _;
                let entity_info = match entry {
                    Entry {
                        credential_id: Some(credential_id),
                        state: Some(state),
                        ..
                    } => RevocationListEntityInfo::Credential(credential_id, state.into()),
                    Entry {
                        id: Some(id),
                        status: Some(status),
                        ..
                    } => RevocationListEntityInfo::WalletUnitAttestedKey(id, status.into()),
                    _ => {
                        return Err(DataLayerError::MappingError);
                    }
                };

                Ok(RevocationListEntry { entity_info, index })
            })
            .collect::<Result<_, DataLayerError>>()
    }
}
