use std::sync::Arc;

use one_core::model::managed_instance_attestation::{
    ManagedInstanceAttestation, ManagedInstanceAttestationRevocationInfo,
    ManagedInstanceAttestationUpsertRequest,
};
use one_core::model::relation::{AsyncModelLoader, Related};
use one_core::repository::error::DataLayerError;
use one_core::repository::revocation_list_repository::RevocationListRepository;
use sea_orm::{EntityTrait, Set};
use shared_types::RevocationListEntryId;

use crate::entity::managed_instance_attestation::{ActiveModel, Model};
use crate::entity::revocation_list_entry;
use crate::mapper::to_data_layer_error;
use crate::transaction_context::TransactionManagerImpl;

pub(super) fn attested_key_from_model(
    value: Model,
    db: &TransactionManagerImpl,
    revocation_list_repository: &Arc<dyn RevocationListRepository>,
) -> Result<ManagedInstanceAttestation, DataLayerError> {
    Ok(ManagedInstanceAttestation {
        id: value.id,
        instance_id: value.managed_instance_id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        expiration_date: value.expiration_date,
        r#type: value.r#type.into(),
        public_key_jwk: serde_json::from_str(&value.public_key_jwk)
            .map_err(|_| DataLayerError::MappingError)?,
        revocation: value.revocation_list_entry_id.map(|id| {
            Related::new(
                id,
                RevocationInfoLoader {
                    db: db.clone(),
                    revocation_list_repository: revocation_list_repository.clone(),
                },
            )
        }),
    })
}

impl TryFrom<ManagedInstanceAttestation> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: ManagedInstanceAttestation) -> Result<Self, DataLayerError> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            expiration_date: Set(value.expiration_date),
            r#type: Set(value.r#type.into()),
            public_key_jwk: Set(serde_json::to_string(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?),
            managed_instance_id: Set(value.instance_id),
            revocation_list_entry_id: Set(value.revocation.map(|revocation| revocation.id())),
        })
    }
}

impl TryFrom<ManagedInstanceAttestationUpsertRequest> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: ManagedInstanceAttestationUpsertRequest) -> Result<Self, DataLayerError> {
        let now = one_core::clock::now_utc();
        Ok(Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            expiration_date: Set(value.expiration_date),
            r#type: Set(value.r#type.into()),
            public_key_jwk: Set(serde_json::to_string(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?),
            managed_instance_id: Set(value.instance_id),
            revocation_list_entry_id: Set(None),
        })
    }
}

struct RevocationInfoLoader {
    db: TransactionManagerImpl,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
}

#[async_trait::async_trait]
impl AsyncModelLoader<ManagedInstanceAttestationRevocationInfo> for RevocationInfoLoader {
    async fn load(
        &self,
        id: &RevocationListEntryId,
    ) -> Result<ManagedInstanceAttestationRevocationInfo, DataLayerError> {
        let revocation_list_entry = revocation_list_entry::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or(DataLayerError::MissingRequiredRelation {
                relation: "managed_instance_attested_key-revocation_list_entry",
                id: id.to_string(),
            })?;

        let revocation_list_index =
            revocation_list_entry
                .index
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "managed_instance_attested_key-revocation_list_entry-index",
                    id: id.to_string(),
                })? as _;

        Ok(ManagedInstanceAttestationRevocationInfo {
            id: *id,
            revocation_list: Related::new(
                revocation_list_entry.revocation_list_id,
                self.revocation_list_repository.clone(),
            ),
            revocation_list_index,
        })
    }
}
