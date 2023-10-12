use one_core::service::key::dto::KeyListItemResponseDTO;

use super::dto::{KeyListItemResponseRestDTO, SortableKeyColumnRestDTO};

impl From<KeyListItemResponseDTO> for KeyListItemResponseRestDTO {
    fn from(value: KeyListItemResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            public_key: value.public_key,
            key_type: value.key_type,
            storage_type: value.storage_type,
        }
    }
}

impl From<SortableKeyColumnRestDTO> for one_core::model::key::SortableKeyColumn {
    fn from(value: SortableKeyColumnRestDTO) -> Self {
        match value {
            SortableKeyColumnRestDTO::Name => one_core::model::key::SortableKeyColumn::Name,
            SortableKeyColumnRestDTO::CreatedDate => {
                one_core::model::key::SortableKeyColumn::CreatedDate
            }
            SortableKeyColumnRestDTO::PublicKey => {
                one_core::model::key::SortableKeyColumn::PublicKey
            }
            SortableKeyColumnRestDTO::KeyType => one_core::model::key::SortableKeyColumn::KeyType,
            SortableKeyColumnRestDTO::StorageType => {
                one_core::model::key::SortableKeyColumn::StorageType
            }
        }
    }
}
