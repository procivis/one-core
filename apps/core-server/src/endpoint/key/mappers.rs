use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::service::key::dto::{KeyListItemResponseDTO, KeyResponseDTO};

use super::dto::{KeyListItemResponseRestDTO, KeyResponseRestDTO, SortableKeyColumnRestDTO};
use crate::mapper::MapperError;

impl TryFrom<KeyResponseDTO> for KeyResponseRestDTO {
    type Error = MapperError;

    fn try_from(value: KeyResponseDTO) -> Result<Self, MapperError> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            organisation_id: value.organisation_id,
            name: value.name,
            public_key: Base64UrlSafeNoPadding::encode_to_string(value.public_key)?,
            key_type: value.key_type,
            storage_type: value.storage_type,
        })
    }
}

impl TryFrom<KeyListItemResponseDTO> for KeyListItemResponseRestDTO {
    type Error = MapperError;

    fn try_from(value: KeyListItemResponseDTO) -> Result<Self, MapperError> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            public_key: Base64UrlSafeNoPadding::encode_to_string(value.public_key)?,
            key_type: value.key_type,
            storage_type: value.storage_type,
        })
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
