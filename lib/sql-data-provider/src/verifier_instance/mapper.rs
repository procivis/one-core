use one_core::model::verifier_instance::VerifierInstance;
use one_core::repository::error::DataLayerError;
use sea_orm::Set;
use time::OffsetDateTime;

use crate::entity::verifier_instance::{ActiveModel, Model};

impl From<Model> for VerifierInstance {
    fn from(value: Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            provider_type: value.provider_type,
            provider_name: value.provider_name,
            provider_url: value.provider_url,
            organisation: None,
        }
    }
}

impl TryFrom<VerifierInstance> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: VerifierInstance) -> Result<Self, Self::Error> {
        let now = OffsetDateTime::now_utc();
        Ok(Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            provider_name: Set(value.provider_name),
            provider_type: Set(value.provider_type),
            provider_url: Set(value.provider_url),
            organisation_id: Set(value.organisation.ok_or(DataLayerError::MappingError)?.id),
        })
    }
}
