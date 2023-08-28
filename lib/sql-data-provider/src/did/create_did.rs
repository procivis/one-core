use std::str::FromStr;

use super::DidProvider;
use crate::{entity::did, error_mapper::to_data_layer_error};
use one_core::{
    model::did::{Did, DidId},
    repository::error::DataLayerError,
};
use sea_orm::ActiveModelTrait;
use uuid::Uuid;

impl DidProvider {
    pub async fn create_did_impl(&self, request: Did) -> Result<DidId, DataLayerError> {
        let did = did::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Uuid::from_str(&did.id).map_err(|_| DataLayerError::MappingError)
    }
}

#[cfg(test)]
mod tests {

    use crate::{did::test_utilities::*, test_utilities::*};
    use one_core::{
        model::did::{Did, DidType},
        repository::{did_repository::DidRepository, error::DataLayerError},
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn test_create_did() {
        let TestSetup {
            provider,
            organisation_id,
            ..
        } = setup_empty().await;

        let id = Uuid::new_v4();
        let result = provider
            .create_did(Did {
                id,
                name: "Name".to_string(),
                organisation_id,
                did: "did:key:123".to_owned(),
                did_type: DidType::Local,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                did_method: "KEY".to_string(),
            })
            .await;

        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(id, response);
    }

    #[tokio::test]
    async fn test_create_did_invalid_organisation() {
        let TestSetup { provider, .. } = setup_empty().await;

        let missing_organisation = Uuid::new_v4();
        let result = provider
            .create_did(Did {
                id: Uuid::new_v4(),
                name: "Name".to_string(),
                organisation_id: missing_organisation,
                did: "did:key:123".to_owned(),
                did_type: DidType::Local,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                did_method: "KEY".to_string(),
            })
            .await;
        assert!(matches!(result, Err(DataLayerError::IncorrectParameters)));
    }
}
