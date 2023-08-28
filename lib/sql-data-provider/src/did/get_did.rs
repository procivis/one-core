use super::DidProvider;
use crate::entity::did;
use one_core::{
    model::did::{Did, DidId, DidRelations},
    repository::error::DataLayerError,
};
use sea_orm::EntityTrait;

impl DidProvider {
    pub async fn get_did_impl(
        &self,
        id: &DidId,
        _relations: &DidRelations,
    ) -> Result<Did, DataLayerError> {
        let did = did::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        did.try_into()
    }
}

#[cfg(test)]
mod tests {

    use crate::did::test_utilities::*;
    use one_core::{
        model::did::{DidRelations, DidType},
        repository::{did_repository::DidRepository, error::DataLayerError},
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn test_get_did_existing() {
        let TestSetupWithDid {
            provider,
            did_id,
            did_name,
            did_value,
            organisation_id,
            ..
        } = setup_with_did().await;

        let result = provider.get_did(&did_id, &DidRelations::default()).await;

        assert!(result.is_ok());

        let content = result.unwrap();
        assert_eq!(content.id, did_id);
        assert_eq!(content.did_method, "KEY");
        assert_eq!(content.did_type, DidType::Local);
        assert_eq!(content.did, did_value);
        assert_eq!(content.name, did_name);
        assert_eq!(content.organisation_id, organisation_id);
    }

    #[tokio::test]
    async fn test_get_did_not_existing() {
        let TestSetup { provider, .. } = setup_empty().await;

        let result = provider
            .get_did(&Uuid::new_v4(), &DidRelations::default())
            .await;

        assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
    }
}
