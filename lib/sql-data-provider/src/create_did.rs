use one_core::{
    config::{data_structure::DidEntity, validator::did::validate_did_method},
    repository::{
        data_provider::{CreateDidRequest, CreateDidResponse},
        error::DataLayerError,
    },
};
use sea_orm::{ActiveModelTrait, Set, SqlErr};
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{entity::did, OldProvider};

impl OldProvider {
    pub async fn create_did(
        &self,
        request: CreateDidRequest,
        did_methods: &HashMap<String, DidEntity>,
    ) -> Result<CreateDidResponse, DataLayerError> {
        validate_did_method(&request.method, did_methods)?;

        let now = OffsetDateTime::now_utc();

        let did = did::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            did: Set(request.did.to_owned()),
            created_date: Set(now),
            last_modified: Set(now),
            name: Set(request.name),
            type_field: Set(request.did_type.into()),
            method: Set(request.method),
            organisation_id: Set(request.organisation_id),
        }
        .insert(&self.db)
        .await
        .map_err(|e| match e.sql_err() {
            Some(sql_error) if matches!(sql_error, SqlErr::UniqueConstraintViolation(_)) => {
                DataLayerError::AlreadyExists
            }
            Some(sql_error) if matches!(sql_error, SqlErr::ForeignKeyConstraintViolation(_)) => {
                DataLayerError::IncorrectParameters
            }
            Some(_) | None => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        Ok(CreateDidResponse { id: did.id })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use uuid::Uuid;

    use one_core::repository::{
        data_provider::{CreateDidRequest, DidType},
        error::DataLayerError,
    };

    use crate::test_utilities::*;

    #[tokio::test]
    async fn test_create_did_simple() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let did_methods = get_did_methods();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did = "did:key:123".to_owned();

        let request = CreateDidRequest {
            name: "Name".to_string(),
            organisation_id,
            did: did.clone(),
            did_type: DidType::Local,
            method: "KEY".to_string(),
        };

        let result = data_layer.create_did(request, &did_methods).await;

        assert!(result.is_ok());

        let response = result.unwrap();

        assert!(Uuid::from_str(&response.id).is_ok());
    }

    #[tokio::test]
    async fn test_create_did_twice_by_id_and_value() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let did_methods = get_did_methods();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let missing_organisation = Uuid::new_v4().to_string();

        let did1 = "did:key:123".to_owned();
        let did2 = "did:key:456".to_owned();

        let mut request = CreateDidRequest {
            name: "Name".to_string(),
            organisation_id,
            did: did1.clone(),
            did_type: DidType::Local,
            method: "KEY".to_string(),
        };

        let result = data_layer.create_did(request.clone(), &did_methods).await;
        assert!(result.is_ok());

        // DID value stays the same
        request.did = did1.clone();
        let result = data_layer.create_did(request.clone(), &did_methods).await;
        assert!(matches!(result, Err(DataLayerError::AlreadyExists)));

        // DID and ID are new. Organisation is incorrect.
        request.did = did2.clone();
        request.organisation_id = missing_organisation;
        let result = data_layer.create_did(request.clone(), &did_methods).await;
        assert!(matches!(result, Err(DataLayerError::IncorrectParameters)));
    }
}
