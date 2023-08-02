use sea_orm::{EntityTrait, Set, SqlErr};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::data_layer::{entities::did, DataLayerError};

use super::DataLayer;

impl DataLayer {
    pub async fn insert_remote_did(
        &self,
        did_value: &str,
        organisation_id: &str,
    ) -> Result<String, DataLayerError> {
        let now = OffsetDateTime::now_utc();
        let id = Uuid::new_v4().to_string();

        did::Entity::insert(did::ActiveModel {
            id: Set(id.to_owned()),
            did: Set(did_value.to_owned()),
            created_date: Set(now),
            last_modified: Set(now),
            name: Set("TODO".to_owned()),
            type_field: Set(did::DidType::Remote),
            method: Set(did::DidMethod::Key),
            organisation_id: Set(organisation_id.to_owned()),
        })
        .exec(&self.db)
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

        Ok(id)
    }
}

#[cfg(test)]
mod tests {

    use sea_orm::EntityTrait;

    use crate::data_layer::{
        entities::{did::DidType, Did},
        test_utilities::*,
    };

    #[tokio::test]
    async fn insert_remote_did_test() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();
        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did_value = "did:key:some";
        let did_id = data_layer
            .insert_remote_did(did_value, &organisation_id)
            .await;
        assert!(did_id.is_ok());

        let dids = Did::find().all(&data_layer.db).await.unwrap();
        assert_eq!(1, dids.len());
        assert_eq!(did_value, dids[0].did);
        assert_eq!(DidType::Remote, dids[0].type_field);
    }
}
