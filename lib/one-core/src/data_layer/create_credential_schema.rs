use sea_orm::{ActiveModelTrait, Set};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::data_layer::{
    data_model::CreateCredentialSchemaRequest,
    entities::{claim_schema, credential_schema},
    DataLayer, DataLayerError,
};

impl DataLayer {
    pub async fn create_credential_schema(
        &self,
        request: CreateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let credential_schema = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            name: Set(request.name),
            created_date: Set(now),
            last_modified: Set(now),
            format: Set(request.format.into()),
            deleted_at: Set(None),
            revocation_method: Set(request.revocation_method.into()),
            organisation_id: Set(request.organisation_id.to_string()),
        }
        .insert(&self.db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        for claim_schema in request.claims {
            claim_schema::ActiveModel {
                id: Set(Uuid::new_v4().to_string()),
                created_date: Set(now),
                last_modified: Set(now),
                key: Set(claim_schema.key),
                datatype: Set(claim_schema.datatype.into()),
                credential_id: Set(credential_schema.id.to_string()),
            }
            .insert(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::EntityTrait;

    use crate::data_layer::entities::claim_schema::Datatype;
    use crate::data_layer::entities::credential_schema::{Format, RevocationMethod};
    use crate::data_layer::entities::{
        claim_schema, credential_schema, ClaimSchema, CredentialSchema,
    };

    use super::*;
    use crate::data_layer::data_model::*;
    use crate::data_layer::test_utilities::*;

    fn create_schema(organization_id: &Uuid) -> CreateCredentialSchemaRequest {
        CreateCredentialSchemaRequest {
            name: "credential".to_string(),
            format: Format::Jwt.into(),
            revocation_method: RevocationMethod::StatusList2021.into(),
            organisation_id: organization_id.to_owned(),
            claims: vec![
                CredentialClaimSchemaRequest {
                    key: "1".to_string(),
                    datatype: Datatype::String.into(),
                },
                CredentialClaimSchemaRequest {
                    key: "2".to_string(),
                    datatype: Datatype::Number.into(),
                },
            ],
        }
    }

    #[tokio::test]
    async fn create_credential_schema_test_simple_without_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let credential_schemas_count = CredentialSchema::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, credential_schemas_count);

        let organisation_id = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(organisation_id))
            .await
            .unwrap();

        let mut schema = create_schema(&organisation_id);
        schema.claims.clear();

        assert!(data_layer.create_credential_schema(schema).await.is_ok());

        let credential_schemas_count = CredentialSchema::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(1, credential_schemas_count);
    }

    #[tokio::test]
    async fn create_credential_schema_test_simple_with_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let credential_schemas_count = CredentialSchema::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, credential_schemas_count);
        let claim_schemas_count = ClaimSchema::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, claim_schemas_count);

        let organisation_id = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(organisation_id))
            .await
            .unwrap();

        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id))
            .await
            .is_ok());

        let credential_schemas_count = CredentialSchema::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(1, credential_schemas_count);
        let claim_schemas_count = ClaimSchema::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(2, claim_schemas_count);
    }

    #[tokio::test]
    async fn create_credential_schema_test_related_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(organisation_id))
            .await
            .unwrap();

        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id))
            .await
            .is_ok());
        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id))
            .await
            .is_ok());
        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id))
            .await
            .is_ok());

        let schemas: Vec<(credential_schema::Model, Vec<claim_schema::Model>)> =
            CredentialSchema::find()
                .find_with_related(ClaimSchema)
                .all(&data_layer.db)
                .await
                .unwrap();
        assert_eq!(3, schemas.len());
        assert_eq!(2, schemas[0].1.len());
        assert_eq!(2, schemas[1].1.len());
        assert_eq!(2, schemas[2].1.len());
    }
}
