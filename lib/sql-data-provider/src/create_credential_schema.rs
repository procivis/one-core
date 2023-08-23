use std::collections::HashMap;

use one_core::{
    config::{data_structure::DatatypeEntity, validator::datatype::validate_datatypes},
    repository::{
        data_provider::{CreateCredentialSchemaRequest, CreateCredentialSchemaResponse},
        error::DataLayerError,
    },
};
use sea_orm::{ActiveModelTrait, EntityTrait, Set, SqlErr};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    entity::{claim_schema, credential_schema, credential_schema_claim_schema},
    OldProvider,
};

impl OldProvider {
    pub async fn create_credential_schema(
        &self,
        request: CreateCredentialSchemaRequest,
        datatypes: &HashMap<String, DatatypeEntity>,
    ) -> Result<CreateCredentialSchemaResponse, DataLayerError> {
        let now = OffsetDateTime::now_utc();

        // move this to the credential service
        validate_datatypes(
            &request
                .claims
                .iter()
                .map(|f| &f.datatype)
                .collect::<Vec<&String>>(),
            datatypes,
        )
        .map_err(DataLayerError::DatatypeValidationError)?;

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
        .map_err(|e| match e.sql_err() {
            Some(sql_error) if matches!(sql_error, SqlErr::UniqueConstraintViolation(_)) => {
                DataLayerError::AlreadyExists
            }
            Some(_) | None => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        if !request.claims.is_empty() {
            let claim_schema_models: Vec<claim_schema::ActiveModel> = request
                .claims
                .iter()
                .map(|claim_data| claim_schema::ActiveModel {
                    id: Set(Uuid::new_v4().to_string()),
                    created_date: Set(now),
                    last_modified: Set(now),
                    key: Set(claim_data.key.clone()),
                    datatype: Set(claim_data.datatype.clone()),
                })
                .collect();

            let credential_schema_claim_schema_relations: Vec<
                credential_schema_claim_schema::ActiveModel,
            > = claim_schema_models
                .iter()
                .enumerate()
                .map(
                    |(i, claim_schema)| credential_schema_claim_schema::ActiveModel {
                        claim_schema_id: claim_schema.id.clone(),
                        credential_schema_id: Set(credential_schema.id.clone()),
                        required: Set(false),
                        order: Set(i as u32),
                    },
                )
                .collect();

            claim_schema::Entity::insert_many(claim_schema_models)
                .exec(&self.db)
                .await
                .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

            credential_schema_claim_schema::Entity::insert_many(
                credential_schema_claim_schema_relations,
            )
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;
        }

        Ok(CreateCredentialSchemaResponse {
            id: credential_schema.id,
        })
    }
}

#[cfg(test)]
mod tests {
    use one_core::repository::data_provider::{Format, RevocationMethod};
    use sea_orm::EntityTrait;

    use crate::test_utilities::*;

    use crate::entity::{ClaimSchema, CredentialSchema};

    use super::*;
    use one_core::repository::data_provider::*;

    fn create_schema(organization_id: &Uuid, name: &str) -> CreateCredentialSchemaRequest {
        CreateCredentialSchemaRequest {
            name: name.to_owned(),
            format: Format::Jwt,
            revocation_method: RevocationMethod::StatusList2021,
            organisation_id: organization_id.to_owned(),
            claims: vec![
                CredentialClaimSchemaRequest {
                    key: "1".to_string(),
                    datatype: "STRING".into(),
                },
                CredentialClaimSchemaRequest {
                    key: "2".to_string(),
                    datatype: "NUMBER".into(),
                },
            ],
        }
    }

    #[tokio::test]
    async fn create_credential_schema_test_simple_without_claims() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let datatypes = get_datatypes();

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

        let mut schema = create_schema(&organisation_id, "Credential1");
        schema.claims.clear();

        assert!(data_layer
            .create_credential_schema(schema, &datatypes)
            .await
            .is_ok());

        let credential_schemas_count = CredentialSchema::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(1, credential_schemas_count);
    }

    // Duplicated names will be reworked later
    #[tokio::test]
    #[ignore]
    async fn create_credential_schema_test_simple_without_claims_duplicated_name() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let datatypes = get_datatypes();

        let organisation_id = Uuid::new_v4();
        let organisation_id2 = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(organisation_id))
            .await
            .unwrap();

        insert_organisation_to_database(&data_layer.db, Some(organisation_id2))
            .await
            .unwrap();

        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id, "Credential1"), &datatypes)
            .await
            .is_ok());

        // The same name is not allowed
        assert!(matches!(
            data_layer
                .create_credential_schema(
                    create_schema(&organisation_id, "Credential1"),
                    &datatypes
                )
                .await,
            Err(DataLayerError::AlreadyExists)
        ));

        // Case sensitive
        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id, "credential1"), &datatypes)
            .await
            .is_ok());

        // Same name for different organisation is ok
        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id2, "Credential1"), &datatypes)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn create_credential_schema_test_simple_with_claims() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let datatypes = get_datatypes();

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
            .create_credential_schema(create_schema(&organisation_id, "Credential1"), &datatypes)
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
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let datatypes = get_datatypes();

        let organisation_id = Uuid::new_v4();

        insert_organisation_to_database(&data_layer.db, Some(organisation_id))
            .await
            .unwrap();

        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id, "Credential1"), &datatypes)
            .await
            .is_ok());
        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id, "Credential2"), &datatypes)
            .await
            .is_ok());
        assert!(data_layer
            .create_credential_schema(create_schema(&organisation_id, "Credential3"), &datatypes)
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
