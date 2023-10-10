use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, ModelTrait,
    PaginatorTrait, QueryFilter, QueryOrder, SqlErr,
};
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

use one_core::{
    common_mapper::vector_try_into,
    model::{
        claim_schema::ClaimSchemaId,
        credential_schema::{
            CredentialSchema, CredentialSchemaClaim, CredentialSchemaId, CredentialSchemaRelations,
            GetCredentialSchemaList, GetCredentialSchemaQuery,
        },
        organisation::Organisation,
    },
    repository::{credential_schema_repository::CredentialSchemaRepository, error::DataLayerError},
};

use crate::{
    credential_schema::{
        mapper::{
            claim_schemas_to_model_vec, claim_schemas_to_relations, create_list_response,
            credential_schema_from_models,
        },
        CredentialSchemaProvider,
    },
    entity::{claim_schema, credential_schema, credential_schema_claim_schema, organisation},
    error_mapper::to_data_layer_error,
    list_query::SelectWithListQuery,
};

async fn delete_credential_schema_from_database(
    db: &DatabaseConnection,
    credential_schema: credential_schema::Model,
    now: OffsetDateTime,
) -> Option<DbErr> {
    let mut value: credential_schema::ActiveModel = credential_schema.into();
    value.deleted_at = Set(Some(now));
    value.reset(credential_schema::Column::DeletedAt);

    value.update(db).await.err()
}

#[async_trait::async_trait]
impl CredentialSchemaRepository for CredentialSchemaProvider {
    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> Result<CredentialSchemaId, DataLayerError> {
        let claim_schemas = schema
            .claim_schemas
            .to_owned()
            .ok_or(DataLayerError::MappingError)?;

        let credential_schema: credential_schema::ActiveModel = schema.try_into()?;
        let credential_schema =
            credential_schema
                .insert(&self.db)
                .await
                .map_err(|e| match e.sql_err() {
                    Some(SqlErr::UniqueConstraintViolation(_)) => DataLayerError::AlreadyExists,
                    Some(_) | None => DataLayerError::GeneralRuntimeError(e.to_string()),
                })?;

        if !claim_schemas.is_empty() {
            let credential_schema_claim_schema_relations =
                claim_schemas_to_relations(&claim_schemas, &credential_schema.id);
            let claim_schema_models = claim_schemas_to_model_vec(claim_schemas);

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

        Uuid::from_str(&credential_schema.id).map_err(|_| DataLayerError::MappingError)
    }

    async fn delete_credential_schema(
        &self,
        id: &CredentialSchemaId,
    ) -> Result<(), DataLayerError> {
        let credential_schema = credential_schema::Entity::find_by_id(id.to_string())
            .filter(credential_schema::Column::DeletedAt.is_null())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        let now = OffsetDateTime::now_utc();

        match delete_credential_schema_from_database(&self.db, credential_schema, now).await {
            None => Ok(()),
            Some(error) => Err(DataLayerError::GeneralRuntimeError(error.to_string())),
        }
    }

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
        relations: &CredentialSchemaRelations,
    ) -> Result<CredentialSchema, DataLayerError> {
        let credential_schema = credential_schema::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or(DataLayerError::RecordNotFound)?;

        let claim_schemas = if let Some(claim_schema_relations) = &relations.claim_schemas {
            let models = credential_schema_claim_schema::Entity::find()
                .filter(
                    credential_schema_claim_schema::Column::CredentialSchemaId.eq(id.to_string()),
                )
                .order_by_asc(credential_schema_claim_schema::Column::Order)
                .all(&self.db)
                .await
                .map_err(to_data_layer_error)?;

            let claim_schema_ids: Vec<ClaimSchemaId> = vector_try_into(models.clone())?;
            let claim_schemas = self
                .claim_schema_repository
                .get_claim_schema_list(claim_schema_ids, claim_schema_relations)
                .await?;

            Some(
                claim_schemas
                    .into_iter()
                    .zip(models)
                    .map(|(claim_schema, model)| CredentialSchemaClaim {
                        schema: claim_schema,
                        required: model.required,
                    })
                    .collect(),
            )
        } else {
            None
        };

        let organisation = if let Some(organisation_relations) = &relations.organisation {
            let model = credential_schema
                .find_related(organisation::Entity)
                .one(&self.db)
                .await
                .map_err(to_data_layer_error)?
                .ok_or(DataLayerError::RecordNotFound)?;
            let organisation: Organisation = model.try_into()?;
            Some(
                self.organisation_repository
                    .get_organisation(&organisation.id, organisation_relations)
                    .await?,
            )
        } else {
            None
        };

        credential_schema_from_models(credential_schema, claim_schemas, organisation)
    }

    async fn get_credential_schema_list(
        &self,
        query_params: GetCredentialSchemaQuery,
    ) -> Result<GetCredentialSchemaList, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = credential_schema::Entity::find()
            .filter(credential_schema::Column::DeletedAt.is_null())
            .with_organisation_id(&query_params, &credential_schema::Column::OrganisationId)
            .with_list_query(
                &query_params,
                &Some(vec![
                    credential_schema::Column::Name,
                    credential_schema::Column::Format,
                ]),
            )
            .order_by_desc(credential_schema::Column::CreatedDate)
            .order_by_desc(credential_schema::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let credential_schemas: Vec<credential_schema::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(create_list_response(credential_schemas, limit, items_count))
    }
}
