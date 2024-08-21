use std::sync::Arc;

use autometrics::autometrics;
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, GetCredentialSchemaList,
    GetCredentialSchemaQuery, UpdateCredentialSchemaRequest,
};
use one_core::model::relation::{Related, RelationLoader};
use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, SqlErr, Unchanged,
};
use shared_types::{ClaimSchemaId, CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;

use crate::common::calculate_pages_count;
use crate::credential_schema::mapper::{
    claim_schemas_to_model_vec, claim_schemas_to_relations, credential_schema_from_models,
};
use crate::credential_schema::CredentialSchemaProvider;
use crate::entity::{claim_schema, credential_schema, credential_schema_claim_schema};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl CredentialSchemaRepository for CredentialSchemaProvider {
    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> Result<CredentialSchemaId, DataLayerError> {
        let claim_schemas = schema.claim_schemas.get().await?;

        let credential_schema: credential_schema::ActiveModel = schema.into();
        let credential_schema =
            credential_schema
                .insert(&self.db)
                .await
                .map_err(|e| match e.sql_err() {
                    Some(SqlErr::UniqueConstraintViolation(_)) => DataLayerError::AlreadyExists,
                    Some(_) | None => DataLayerError::Db(e.into()),
                })?;

        if !claim_schemas.is_empty() {
            let credential_schema_claim_schema_relations =
                claim_schemas_to_relations(&claim_schemas, &credential_schema.id);
            let claim_schema_models = claim_schemas_to_model_vec(claim_schemas);

            claim_schema::Entity::insert_many(claim_schema_models)
                .exec(&self.db)
                .await
                .map_err(|e| DataLayerError::Db(e.into()))?;

            credential_schema_claim_schema::Entity::insert_many(
                credential_schema_claim_schema_relations,
            )
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        }

        Ok(credential_schema.id)
    }

    async fn delete_credential_schema(
        &self,
        id: &CredentialSchemaId,
    ) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let credential_schema = credential_schema::ActiveModel {
            id: Unchanged(*id),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        credential_schema::Entity::update(credential_schema)
            .filter(credential_schema::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map_err(|error| match error {
                DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
                error => DataLayerError::Db(error.into()),
            })?;

        Ok(())
    }

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        let credential_schema = credential_schema::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(credential_schema) = credential_schema else {
            return Ok(None);
        };

        Ok(Some(self.convert_model(credential_schema, false)))
    }

    async fn get_credential_schema_list(
        &self,
        query_params: GetCredentialSchemaQuery,
    ) -> Result<GetCredentialSchemaList, DataLayerError> {
        let limit = query_params
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as _);

        let query = credential_schema::Entity::find()
            .filter(credential_schema::Column::DeletedAt.is_null())
            .with_list_query(&query_params)
            .order_by_desc(credential_schema::Column::CreatedDate)
            .order_by_desc(credential_schema::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let credential_schemas: Vec<credential_schema::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(GetCredentialSchemaList {
            values: credential_schemas
                .into_iter()
                .map(|credential_schema| {
                    self.convert_model(
                        credential_schema,
                        !query_params.include.as_ref().is_some_and(|include| {
                            include.contains(
                                &CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
                            )
                        }),
                    )
                })
                .collect(),
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
            total_items: items_count,
        })
    }

    async fn update_credential_schema(
        &self,
        request: UpdateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError> {
        let id = &request.id;

        let revocation_method = match request.revocation_method {
            None => Unchanged(Default::default()),
            Some(revocation_method) => Set(revocation_method),
        };

        let format = match request.format {
            None => Unchanged(Default::default()),
            Some(format) => Set(format),
        };

        let update_model = credential_schema::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            revocation_method,
            format,
            ..Default::default()
        };

        update_model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::Db(e.into()),
        })?;

        if let Some(claim_schemas) = request.claim_schemas {
            let credential_schema_claim_schema_relations =
                claim_schemas_to_relations(&claim_schemas, &request.id);
            let claim_schema_models = claim_schemas_to_model_vec(claim_schemas);

            claim_schema::Entity::insert_many(claim_schema_models)
                .exec(&self.db)
                .await
                .map_err(|e| DataLayerError::Db(e.into()))?;

            credential_schema_claim_schema::Entity::insert_many(
                credential_schema_claim_schema_relations,
            )
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        }

        Ok(())
    }

    async fn get_by_schema_id_and_organisation(
        &self,
        schema_id: &str,
        schema_type: CredentialSchemaType,
        organisation_id: OrganisationId,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        let credential_schema = credential_schema::Entity::find()
            .filter(credential_schema::Column::SchemaId.eq(schema_id))
            .filter(credential_schema::Column::SchemaType.eq(schema_type.to_string()))
            .filter(credential_schema::Column::OrganisationId.eq(organisation_id))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(credential_schema) = credential_schema else {
            return Ok(None);
        };

        Ok(self.convert_model(credential_schema, true).into())
    }
}

impl CredentialSchemaProvider {
    fn get_loaded_claim_schemas(
        &self,
        credential_schema_id: CredentialSchemaId,
    ) -> Related<Vec<CredentialSchemaClaim>> {
        struct CredentialSchemaClaimsLoader {
            credential_schema_id: CredentialSchemaId,
            claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
            db: DatabaseConnection,
        }

        #[async_trait::async_trait]
        impl RelationLoader<Vec<CredentialSchemaClaim>> for CredentialSchemaClaimsLoader {
            async fn load(&self, _: &()) -> Result<Vec<CredentialSchemaClaim>, DataLayerError> {
                let models = credential_schema_claim_schema::Entity::find()
                    .filter(
                        credential_schema_claim_schema::Column::CredentialSchemaId
                            .eq(self.credential_schema_id.to_string()),
                    )
                    .order_by_asc(credential_schema_claim_schema::Column::Order)
                    .all(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;

                let claim_schema_ids: Vec<ClaimSchemaId> =
                    models.iter().map(|model| model.claim_schema_id).collect();

                let claim_schemas = self
                    .claim_schema_repository
                    .get_claim_schema_list(claim_schema_ids, &Default::default())
                    .await?;

                Ok(claim_schemas
                    .into_iter()
                    .zip(models)
                    .map(|(claim_schema, model)| CredentialSchemaClaim {
                        schema: claim_schema,
                        required: model.required,
                    })
                    .collect())
            }
        }

        Related::from_loader_no_id(Box::new(CredentialSchemaClaimsLoader {
            credential_schema_id,
            claim_schema_repository: self.claim_schema_repository.to_owned(),
            db: self.db.to_owned(),
        }))
    }

    fn convert_model(
        &self,
        credential_schema: credential_schema::Model,
        skip_layout_properties: bool,
    ) -> CredentialSchema {
        let claim_schemas = self.get_loaded_claim_schemas(credential_schema.id);

        let organisation = Related::from_organisation_id(
            credential_schema.organisation_id,
            self.organisation_repository.to_owned(),
        );

        credential_schema_from_models(
            credential_schema,
            claim_schemas,
            organisation,
            skip_layout_properties,
        )
    }
}
