use anyhow::anyhow;
use autometrics::autometrics;
use futures::stream::{self, StreamExt};
use itertools::Either;
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, CredentialSchemaType,
    GetCredentialSchemaList, GetCredentialSchemaQuery, UpdateCredentialSchemaRequest,
};
use one_core::model::organisation::Organisation;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, PaginatorTrait, QueryFilter,
    QueryOrder, SqlErr, Unchanged,
};
use shared_types::{ClaimSchemaId, CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;

use crate::common::calculate_pages_count;
use crate::credential_schema::mapper::{
    claim_schemas_to_model_vec, claim_schemas_to_relations, credential_schema_from_models,
};
use crate::credential_schema::CredentialSchemaProvider;
use crate::entity::credential_schema::LayoutType;
use crate::entity::{
    claim_schema, credential_schema, credential_schema_claim_schema, organisation,
};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
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
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        let credential_schema = credential_schema::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(credential_schema) = credential_schema else {
            return Ok(None);
        };

        let claim_schemas = if let Some(claim_schema_relations) = &relations.claim_schemas {
            let models = credential_schema_claim_schema::Entity::find()
                .filter(
                    credential_schema_claim_schema::Column::CredentialSchemaId.eq(id.to_string()),
                )
                .order_by_asc(credential_schema_claim_schema::Column::Order)
                .all(&self.db)
                .await
                .map_err(to_data_layer_error)?;

            let claim_schema_ids: Vec<ClaimSchemaId> =
                models.iter().map(|model| model.claim_schema_id).collect();

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
                .ok_or(DataLayerError::Db(anyhow!(
                    "Missing organisation for credential schema {id}"
                )))?;

            Some(
                self.organisation_repository
                    .get_organisation(&model.id, organisation_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "credential_schema-organisation",
                        id: model.id.to_string(),
                    })?,
            )
        } else {
            None
        };

        let credential_schema =
            credential_schema_from_models(credential_schema, claim_schemas, organisation, false);

        Ok(Some(credential_schema))
    }

    async fn get_credential_schema_list(
        &self,
        query_params: GetCredentialSchemaQuery,
        relations: &CredentialSchemaRelations,
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

        let claims = if let Some(claim_schemas) = &relations.claim_schemas {
            Either::Left(
                stream::iter(&credential_schemas)
                    .then(|credential_schema| async {
                        let models = credential_schema_claim_schema::Entity::find()
                            .filter(
                                credential_schema_claim_schema::Column::CredentialSchemaId
                                    .eq(credential_schema.id.to_string()),
                            )
                            .order_by_asc(credential_schema_claim_schema::Column::Order)
                            .all(&self.db)
                            .await
                            .map_err(to_data_layer_error)?;

                        let claim_schema_ids: Vec<ClaimSchemaId> =
                            models.iter().map(|model| model.claim_schema_id).collect();

                        let claim_schemas = self
                            .claim_schema_repository
                            .get_claim_schema_list(claim_schema_ids, claim_schemas)
                            .await?;

                        Ok::<_, DataLayerError>(Some(
                            claim_schemas
                                .into_iter()
                                .zip(models)
                                .map(|(claim_schema, model)| CredentialSchemaClaim {
                                    schema: claim_schema,
                                    required: model.required,
                                })
                                .collect::<Vec<_>>(),
                        ))
                    })
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?,
            )
        } else {
            Either::Right(std::iter::repeat(None::<Vec<CredentialSchemaClaim>>))
        };

        let organisations = if let Some(organisations) = &relations.organisation {
            Either::Left(
                stream::iter(&credential_schemas)
                    .then(|credential_schema| async {
                        let model = credential_schema
                            .find_related(organisation::Entity)
                            .one(&self.db)
                            .await
                            .map_err(to_data_layer_error)?
                            .ok_or(DataLayerError::Db(anyhow!(
                                "Missing organisation for credential schema {}",
                                credential_schema.id
                            )))?;

                        Ok::<_, DataLayerError>(Some(
                            self.organisation_repository
                                .get_organisation(&model.id, organisations)
                                .await?
                                .ok_or(DataLayerError::MissingRequiredRelation {
                                    relation: "credential_schema-organisation",
                                    id: model.id.to_string(),
                                })?,
                        ))
                    })
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?,
            )
        } else {
            Either::Right(std::iter::repeat(None::<Organisation>))
        };

        Ok(GetCredentialSchemaList {
            values: credential_schemas
                .into_iter()
                .zip(claims.into_iter())
                .zip(organisations.into_iter())
                .map(|((credential_schema, claim_schemas), organisation)| {
                    credential_schema_from_models(
                        credential_schema,
                        claim_schemas,
                        organisation,
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

        let layout_type = match request.layout_type {
            None => Unchanged(LayoutType::Card),
            Some(layout_type) => Set(layout_type.into()),
        };

        let layout_properties = match request.layout_properties {
            None => Unchanged(Default::default()),
            Some(layout_properties) => Set(Some(layout_properties.into())),
        };

        let update_model = credential_schema::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            revocation_method,
            format,
            layout_type,
            layout_properties,
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

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
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, DataLayerError> {
        let credential_schema = credential_schema::Entity::find()
            .filter(credential_schema::Column::SchemaId.eq(schema_id))
            .filter(credential_schema::Column::SchemaType.eq(schema_type.to_string()))
            .filter(credential_schema::Column::OrganisationId.eq(organisation_id))
            .filter(credential_schema::Column::DeletedAt.is_null())
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(credential_schema) = credential_schema else {
            return Ok(None);
        };

        let mut claim_schemas = None;
        if relations.claim_schemas.is_some() {
            let schemas = credential_schema
                .find_related(claim_schema::Entity)
                .select_also(credential_schema_claim_schema::Entity)
                .all(&self.db)
                .await
                .map_err(to_data_layer_error)?;

            if schemas.is_empty() {
                return Err(DataLayerError::MappingError);
            }

            claim_schemas = Some(
                schemas
                    .into_iter()
                    .map(|(claim_schema, credential_schema_claim_schema)| {
                        let credential_schema_claim_schema =
                            credential_schema_claim_schema.ok_or(DataLayerError::MappingError)?;

                        Ok(CredentialSchemaClaim {
                            schema: claim_schema.into(),
                            required: credential_schema_claim_schema.required,
                        })
                    })
                    .collect::<Result<_, DataLayerError>>()?,
            );
        }

        let mut organisation = None;
        if relations.organisation.is_some() {
            organisation = Some(
                credential_schema
                    .find_related(organisation::Entity)
                    .one(&self.db)
                    .await
                    .map_err(to_data_layer_error)?
                    .map(Into::into)
                    .ok_or(DataLayerError::MappingError)?,
            );
        }

        Ok(
            credential_schema_from_models(credential_schema, claim_schemas, organisation, true)
                .into(),
        )
    }
}
