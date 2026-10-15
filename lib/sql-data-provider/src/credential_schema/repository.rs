use std::collections::HashSet;

use autometrics::autometrics;
use futures::FutureExt;
use migration::supported_db_type::WithSupportedDbType;
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaListQuery, GetCredentialSchemaList,
    UpdateCredentialSchemaRequest,
};
use one_core::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Unchanged};
use shared_types::CredentialSchemaId;

use crate::common::list_query_with_custom_model;
use crate::credential_schema::CredentialSchemaProvider;
use crate::credential_schema::mapper::{
    claim_schema_to_update_model, claim_schemas_to_model_vec, credential_schema_formats,
    credential_schema_from_models,
};
use crate::entity::{
    claim_schema, credential_schema, credential_schema_format,
    credential_schema_format_claim_schema,
};
use crate::list_query_generic::{SelectWithFilterJoin, SelectWithListQuery};
use crate::localized_text::localized_texts;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl CredentialSchemaRepository for CredentialSchemaProvider {
    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> Result<CredentialSchemaId, DataLayerError> {
        let claim_schemas = schema.claim_schemas.as_ref().await?.to_owned();
        let formats = schema.formats.as_ref().await?.to_owned();
        let mut claim_mappings = vec![];
        for format in &formats {
            claim_mappings.extend(format.claim_mappings.as_ref().await?.to_owned())
        }

        let mut localized_texts = vec![];
        localized_texts.extend(schema.translations.as_ref().await?.to_owned());
        let credential_schema: credential_schema::ActiveModel = schema.into();

        let credential_schema = self
            .db
            .tx(async {
                let credential_schema = credential_schema
                    .insert(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;

                if !claim_schemas.is_empty() {
                    for claim_schema in &claim_schemas {
                        localized_texts
                            .extend(claim_schema.translations.as_ref().await?.to_owned());
                    }
                    let claim_schema_models =
                        claim_schemas_to_model_vec(claim_schemas, &credential_schema.id, 0);

                    claim_schema::Entity::insert_many(claim_schema_models)
                        .exec(&self.db)
                        .await
                        .map_err(|e| DataLayerError::Db(e.into()))?;
                }
                if !formats.is_empty() {
                    let format_models: Vec<credential_schema_format::ActiveModel> =
                        convert_inner(formats);
                    credential_schema_format::Entity::insert_many(format_models)
                        .exec(&self.db)
                        .await
                        .map_err(|e| DataLayerError::Db(e.into()))?;
                }
                self.insert_claim_mappings(claim_mappings).await?;
                if !localized_texts.is_empty() {
                    self.localized_text_repository
                        .upsert_many(localized_texts)
                        .await?;
                }
                Ok::<_, DataLayerError>(credential_schema)
            })
            .await??;
        Ok(credential_schema.id)
    }

    async fn delete_credential_schema(
        &self,
        credential_schema: &CredentialSchema,
    ) -> Result<(), DataLayerError> {
        let now = one_core::clock::now_utc();

        let credential_schema = credential_schema::ActiveModel {
            id: Unchanged(credential_schema.id),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        credential_schema::Entity::update(credential_schema)
            .validate()
            .map_err(to_update_data_layer_error)?
            .filter(credential_schema::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn get_credential_schema(
        &self,
        id: &CredentialSchemaId,
    ) -> Result<CredentialSchema, DataLayerError> {
        let credential_schema = credential_schema::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::CredentialSchema,
                id: (*id).into(),
            })?;

        let formats = credential_schema_formats(credential_schema.id, self.db.to_owned());
        let translations = localized_texts(credential_schema.id.into(), self.db.to_owned());
        credential_schema_from_models(
            credential_schema,
            false,
            self.db.to_owned(),
            &self.organisation_repository,
            formats,
            translations,
        )
    }

    async fn get_credential_schema_list(
        &self,
        query_params: CredentialSchemaListQuery,
    ) -> Result<GetCredentialSchemaList, DataLayerError> {
        let query = credential_schema::Entity::find()
            .filter(credential_schema::Column::DeletedAt.is_null())
            .with_filter_join(&query_params)
            .with_list_query(&query_params, self.db.supported_db_type())
            .order_by_desc(credential_schema::Column::CreatedDate)
            .order_by_desc(credential_schema::Column::Id);

        let skip_layout_properties = !query_params.include.as_ref().is_some_and(|include| {
            include.contains(&CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties)
        });

        list_query_with_custom_model(query, query_params, &self.db, |model| {
            let formats = credential_schema_formats(model.id, self.db.to_owned());
            let translations = localized_texts(model.id.into(), self.db.to_owned());
            credential_schema_from_models(
                model,
                skip_layout_properties,
                self.db.to_owned(),
                &self.organisation_repository,
                formats,
                translations,
            )
        })
        .await
    }

    async fn update_credential_schema(
        &self,
        id: &CredentialSchemaId,
        request: UpdateCredentialSchemaRequest,
    ) -> Result<(), DataLayerError> {
        let translations = request.translations.unwrap_or_default();
        let layout_properties = match request.layout_properties {
            None => Unchanged(Default::default()),
            Some(layout_properties) => Set(Some(layout_properties.into())),
        };

        let update_model = credential_schema::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(one_core::clock::now_utc()),
            layout_properties,
            ..Default::default()
        };

        self.db
            .tx(async {
                update_model
                    .update(&self.db)
                    .await
                    .map_err(to_update_data_layer_error)?;

                if let Some(claim_schemas) = request.claim_schemas
                    && !claim_schemas.is_empty()
                {
                    let existing_claim_schemas = claim_schema::Entity::find()
                        .filter(claim_schema::Column::CredentialSchemaId.eq(id))
                        .all(&self.db)
                        .await
                        .map_err(to_data_layer_error)?;
                    let next_order = existing_claim_schemas
                        .iter()
                        .map(|claim_schema| claim_schema.order)
                        .max()
                        .map_or(0, |order| order + 1);
                    let existing_ids: HashSet<_> = existing_claim_schemas
                        .into_iter()
                        .map(|claim_schema| claim_schema.id)
                        .collect();

                    let mut localized_texts = vec![];
                    let mut new_claim_schemas = vec![];
                    for claim_schema in claim_schemas {
                        localized_texts
                            .extend(claim_schema.translations.as_ref().await?.to_owned());
                        if existing_ids.contains(&claim_schema.id) {
                            claim_schema_to_update_model(claim_schema)
                                .update(&self.db)
                                .await
                                .map_err(to_update_data_layer_error)?;
                        } else {
                            new_claim_schemas.push(claim_schema);
                        }
                    }

                    if !new_claim_schemas.is_empty() {
                        let claim_schema_models =
                            claim_schemas_to_model_vec(new_claim_schemas, id, next_order);
                        claim_schema::Entity::insert_many(claim_schema_models)
                            .exec(&self.db)
                            .await
                            .map_err(|e| DataLayerError::Db(e.into()))?;
                    }

                    if !localized_texts.is_empty() {
                        self.localized_text_repository
                            .upsert_many(localized_texts)
                            .await?;
                    }
                }

                if let Some(formats) = request.formats
                    && !formats.is_empty()
                {
                    let mut claim_mappings = vec![];
                    for format in &formats {
                        claim_mappings.extend(format.claim_mappings.as_ref().await?.to_owned());
                    }

                    let format_models: Vec<credential_schema_format::ActiveModel> =
                        convert_inner(formats);
                    credential_schema_format::Entity::insert_many(format_models)
                        .exec(&self.db)
                        .await
                        .map_err(|e| DataLayerError::Db(e.into()))?;

                    self.insert_claim_mappings(claim_mappings).await?;
                }

                if let Some(claim_mappings) = request.claim_mappings {
                    self.insert_claim_mappings(claim_mappings).await?;
                }
                if !translations.is_empty() {
                    self.localized_text_repository
                        .upsert_many(translations)
                        .await?;
                }
                Ok::<_, DataLayerError>(())
            }
            .boxed())
            .await??;

        Ok(())
    }
}

impl CredentialSchemaProvider {
    async fn insert_claim_mappings(
        &self,
        claim_mappings: Vec<CredentialSchemaFormatClaimSchema>,
    ) -> Result<(), DataLayerError> {
        if !claim_mappings.is_empty() {
            let mapping_models: Vec<credential_schema_format_claim_schema::ActiveModel> =
                convert_inner(claim_mappings);
            credential_schema_format_claim_schema::Entity::insert_many(mapping_models)
                .exec(&self.db)
                .await
                .map_err(|e| DataLayerError::Db(e.into()))?;
        }
        Ok(())
    }
}
