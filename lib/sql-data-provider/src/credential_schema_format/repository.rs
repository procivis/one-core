use autometrics::autometrics;
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::repository::credential_schema_format_repository::CredentialSchemaFormatRepository;
use one_core::repository::error::{DataLayerError, EntityKind};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use shared_types::{CredentialSchemaFormatId, CredentialSchemaId};

use crate::credential_schema_format::CredentialSchemaFormatProvider;
use crate::credential_schema_format::mapper::credential_schema_format_from_model;
use crate::entity::{credential_schema_format, credential_schema_format_claim_schema};
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl CredentialSchemaFormatRepository for CredentialSchemaFormatProvider {
    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn create_credential_schema_format(
        &self,
        request: CredentialSchemaFormat,
    ) -> Result<CredentialSchemaFormatId, DataLayerError> {
        let claim_mappings = request.claim_mappings.as_ref().await?.to_owned();
        let format_active: credential_schema_format::ActiveModel = request.into();

        let inserted_id = self
            .db
            .tx(async {
                let inserted = format_active
                    .insert(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;

                if !claim_mappings.is_empty() {
                    let mappings: Vec<credential_schema_format_claim_schema::ActiveModel> =
                        claim_mappings.into_iter().map(Into::into).collect();
                    credential_schema_format_claim_schema::Entity::insert_many(mappings)
                        .exec(&self.db)
                        .await
                        .map_err(|e| DataLayerError::Db(e.into()))?;
                }

                Ok::<_, DataLayerError>(inserted.id)
            })
            .await??;

        Ok(inserted_id)
    }

    async fn get_credential_schema_format(
        &self,
        id: &CredentialSchemaFormatId,
    ) -> Result<CredentialSchemaFormat, DataLayerError> {
        let row = credential_schema_format::Entity::find_by_id(*id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::CredentialSchemaFormat,
                id: (*id).into(),
            })?;

        Ok(credential_schema_format_from_model(row, self.db.to_owned()))
    }

    async fn list_by_credential_schema_id(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<Vec<CredentialSchemaFormat>, DataLayerError> {
        let rows = credential_schema_format::Entity::find()
            .filter(credential_schema_format::Column::CredentialSchemaId.eq(*credential_schema_id))
            .order_by_asc(credential_schema_format::Column::CreatedDate)
            .order_by_asc(credential_schema_format::Column::Format)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(rows
            .into_iter()
            .map(|model| credential_schema_format_from_model(model, self.db.to_owned()))
            .collect())
    }
}
