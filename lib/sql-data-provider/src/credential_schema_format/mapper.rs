use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use one_core::model::relation::{AsyncVecLoader, RelatedVec};
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use shared_types::CredentialSchemaFormatId;

use crate::TransactionManagerImpl;
use crate::entity::{credential_schema_format, credential_schema_format_claim_schema};
use crate::mapper::to_data_layer_error;

impl From<credential_schema_format_claim_schema::Model> for CredentialSchemaFormatClaimSchema {
    fn from(value: credential_schema_format_claim_schema::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            credential_schema_format_id: value.credential_schema_format_id,
            claim_schema_id: value.claim_schema_id,
            technical_key: value.technical_key,
            namespace: value.namespace,
        }
    }
}

impl From<CredentialSchemaFormat> for credential_schema_format::ActiveModel {
    fn from(value: CredentialSchemaFormat) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            credential_schema_id: Set(value.credential_schema_id),
            format: Set(value.format),
            ecosystem_schema_id: Set(value.ecosystem_schema_id),
        }
    }
}

impl From<CredentialSchemaFormatClaimSchema>
    for credential_schema_format_claim_schema::ActiveModel
{
    fn from(value: CredentialSchemaFormatClaimSchema) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            credential_schema_format_id: Set(value.credential_schema_format_id),
            claim_schema_id: Set(value.claim_schema_id),
            technical_key: Set(value.technical_key),
            namespace: Set(value.namespace),
        }
    }
}

pub(crate) fn credential_schema_format_from_model(
    model: credential_schema_format::Model,
    db: TransactionManagerImpl,
) -> CredentialSchemaFormat {
    let id = model.id;
    CredentialSchemaFormat {
        id,
        created_date: model.created_date,
        last_modified: model.last_modified,
        credential_schema_id: model.credential_schema_id,
        format: model.format,
        ecosystem_schema_id: model.ecosystem_schema_id,
        claim_mappings: RelatedVec::new(ClaimMappingsLoader {
            credential_schema_format_id: id,
            db,
        }),
    }
}

pub(crate) struct ClaimMappingsLoader {
    pub credential_schema_format_id: CredentialSchemaFormatId,
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncVecLoader<CredentialSchemaFormatClaimSchema> for ClaimMappingsLoader {
    async fn load(&self) -> Result<Vec<CredentialSchemaFormatClaimSchema>, DataLayerError> {
        let rows = credential_schema_format_claim_schema::Entity::find()
            .filter(
                credential_schema_format_claim_schema::Column::CredentialSchemaFormatId
                    .eq(self.credential_schema_format_id),
            )
            .order_by_asc(credential_schema_format_claim_schema::Column::CreatedDate)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(convert_inner(rows))
    }
}
