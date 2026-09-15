use std::sync::Arc;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential_schema::{
    CredentialSchema, SortableCredentialSchemaColumn, TransactionCode,
};
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::{AsyncVecLoader, Related, RelatedVec};
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::service::credential_schema::dto::CredentialSchemaFilterValue;
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::sea_query::{ColumnRef, Condition, ExprTrait, Query};
use sea_orm::{ColumnTrait, EntityTrait, JoinType, QueryFilter, QueryOrder, RelationTrait};
use shared_types::CredentialSchemaId;
use time::Duration;

use crate::TransactionManagerImpl;
use crate::claim_schema::mapper::claim_schema_from_model;
use crate::credential_schema_format::mapper::credential_schema_format_from_model;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::{claim_schema, credential_schema, credential_schema_format, localized_text};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_comparison_condition, get_equals_condition, get_string_match_condition,
};
use crate::localized_text::LocalizedTextLoader;
use crate::mapper::to_data_layer_error;

impl IntoSortingColumn for SortableCredentialSchemaColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::CreatedDate => {
                ColumnSortingBehavior::default(credential_schema::Column::CreatedDate)
            }
            Self::Name => ColumnSortingBehavior::case_insensitive(credential_schema::Column::Name),
        }
    }
}

impl IntoFilterCondition for CredentialSchemaFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(credential_schema::Column::Name, string_match)
            }
            Self::DisplayNames(language_matches) => {
                let language_matches = language_matches.into_iter().fold(
                    Condition::any(),
                    |condition, (language, string_match)| {
                        condition.add(
                            Condition::all()
                                .add(localized_text::Column::Lang.eq(language))
                                .add(get_string_match_condition(
                                    localized_text::Column::Value,
                                    string_match,
                                )),
                        )
                    },
                );

                credential_schema::Column::Id
                    .in_subquery(
                        Query::select()
                            .column(localized_text::Column::EntityId)
                            .from(localized_text::Entity)
                            .cond_where(localized_text::Column::EntityType.eq("CREDENTIAL_SCHEMA"))
                            .cond_where(localized_text::Column::Field.eq("NAME"))
                            .cond_where(language_matches)
                            .to_owned(),
                    )
                    .into_condition()
            }
            Self::EcosystemSchemaId(string_match) => get_string_match_condition(
                credential_schema_format::Column::EcosystemSchemaId,
                string_match,
            ),
            Self::EcosystemSchemaIds(schema_ids) => {
                credential_schema_format::Column::EcosystemSchemaId
                    .is_in(&schema_ids)
                    .into_condition()
            }
            Self::Formats(formats) => credential_schema_format::Column::Format
                .is_in(&formats)
                .into_condition(),
            Self::Ecosystems(ecosystems) => credential_schema::Column::Ecosystem
                .is_in(ecosystems.iter())
                .into_condition(),
            Self::OrganisationId(organisation_id) => get_equals_condition(
                credential_schema::Column::OrganisationId,
                organisation_id.to_string(),
            ),
            Self::CredentialSchemaIds(ids) => credential_schema::Column::Id
                .is_in(ids.iter())
                .into_condition(),
            Self::CreatedDate(value) => {
                get_comparison_condition(credential_schema::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(credential_schema::Column::LastModified, value)
            }
            Self::Expiration(value) => {
                get_comparison_condition(credential_schema::Column::Expiration, value)
            }
            Self::RequiresWalletInstanceAttestation(requires_wia) => get_equals_condition(
                credential_schema::Column::RequiresWalletInstanceAttestation,
                requires_wia,
            ),
            Self::KeyStorageSecurity(security_levels) => {
                let security_levels: Vec<KeyStorageSecurity> = convert_inner(security_levels);
                credential_schema::Column::KeyStorageSecurity
                    .is_in(security_levels)
                    .into_condition()
            }
            Self::UsesBatchIssuance(uses_batch_issuance) => {
                if uses_batch_issuance {
                    credential_schema::Column::BatchSize
                        .is_not_null()
                        .into_condition()
                } else {
                    credential_schema::Column::BatchSize
                        .is_null()
                        .into_condition()
                }
            }
            Self::IsMultiformatSchema(is_multiformat) => {
                let subquery = Query::select()
                    .column(credential_schema_format::Column::CredentialSchemaId)
                    .from(credential_schema_format::Entity)
                    .group_by_col(credential_schema_format::Column::CredentialSchemaId)
                    .and_having(
                        sea_orm::sea_query::Expr::col(
                            credential_schema_format::Column::CredentialSchemaId,
                        )
                        .count()
                        .gt(1_i32),
                    )
                    .to_owned();

                if is_multiformat {
                    credential_schema::Column::Id
                        .in_subquery(subquery)
                        .into_condition()
                } else {
                    credential_schema::Column::Id
                        .not_in_subquery(subquery)
                        .into_condition()
                }
            }
        }
    }
}

impl IntoJoinRelations for CredentialSchemaFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        match self {
            CredentialSchemaFilterValue::EcosystemSchemaId(_)
            | CredentialSchemaFilterValue::EcosystemSchemaIds(_)
            | CredentialSchemaFilterValue::Formats(_) => vec![JoinRelation {
                join_type: JoinType::InnerJoin,
                relation_def: credential_schema::Relation::CredentialSchemaFormat.def(),
                alias: None,
            }],
            _ => vec![],
        }
    }
}

impl From<CredentialSchema> for credential_schema::ActiveModel {
    fn from(value: CredentialSchema) -> Self {
        let (transaction_code_type, transaction_code_length, transaction_code_description) =
            match value.transaction_code {
                Some(code) => (
                    Some(code.r#type.into()),
                    Some(code.length),
                    code.description,
                ),
                None => (None, None, None),
            };

        Self {
            id: Set(value.id),
            deleted_at: Set(value.deleted_at),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            imported_source_url: Set(value.imported_source_url),
            organisation_id: Set(value.organisation.id()),
            key_storage_security: Set(convert_inner(value.key_storage_security)),
            layout_properties: Set(convert_inner(value.layout_properties)),
            allow_suspension: Set(value.allow_suspension),
            requires_wallet_instance_attestation: Set(value.requires_wallet_instance_attestation),
            transaction_code_type: Set(transaction_code_type),
            transaction_code_length: Set(transaction_code_length.map(|l| l as i32)),
            transaction_code_description: Set(transaction_code_description),
            batch_size: Set(value.batch_size),
            allow_revocation: Set(value.allow_revocation),
            embedded_disclosure_policy: Set(value.embedded_disclosure_policy),
            expiration: Set(value.expiration.map(|d| d.whole_seconds() as i32)),
            ecosystem: Set(value.ecosystem),
        }
    }
}

pub(super) fn claim_schemas_to_model_vec(
    claim_schemas: Vec<ClaimSchema>,
    credential_schema_id: &CredentialSchemaId,
    min_order: i32,
) -> Vec<claim_schema::ActiveModel> {
    claim_schemas
        .into_iter()
        .enumerate()
        .map(|(index, claim_schema)| claim_schema::ActiveModel {
            id: Set(claim_schema.id),
            created_date: Set(claim_schema.created_date),
            last_modified: Set(claim_schema.last_modified),
            key: Set(claim_schema.key),
            datatype: Set(claim_schema.data_type),
            array: Set(claim_schema.array),
            metadata: Set(claim_schema.metadata),
            credential_schema_id: Set(*credential_schema_id),
            required: Set(claim_schema.required),
            order: Set(index as i32 + min_order),
        })
        .collect()
}

pub(super) fn credential_schema_from_models(
    credential_schema: credential_schema::Model,
    skip_layout_properties: bool,
    db: TransactionManagerImpl,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Result<CredentialSchema, DataLayerError> {
    let transaction_code = match (
        credential_schema.transaction_code_type,
        credential_schema.transaction_code_length,
    ) {
        (Some(r#type), Some(length)) => Some(TransactionCode {
            r#type: r#type.into(),
            length: length as u32,
            description: credential_schema.transaction_code_description,
        }),
        (None, None) => None,
        _ => return Err(DataLayerError::MappingError),
    };

    let id = credential_schema.id;
    Ok(CredentialSchema {
        id,
        deleted_at: credential_schema.deleted_at,
        created_date: credential_schema.created_date,
        last_modified: credential_schema.last_modified,
        name: credential_schema.name,
        key_storage_security: convert_inner(credential_schema.key_storage_security),
        formats: RelatedVec::new(CredentialSchemaFormatsLoader { id, db: db.clone() }),
        claim_schemas: RelatedVec::new(ClaimSchemasLoader { id, db: db.clone() }),
        organisation: Related::new(
            credential_schema.organisation_id,
            organisation_repository.to_owned(),
        ),
        layout_properties: if skip_layout_properties {
            None
        } else {
            convert_inner(credential_schema.layout_properties)
        },
        imported_source_url: credential_schema.imported_source_url,
        allow_suspension: credential_schema.allow_suspension,
        requires_wallet_instance_attestation: credential_schema
            .requires_wallet_instance_attestation,
        transaction_code,
        batch_size: credential_schema.batch_size,
        allow_revocation: credential_schema.allow_revocation,
        embedded_disclosure_policy: credential_schema.embedded_disclosure_policy,
        expiration: credential_schema
            .expiration
            .map(|seconds| Duration::seconds(seconds as i64)),
        ecosystem: credential_schema.ecosystem,
        translations: RelatedVec::new(LocalizedTextLoader { id: id.into(), db }),
    })
}

pub(crate) struct ClaimSchemasLoader {
    pub id: CredentialSchemaId,
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncVecLoader<ClaimSchema> for ClaimSchemasLoader {
    async fn load(&self) -> Result<Vec<ClaimSchema>, DataLayerError> {
        let claim_schemas = claim_schema::Entity::find()
            .filter(claim_schema::Column::CredentialSchemaId.eq(self.id.to_string()))
            .order_by_asc(claim_schema::Column::Order)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(claim_schemas
            .into_iter()
            .map(|m| claim_schema_from_model(m, self.db.clone()))
            .collect())
    }
}

pub(crate) struct CredentialSchemaFormatsLoader {
    pub id: CredentialSchemaId,
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncVecLoader<CredentialSchemaFormat> for CredentialSchemaFormatsLoader {
    async fn load(&self) -> Result<Vec<CredentialSchemaFormat>, DataLayerError> {
        let credential_schema_formats = credential_schema_format::Entity::find()
            .filter(credential_schema_format::Column::CredentialSchemaId.eq(self.id.to_string()))
            .order_by_asc(credential_schema_format::Column::Format)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(credential_schema_formats
            .into_iter()
            .map(|m| credential_schema_format_from_model(m, self.db.clone()))
            .collect())
    }
}
