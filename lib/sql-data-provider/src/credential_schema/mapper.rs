use std::collections::HashMap;
use std::sync::Arc;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential_schema::{
    CredentialSchema, SortableCredentialSchemaColumn, TransactionCode, WalletAttestation,
};
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::localized_text::LocalizedText;
use one_core::model::relation::{
    AsyncBatchLoader, AsyncModelsLoader, BatchModelLoader, Related, RelatedVec,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::service::credential_schema::dto::CredentialSchemaFilterValue;
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::sea_query::{ColumnRef, Condition, ExprTrait, Query};
use sea_orm::{ColumnTrait, EntityTrait, JoinType, QueryFilter, QueryOrder, RelationTrait};
use shared_types::{CredentialSchemaId, EntityId};
use time::Duration;

use crate::TransactionManagerImpl;
use crate::claim_schema::mapper::claim_schema_with_translations_from_model;
use crate::credential_schema_format::mapper::credential_schema_format_from_model;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::{claim_schema, credential_schema, credential_schema_format, localized_text};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_comparison_condition, get_equals_condition, get_string_match_condition,
};
use crate::localized_text::{LocalizedTextLoader, load_localized_texts};
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
            key_storage_security: Set(convert_inner(
                value.wallet_attestation.key_storage_security_level,
            )),
            layout_properties: Set(convert_inner(value.layout_properties)),
            allow_suspension: Set(value.allow_suspension),
            requires_wallet_instance_attestation: Set(value
                .wallet_attestation
                .require_instance_attestation),
            preferred_key_storage_attestation_lifetime: Set(value
                .wallet_attestation
                .preferred_key_storage_attestation_lifetime
                .map(|d| d.whole_seconds() as i32)),
            preferred_instance_attestation_lifetime: Set(value
                .wallet_attestation
                .preferred_instance_attestation_lifetime
                .map(|d| d.whole_seconds() as i32)),
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

pub(super) fn claim_schema_to_update_model(claim_schema: ClaimSchema) -> claim_schema::ActiveModel {
    claim_schema::ActiveModel {
        id: Unchanged(claim_schema.id),
        last_modified: Set(claim_schema.last_modified),
        key: Set(claim_schema.key),
        datatype: Set(claim_schema.data_type),
        array: Set(claim_schema.array),
        metadata: Set(claim_schema.metadata),
        required: Set(claim_schema.required),
        ..Default::default()
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
    organisation_repository: &Arc<dyn OrganisationRepository>,
    formats: RelatedVec<CredentialSchemaFormat>,
    relations: &CredentialSchemaRelations,
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
        _ => {
            return Err(DataLayerError::MappingError(anyhow::anyhow!(
                "Transaction code type and length must both be present or absent"
            )));
        }
    };

    let id = credential_schema.id;
    Ok(CredentialSchema {
        id,
        deleted_at: credential_schema.deleted_at,
        created_date: credential_schema.created_date,
        last_modified: credential_schema.last_modified,
        name: credential_schema.name,
        wallet_attestation: WalletAttestation {
            require_instance_attestation: credential_schema.requires_wallet_instance_attestation,
            key_storage_security_level: convert_inner(credential_schema.key_storage_security),
            preferred_key_storage_attestation_lifetime: credential_schema
                .preferred_key_storage_attestation_lifetime
                .map(|seconds| Duration::seconds(seconds as i64)),
            preferred_instance_attestation_lifetime: credential_schema
                .preferred_instance_attestation_lifetime
                .map(|seconds| Duration::seconds(seconds as i64)),
        },
        formats,
        claim_schemas: RelatedVec::new(relations.claim_schemas.list(id)),
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
        transaction_code,
        batch_size: credential_schema.batch_size,
        allow_revocation: credential_schema.allow_revocation,
        embedded_disclosure_policy: credential_schema.embedded_disclosure_policy,
        expiration: credential_schema
            .expiration
            .map(|seconds| Duration::seconds(seconds as i64)),
        ecosystem: credential_schema.ecosystem,
        translations: RelatedVec::new(relations.translations.list(id.into())),
    })
}

/// Claim schemas of credential schemas, keyed by credential schema
struct ClaimSchemasLoader {
    db: TransactionManagerImpl,
    translations: Arc<BatchModelLoader<EntityId, Vec<LocalizedText>>>,
}

#[async_trait::async_trait]
impl AsyncBatchLoader<CredentialSchemaId, Vec<ClaimSchema>> for ClaimSchemasLoader {
    async fn load(
        &self,
        ids: &[CredentialSchemaId],
    ) -> Result<HashMap<CredentialSchemaId, Vec<ClaimSchema>>, DataLayerError> {
        let claim_schemas = claim_schema::Entity::find()
            .filter(claim_schema::Column::CredentialSchemaId.is_in(ids))
            .order_by_asc(claim_schema::Column::Order)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let mut by_schema: HashMap<_, Vec<_>> = HashMap::new();
        for model in claim_schemas {
            let translations = RelatedVec::new(self.translations.list(model.id.into()));
            by_schema
                .entry(model.credential_schema_id)
                .or_default()
                .push(claim_schema_with_translations_from_model(
                    model,
                    translations,
                ));
        }
        Ok(by_schema)
    }
}

/// Schemas of a credential list, their formats, translations, claim schemas and claim schema
/// translations load with one query each.
pub(crate) struct CredentialSchemasLoader {
    pub db: TransactionManagerImpl,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub skip_layout_properties: bool,
}

#[async_trait::async_trait]
impl AsyncModelsLoader<CredentialSchema> for CredentialSchemasLoader {
    async fn load(
        &self,
        ids: &[CredentialSchemaId],
    ) -> Result<Vec<CredentialSchema>, DataLayerError> {
        let models = credential_schema::Entity::find()
            .filter(credential_schema::Column::Id.is_in(ids))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let formats = BatchModelLoader::new(
            ids.iter().copied(),
            CredentialSchemaFormatsLoader {
                db: self.db.clone(),
            },
        );
        let relations = CredentialSchemaRelations::list(ids.iter().copied(), self.db.clone());
        models
            .into_iter()
            .map(|model| {
                let id = model.id;
                credential_schema_from_models(
                    model,
                    self.skip_layout_properties,
                    &self.organisation_repository,
                    RelatedVec::new(formats.list(id)),
                    &relations,
                )
            })
            .collect()
    }
}

pub(crate) struct CredentialSchemaFormatsLoader {
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncBatchLoader<CredentialSchemaId, Vec<CredentialSchemaFormat>>
    for CredentialSchemaFormatsLoader
{
    async fn load(
        &self,
        ids: &[CredentialSchemaId],
    ) -> Result<HashMap<CredentialSchemaId, Vec<CredentialSchemaFormat>>, DataLayerError> {
        let credential_schema_formats = credential_schema_format::Entity::find()
            .filter(credential_schema_format::Column::CredentialSchemaId.is_in(ids))
            .order_by_asc(credential_schema_format::Column::Format)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let mut by_schema: HashMap<_, Vec<_>> = HashMap::new();
        for model in credential_schema_formats {
            by_schema
                .entry(model.credential_schema_id)
                .or_default()
                .push(credential_schema_format_from_model(model, self.db.clone()));
        }
        Ok(by_schema)
    }
}

pub(crate) fn credential_schema_formats(
    id: CredentialSchemaId,
    db: TransactionManagerImpl,
) -> RelatedVec<CredentialSchemaFormat> {
    RelatedVec::new(BatchModelLoader::new([id], CredentialSchemaFormatsLoader { db }).list(id))
}

/// Batches serving the claim schemas and translations of credential schemas
pub(crate) struct CredentialSchemaRelations {
    translations: Arc<BatchModelLoader<EntityId, Vec<LocalizedText>>>,
    claim_schemas: Arc<BatchModelLoader<CredentialSchemaId, Vec<ClaimSchema>>>,
}

impl CredentialSchemaRelations {
    /// Every reader of a single schema's translations also reads its claim schema translations,
    /// so the first access loads both with a single query.
    pub(crate) fn single(id: CredentialSchemaId, db: TransactionManagerImpl) -> Self {
        let translations = BatchModelLoader::new(
            [EntityId::from(id)],
            CredentialSchemaTranslationsLoader {
                db: db.clone(),
                include_credential_schemas: true,
            },
        );
        Self {
            translations: translations.clone(),
            claim_schemas: BatchModelLoader::new([id], ClaimSchemasLoader { db, translations }),
        }
    }

    /// Most list readers only need the schema translations (e.g. the name): those load for all
    /// schemas with one query, the claim schema translations of all schemas with a separate one,
    /// only once any of them is accessed. The claim schemas of all schemas load with one query.
    pub(crate) fn list(
        ids: impl IntoIterator<Item = CredentialSchemaId>,
        db: TransactionManagerImpl,
    ) -> Self {
        let ids: Vec<CredentialSchemaId> = ids.into_iter().collect();
        let entity_ids: Vec<EntityId> = ids.iter().copied().map(EntityId::from).collect();
        let claim_schema_translations = BatchModelLoader::new(
            entity_ids.clone(),
            CredentialSchemaTranslationsLoader {
                db: db.clone(),
                include_credential_schemas: false,
            },
        );
        Self {
            translations: BatchModelLoader::new(entity_ids, LocalizedTextLoader { db: db.clone() }),
            claim_schemas: BatchModelLoader::new(
                ids,
                ClaimSchemasLoader {
                    db,
                    translations: claim_schema_translations,
                },
            ),
        }
    }
}

/// Translations of the claim schemas of credential schemas (and of the credential schemas
/// themselves, if `include_credential_schemas` is set), keyed by entity.
/// The ids passed to `load` are credential schema ids.
struct CredentialSchemaTranslationsLoader {
    db: TransactionManagerImpl,
    include_credential_schemas: bool,
}

#[async_trait::async_trait]
impl AsyncBatchLoader<EntityId, Vec<LocalizedText>> for CredentialSchemaTranslationsLoader {
    async fn load(
        &self,
        ids: &[EntityId],
    ) -> Result<HashMap<EntityId, Vec<LocalizedText>>, DataLayerError> {
        let claim_schema_ids = Query::select()
            .column(claim_schema::Column::Id)
            .from(claim_schema::Entity)
            .and_where(claim_schema::Column::CredentialSchemaId.is_in(ids.iter().copied()))
            .to_owned();
        let mut condition =
            Condition::any().add(localized_text::Column::EntityId.in_subquery(claim_schema_ids));
        if self.include_credential_schemas {
            condition = condition.add(localized_text::Column::EntityId.is_in(ids.iter().copied()));
        }
        load_localized_texts(condition, &self.db).await
    }
}
