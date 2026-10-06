use std::sync::Arc;

use one_core::model::claim::Claim;
use one_core::model::credential::{
    Clearable, Credential, CredentialCommon, CredentialFilterValue, HolderBinding,
    HolderCredentialData, IssuerCredentialData, IssuerData, IssuerIdentity,
    SortableCredentialColumn, VerifierCredentialData,
};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::identifier::Identifier;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::{AsyncModelLoader, AsyncModelsLoader, Related, RelatedVec};
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::claim_repository::{ClaimRepository, CredentialClaimsLoader};
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::sea_query::{
    Alias, ColumnRef, Expr, ExprTrait, NullOrdering, Order, Query, SelectStatement, SimpleExpr,
    SubQueryStatement,
};
use sea_orm::{
    ActiveValue, ColumnTrait, EntityTrait, JoinType, QueryFilter, RelationTrait, Set, Value,
};
use shared_types::{CredentialId, CredentialSchemaFormatId, OrganisationId};

use crate::TransactionManagerImpl;
use crate::credential_schema_format::mapper::credential_schema_format_from_model;
use crate::entity::{claim, credential, credential_schema, credential_schema_format, identifier};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_blob_match_condition, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};
use crate::mapper::to_data_layer_error;

pub(super) fn from_clearable<T>(clearable: Clearable<Option<T>>) -> ActiveValue<Option<T>>
where
    Option<T>: Into<Value>,
{
    match clearable {
        Clearable::ForceSet(value) => Set(value),
        Clearable::DontTouch => ActiveValue::Unchanged(Default::default()),
    }
}

impl IntoSortingColumn for SortableCredentialColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::CreatedDate => ColumnSortingBehavior::default(credential::Column::CreatedDate),
            Self::SchemaName => {
                ColumnSortingBehavior::case_insensitive(credential_schema::Column::Name)
            }
            Self::Issuer => ColumnSortingBehavior::case_insensitive(identifier::Column::Name),
            Self::State => ColumnSortingBehavior::default(credential::Column::State),
            Self::ExpiresAt => ColumnSortingBehavior::default(credential::Column::ExpiresAt),
        }
    }
}

impl IntoFilterCondition for CredentialFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::CredentialSchemaName(string_match) => {
                get_string_match_condition(credential_schema::Column::Name, string_match)
            }
            Self::ClaimName(string_match) => {
                get_string_match_condition(claim::Column::Path, string_match)
            }
            Self::ClaimValue(string_match) => {
                get_blob_match_condition(claim::Column::Value, string_match, 255)
            }
            Self::OrganisationId(organisation_id) => get_equals_condition(
                credential::Column::OrganisationId,
                organisation_id.to_string(),
            ),
            Self::Roles(roles) => credential::Column::Role
                .is_in(
                    roles
                        .into_iter()
                        .map(credential::CredentialRole::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::CredentialIds(ids) => credential::Column::Id.is_in(ids.iter()).into_condition(),
            Self::ParentCredential(parent_id) => {
                get_equals_condition(credential::Column::ParentId, parent_id.to_string())
            }
            Self::ParentCredentials(parent_ids) => credential::Column::ParentId
                .is_in(parent_ids.iter().map(ToString::to_string))
                .into_condition(),
            Self::CredentialSchemaIds(ids) => credential::Column::CredentialSchemaId
                .is_in(ids.iter())
                .into_condition(),
            Self::Ecosystems(ecosystems) => credential::Column::Ecosystem
                .is_in(ecosystems.iter())
                .into_condition(),
            Self::SchemaId(schema_id) => credential::Column::CredentialSchemaId
                .in_subquery(
                    Query::select()
                        .column(credential_schema_format::Column::CredentialSchemaId)
                        .from(credential_schema_format::Entity)
                        .cond_where(get_equals_condition(
                            credential_schema_format::Column::EcosystemSchemaId,
                            schema_id,
                        ))
                        .to_owned(),
                )
                .into_condition(),
            Self::IssuerIds(ids) => credential::Column::IssuerIdentifierId
                .is_in(ids.iter())
                .into_condition(),
            Self::States(states) => credential::Column::State
                .is_in(
                    states
                        .into_iter()
                        .map(credential::CredentialState::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::Types(types) => credential::Column::Type
                .is_in(
                    types
                        .into_iter()
                        .map(credential::CredentialType::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::Consumed(consumed) => (if consumed {
                credential::Column::ConsumedAt.is_not_null()
            } else {
                credential::Column::ConsumedAt.is_null()
            })
            .into_condition(),
            Self::SuspendEndDate(comparison) => {
                get_comparison_condition(credential::Column::SuspendEndDate, comparison)
            }
            Self::Profiles(profiles) => credential::Column::Profile
                .is_in(profiles.iter())
                .into_condition(),
            Self::CreatedDate(value) => {
                get_comparison_condition(credential::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(credential::Column::LastModified, value)
            }
            Self::IssuanceDate(value) => {
                get_comparison_condition(credential::Column::IssuanceDate, value)
            }
            Self::RevocationDate(value) => {
                get_comparison_condition(credential::Column::LastModified, value)
                    .and(credential::Column::State.eq(credential::CredentialState::Revoked))
                    .into_condition()
            }
            Self::ExpiresAt(value) => {
                get_comparison_condition(credential::Column::ExpiresAt, value)
            }
            Self::FormatIds(formats) => credential::Column::Format
                .is_in(formats.iter().map(ToString::to_string))
                .into_condition(),
            Self::Formats(formats) => credential_schema_format::Column::Format
                .is_in(formats)
                .into_condition(),
            Self::HasUnconsumedBatchItems(true) => credential::Column::Id
                .in_subquery(unconsumed_item_select())
                .into_condition(),
            Self::HasUnconsumedBatchItems(false) => credential::Column::Id
                .not_in_subquery(unconsumed_item_select())
                .into_condition(),
            Self::EarliestExpiringBatchItemPerFormat => {
                Expr::col((credential::Entity, credential::Column::Id))
                    .eq(SimpleExpr::SubQuery(
                        None,
                        Box::new(SubQueryStatement::SelectStatement(
                            earliest_expiring_batch_item(),
                        )),
                    ))
                    .into_condition()
            }
            Self::Deleted(false) => credential::Column::DeletedAt.is_null().into_condition(),
            Self::Deleted(true) => credential::Column::DeletedAt.is_not_null().into_condition(),
        }
    }
}

fn unconsumed_item_select() -> SelectStatement {
    Query::select()
        .distinct()
        .column(credential::Column::ParentId)
        .from(credential::Entity)
        .cond_where(
            credential::Column::ConsumedAt
                .is_null()
                .and(credential::Column::State.eq(credential::CredentialState::Accepted)),
        )
        .to_owned()
}

/// Correlated with the outer credential row by parent and format. LIMIT 1 selects
/// the available item with the earliest expiry for that group, placing items
/// without an expiry last and breaking ties by descending ID. The outer query
/// keeps every row matching its group's ID.
/// Example query produced by this filter:
/// ``` SQL
/// SELECT "credential"."id"
/// FROM "credential"
///          INNER JOIN "credential_schema" ON "credential"."credential_schema_id" = "credential_schema"."id"
///          LEFT JOIN "identifier" ON "credential"."issuer_identifier_id" = "identifier"."id"
/// WHERE "credential"."type" IN ('SINGLE')
///    OR "credential"."id" = (
///     -- This subquery selects the earliest-expiring accepted, non-deleted, unconsumed item
///     -- Then the credential id must be equal to the outer row --> hence it filters out all rows that are different items
///     -- Given it is scoped by format of the outer select, this leaves exactly one row per format.
///     SELECT "available_item"."id"
///     FROM "credential" AS "available_item"
///     WHERE "available_item"."parent_id" = "credential"."parent_id"
///       AND "available_item"."format" = "credential"."format"
///       AND "available_item"."type" = 'BATCH_ITEM'
///       AND "available_item"."state" = 'ACCEPTED'
///       AND "available_item"."deleted_at" IS NULL
///       AND "available_item"."consumed_at" IS NULL
///     ORDER BY "available_item"."expires_at" ASC NULLS LAST, "available_item"."id" DESC
///     LIMIT 1)
/// ```
fn earliest_expiring_batch_item() -> SelectStatement {
    let item = Alias::new("available_item");
    Query::select()
        .column((item.clone(), credential::Column::Id))
        .from_as(credential::Entity, item.clone())
        .and_where(
            Expr::col((item.clone(), credential::Column::ParentId))
                .equals((credential::Entity, credential::Column::ParentId)),
        )
        .and_where(
            Expr::col((item.clone(), credential::Column::Format))
                .equals((credential::Entity, credential::Column::Format)),
        )
        .and_where(
            Expr::col((item.clone(), credential::Column::Type))
                .eq(credential::CredentialType::BatchItem),
        )
        .and_where(
            Expr::col((item.clone(), credential::Column::State))
                .eq(credential::CredentialState::Accepted),
        )
        .and_where(Expr::col((item.clone(), credential::Column::DeletedAt)).is_null())
        .and_where(Expr::col((item.clone(), credential::Column::ConsumedAt)).is_null())
        .order_by_with_nulls(
            (item.clone(), credential::Column::ExpiresAt),
            Order::Asc,
            NullOrdering::Last,
        )
        .order_by((item, credential::Column::Id), Order::Desc)
        .limit(1)
        .to_owned()
}

impl IntoJoinRelations for CredentialFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        match self {
            Self::Formats(_) => vec![JoinRelation {
                // Preserve credentials without a format when another OR branch matches.
                join_type: JoinType::LeftJoin,
                relation_def: credential::Relation::CredentialSchemaFormat.def(),
                alias: None,
            }],
            // Claim filters use an explicit join to the effective claim owner.
            _ => vec![],
        }
    }
}

/// Match the holder detail view: use the newest nondeleted item's own claims.
/// Other roles are unchanged.
pub(crate) fn effective_claim_owner() -> SimpleExpr {
    let item = Alias::new("claim_source_item");
    let latest = Query::select()
        .column((item.clone(), credential::Column::Id))
        .from_as(credential::Entity, item.clone())
        .and_where(
            Expr::col((item.clone(), credential::Column::ParentId))
                .equals((credential::Entity, credential::Column::Id)),
        )
        .and_where(Expr::col((item.clone(), credential::Column::DeletedAt)).is_null())
        .order_by((item.clone(), credential::Column::CreatedDate), Order::Desc)
        .order_by((item, credential::Column::Id), Order::Desc)
        .limit(1)
        .to_owned();
    Expr::case(
        Expr::col((credential::Entity, credential::Column::Role))
            .eq(credential::CredentialRole::Holder)
            .and(
                Expr::col((credential::Entity, credential::Column::Type))
                    .eq(credential::CredentialType::BatchParent),
            ),
        SimpleExpr::SubQuery(None, Box::new(SubQueryStatement::SelectStatement(latest))),
    )
    .finally(Expr::col((credential::Entity, credential::Column::Id)))
    .into()
}

/// Builds the lazily loaded claims relation of a credential. Shared between the credential
/// mapper and the credential list projection.
pub(crate) fn credential_claims(
    credential_id: CredentialId,
    claim_repository: &Arc<dyn ClaimRepository>,
) -> RelatedVec<Claim> {
    RelatedVec::new(CredentialClaimsLoader {
        credential_id,
        claim_repository: claim_repository.to_owned(),
    })
}

pub(super) struct CredentialRepositories<'a> {
    pub claim_repository: &'a Arc<dyn ClaimRepository>,
    pub interaction_repository: &'a Arc<dyn InteractionRepository>,
    pub certificate_repository: &'a Arc<dyn CertificateRepository>,
    pub identifier_repository: &'a Arc<dyn IdentifierRepository>,
    pub key_repository: &'a Arc<dyn KeyRepository>,
    pub credential_repository: Arc<dyn CredentialRepository>,
}

pub(super) fn credential_from_model(
    credential: credential::Model,
    schema: impl AsyncModelLoader<CredentialSchema> + 'static,
    issuer: impl AsyncModelLoader<Identifier> + 'static,
    format: impl AsyncModelLoader<CredentialSchemaFormat> + 'static,
    repositories: CredentialRepositories<'_>,
) -> Result<Credential, DataLayerError> {
    let common = CredentialCommon {
        id: credential.id,
        created_date: credential.created_date,
        issuance_date: credential.issuance_date,
        expires_at: credential.expires_at,
        last_modified: credential.last_modified,
        deleted_at: credential.deleted_at,
        protocol: credential.protocol,
        redirect_uri: credential.redirect_uri,
        state: credential.state.into(),
        profile: credential.profile,
        schema: Related::new(credential.credential_schema_id, schema),
        interaction: credential
            .interaction_id
            .map(|id| Related::new(id, repositories.interaction_repository.clone())),
        ecosystem: credential.ecosystem,
    };
    if credential.role == credential::CredentialRole::Verifier {
        if credential.r#type != credential::CredentialType::Single {
            return Err(DataLayerError::MappingError);
        }
        return Ok(Credential::Verifier {
            common,
            verifier_data: VerifierCredentialData {
                issuer: IssuerIdentity {
                    identifier: Related::new(
                        credential
                            .issuer_identifier_id
                            .ok_or(DataLayerError::MappingError)?,
                        issuer,
                    ),
                    certificate: credential
                        .issuer_certificate_id
                        .map(|id| Related::new(id, repositories.certificate_repository.clone())),
                },
                format: Related::new(
                    credential.format.ok_or(DataLayerError::MappingError)?,
                    format,
                ),
                claims: credential_claims(credential.id, repositories.claim_repository),
                holder_identifier: credential
                    .holder_identifier_id
                    .map(|id| Related::new(id, repositories.identifier_repository.clone())),
            },
        });
    }
    if credential.role == credential::CredentialRole::Issuer {
        let issuer = IssuerData {
            identifier: Related::new(
                credential
                    .issuer_identifier_id
                    .ok_or(DataLayerError::MappingError)?,
                issuer,
            ),
            certificate: credential
                .issuer_certificate_id
                .map(|id| Related::new(id, repositories.certificate_repository.clone())),
            signing_key: Related::new(
                credential.key_id.ok_or(DataLayerError::MappingError)?,
                repositories.key_repository.clone(),
            ),
        };
        if credential.r#type == credential::CredentialType::BatchParent {
            return Ok(Credential::IssuerBatchParent {
                common,
                issuer,
                suspend_end_date: credential.suspend_end_date,
                webhook_url: credential.webhook_url,
                subscriber_information: credential.subscriber_information,
                claims: credential_claims(credential.id, repositories.claim_repository),
            });
        }
        let data = IssuerCredentialData {
            format: Related::new(
                credential.format.ok_or(DataLayerError::MappingError)?,
                format,
            ),
            holder_identifier: credential
                .holder_identifier_id
                .map(|id| Related::new(id, repositories.identifier_repository.clone())),
            credential_blob_id: credential.credential_blob_id,
            wallet_key_attestation_blob_id: credential.wallet_key_attestation_blob_id,
            wallet_instance_attestation_blob_id: credential.wallet_instance_attestation_blob_id,
            suspend_end_date: credential.suspend_end_date,
        };
        return Ok(match credential.r#type {
            credential::CredentialType::BatchItem => Credential::IssuerBatchItem {
                common,
                issuer,
                parent: Related::new(
                    credential.parent_id.ok_or(DataLayerError::MappingError)?,
                    repositories.credential_repository,
                ),
                credential: data,
            },
            credential::CredentialType::Single => Credential::IssuerSingle {
                common,
                issuer,
                webhook_url: credential.webhook_url,
                subscriber_information: credential.subscriber_information,
                claims: credential_claims(credential.id, repositories.claim_repository),
                credential: data,
            },
            credential::CredentialType::BatchParent => unreachable!(),
        });
    }
    if credential.r#type == credential::CredentialType::BatchParent {
        return Ok(Credential::HolderBatchParent { common });
    }
    let binding = match (credential.holder_identifier_id, credential.key_id) {
        (Some(identifier), Some(key)) => Some(HolderBinding {
            identifier: Related::new(identifier, repositories.identifier_repository.clone()),
            key: Related::new(key, repositories.key_repository.clone()),
        }),
        (None, None) => None,
        _ => return Err(DataLayerError::MappingError),
    };
    let data = HolderCredentialData {
        issuer: IssuerIdentity {
            identifier: Related::new(
                credential
                    .issuer_identifier_id
                    .ok_or(DataLayerError::MappingError)?,
                issuer,
            ),
            certificate: credential
                .issuer_certificate_id
                .map(|id| Related::new(id, repositories.certificate_repository.clone())),
        },
        format: Related::new(
            credential.format.ok_or(DataLayerError::MappingError)?,
            format,
        ),
        claims: credential_claims(credential.id, repositories.claim_repository),
        binding,
        credential_blob_id: credential.credential_blob_id,
        embedded_disclosure_policy: credential.embedded_disclosure_policy,
    };
    Ok(match credential.r#type {
        credential::CredentialType::Single => Credential::HolderSingle {
            common,
            credential: data,
        },
        credential::CredentialType::BatchItem => Credential::HolderBatchItem {
            common,
            credential: data,
            parent: Related::new(
                credential.parent_id.ok_or(DataLayerError::MappingError)?,
                repositories.credential_repository,
            ),
            consumed_at: credential.consumed_at,
        },
        credential::CredentialType::BatchParent => unreachable!(),
    })
}

pub(super) fn request_to_active_model(
    request: &Credential,
    organisation_id: OrganisationId,
) -> credential::ActiveModel {
    credential::ActiveModel {
        id: Set(request.common().id),
        credential_schema_id: Set(request.common().schema.id()),
        organisation_id: Set(organisation_id),
        created_date: Set(request.common().created_date),
        last_modified: Set(request.common().last_modified),
        issuance_date: Set(request.common().issuance_date),
        expires_at: Set(request.common().expires_at),
        deleted_at: Set(request.common().deleted_at),
        consumed_at: Set(request.consumed_at()),
        protocol: Set(request.common().protocol.to_owned()),
        redirect_uri: Set(request.common().redirect_uri.to_owned()),
        issuer_identifier_id: Set(request
            .issuer_identifier()
            .map(|identifier| identifier.id())),
        issuer_certificate_id: Set(request
            .issuer_certificate()
            .as_ref()
            .map(|certificate| certificate.id())),
        holder_identifier_id: Set(request
            .holder_identifier()
            .as_ref()
            .map(|identifier| identifier.id())),
        interaction_id: Set(request
            .common()
            .interaction
            .as_ref()
            .map(|interaction| interaction.id())),
        key_id: Set(request.key().map(|key| key.id())),
        role: Set(request.role().to_owned().into()),
        state: Set(request.common().state.into()),
        suspend_end_date: Set(request.suspend_end_date()),
        profile: Set(request.common().profile.clone()),
        parent_id: Set(request.parent().map(|m| m.id())),
        credential_blob_id: Set(request.credential_blob_id()),
        wallet_key_attestation_blob_id: Set(request.wallet_key_attestation_blob_id()),
        wallet_instance_attestation_blob_id: Set(request.wallet_instance_attestation_blob_id()),
        webhook_url: Set(request.webhook_url().to_owned()),
        embedded_disclosure_policy: Set(request.embedded_disclosure_policy().clone()),
        subscriber_information: Set(request.subscriber_information().clone()),
        ecosystem: Set(request.common().ecosystem.clone()),
        r#type: Set(request.r#type().into()),
        format: Set(request.format().map(|format| format.id())),
    }
}

pub(crate) struct CredentialSchemaFormatLoader {
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncModelsLoader<CredentialSchemaFormat> for CredentialSchemaFormatLoader {
    async fn load(
        &self,
        ids: &[CredentialSchemaFormatId],
    ) -> Result<Vec<CredentialSchemaFormat>, DataLayerError> {
        let models = credential_schema_format::Entity::find()
            .filter(credential_schema_format::Column::Id.is_in(ids))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(models
            .into_iter()
            .map(|model| credential_schema_format_from_model(model, self.db.clone()))
            .collect())
    }
}
