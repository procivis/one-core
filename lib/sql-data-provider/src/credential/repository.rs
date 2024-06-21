use std::str::FromStr;
use std::sync::Arc;

use autometrics::autometrics;
use dto_mapper::convert_inner;
use migration::{all, Asterisk, CommonTableExpression, Func, WithClause, WithQuery};
use one_core::model::claim::{Claim, ClaimId, ClaimRelations};
use one_core::model::credential::{
    Credential, CredentialRelations, CredentialState, GetCredentialList, GetCredentialQuery,
    GetCredentialQueryFilters, UpdateCredentialRequest,
};
use one_core::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use one_core::model::did::{Did, DidRelations};
use one_core::model::interaction::InteractionId;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::error::DataLayerError;
use one_core::service::credential::dto::CredentialListIncludeEntityTypeEnum;
use sea_orm::sea_query::{Alias, Expr, IntoCondition, Query};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    FromQueryResult, JoinType, Order, QueryFilter, QueryOrder, QuerySelect, RelationTrait, Set,
    SqlErr, Unchanged,
};
use shared_types::{CredentialId, CredentialSchemaId, DidId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::calculate_pages_count;
use crate::credential::entity_model::{CredentialCountEntityModel, CredentialListEntityModel};
use crate::credential::mapper::{
    credentials_to_repository, get_credential_state_active_model, request_to_active_model,
};
use crate::credential::CredentialProvider;
use crate::entity::{
    claim, claim_schema, credential, credential_schema, credential_schema_claim_schema,
    credential_state, did,
};
use crate::list_query_generic::SelectWithListQuery;

async fn get_credential_schema(
    schema_id: &CredentialSchemaId,
    relations: &Option<CredentialSchemaRelations>,
    repository: Arc<dyn CredentialSchemaRepository>,
) -> Result<Option<CredentialSchema>, DataLayerError> {
    match relations {
        None => Ok(None),
        Some(schema_relations) => Ok(Some(
            repository
                .get_credential_schema(schema_id, schema_relations)
                .await?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "credential-credential_schema",
                    id: schema_id.to_string(),
                })?,
        )),
    }
}

async fn get_claims(
    credential: &credential::Model,
    relations: &ClaimRelations,
    db: &DatabaseConnection,
    claim_repository: Arc<dyn ClaimRepository>,
) -> Result<Vec<Claim>, DataLayerError> {
    #[derive(FromQueryResult)]
    struct ClaimIdModel {
        pub id: String,
    }

    let ids: Vec<ClaimId> = claim::Entity::find()
        .select_only()
        .columns([claim::Column::Id])
        .filter(claim::Column::CredentialId.eq(credential.id))
        .join(JoinType::InnerJoin, claim::Relation::ClaimSchema.def())
        .join(
            JoinType::InnerJoin,
            claim_schema::Relation::CredentialSchemaClaimSchema.def(),
        )
        // sorting claims according to the order from credential_schema
        .order_by_asc(credential_schema_claim_schema::Column::Order)
        .into_model::<ClaimIdModel>()
        .all(db)
        .await
        .map_err(|e| DataLayerError::Db(e.into()))?
        .into_iter()
        .map(|claim| Uuid::from_str(&claim.id))
        .collect::<Result<Vec<_>, _>>()?;

    claim_repository.get_claim_list(ids, relations).await
}

impl CredentialProvider {
    async fn credential_model_to_repository_model(
        &self,
        credential: credential::Model,
        relations: &CredentialRelations,
    ) -> Result<Credential, DataLayerError> {
        let issuer_did = get_related_did(
            self.did_repository.as_ref(),
            credential.issuer_did_id.as_ref(),
            relations.issuer_did.as_ref(),
        )
        .await?;
        let holder_did = get_related_did(
            self.did_repository.as_ref(),
            credential.holder_did_id.as_ref(),
            relations.holder_did.as_ref(),
        )
        .await?;

        let state: Option<Vec<CredentialState>> = match &relations.state {
            None => None,
            Some(_) => {
                let credential_states = credential_state::Entity::find()
                    .filter(credential_state::Column::CredentialId.eq(credential.id))
                    .order_by_desc(credential_state::Column::CreatedDate)
                    .all(&self.db)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            "Error while fetching credential {} state. Error: {}",
                            credential.id,
                            e.to_string()
                        );
                        DataLayerError::Db(e.into())
                    })?;

                Some(convert_inner(credential_states))
            }
        };

        let schema_id = Uuid::from_str(&credential.credential_schema_id)?;
        let schema = get_credential_schema(
            &schema_id.into(),
            &relations.schema.to_owned(),
            self.credential_schema_repository.clone(),
        )
        .await?;

        let claims = if let Some(claim_relations) = &relations.claims {
            Some(
                get_claims(
                    &credential,
                    claim_relations,
                    &self.db,
                    self.claim_repository.clone(),
                )
                .await?,
            )
        } else {
            None
        };

        let interaction = if let Some(interaction_relations) = &relations.interaction {
            match &credential.interaction_id {
                None => None,
                Some(interaction_id) => {
                    let interaction_id = Uuid::from_str(interaction_id)?;
                    Some(
                        self.interaction_repository
                            .get_interaction(&interaction_id, interaction_relations)
                            .await?
                            .ok_or(DataLayerError::MissingRequiredRelation {
                                relation: "credential-interaction",
                                id: interaction_id.to_string(),
                            })?,
                    )
                }
            }
        } else {
            None
        };

        let revocation_list = if let Some(revocation_list_relations) = &relations.revocation_list {
            match &credential.revocation_list_id {
                None => None,
                Some(revocation_list_id) => {
                    let revocation_list_id = Uuid::from_str(revocation_list_id)?;
                    Some(
                        self.revocation_list_repository
                            .get_revocation_list(&revocation_list_id, revocation_list_relations)
                            .await?
                            .ok_or(DataLayerError::MissingRequiredRelation {
                                relation: "credential-revocation_list",
                                id: revocation_list_id.to_string(),
                            })?,
                    )
                }
            }
        } else {
            None
        };

        let key = if let Some(key_relations) = &relations.key {
            match &credential.key_id {
                None => None,
                Some(key_id) => {
                    let key = self
                        .key_repository
                        .get_key(key_id, key_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "credential-key",
                            id: key_id.to_string(),
                        })?;

                    Some(key)
                }
            }
        } else {
            None
        };

        Ok(Credential {
            state,
            issuer_did,
            holder_did,
            claims,
            schema,
            revocation_list,
            interaction,
            key,
            ..credential.into()
        })
    }

    async fn credentials_to_repository(
        &self,
        credentials: Vec<credential::Model>,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let mut result: Vec<Credential> = Vec::new();
        for credential in credentials.into_iter() {
            result.push(
                self.credential_model_to_repository_model(credential, relations)
                    .await?,
            );
        }

        Ok(result)
    }
}

fn get_credential_list_query(
    organisation_id: Option<OrganisationId>,
    query_params: &GetCredentialQuery,
) -> WithQuery {
    let credential_ids_name = Alias::new("credential_ids");
    let credential_ids = Query::select()
        .column((credential::Entity, credential::Column::Id))
        .from(credential::Entity)
        .inner_join(
            credential_schema::Entity,
            Expr::col((credential::Entity, credential::Column::CredentialSchemaId))
                .equals((credential_schema::Entity, credential_schema::Column::Id)),
        )
        .and_where_option(organisation_id.map(|organisation_id| {
            Expr::col((
                credential_schema::Entity,
                credential_schema::Column::OrganisationId,
            ))
            .eq(organisation_id)
        }))
        .and_where(Expr::col((credential::Entity, credential::Column::DeletedAt)).is_null())
        .order_by(
            (credential::Entity, credential::Column::CreatedDate),
            Order::Desc,
        )
        .take();

    let latest_credential_state = Alias::new("latest_credential_state");
    let credential_states_name = Alias::new("credential_states");
    let credential_states = Query::select()
        .columns([
            (
                credential_state::Entity,
                credential_state::Column::CredentialId,
            ),
            (
                credential_state::Entity,
                credential_state::Column::CreatedDate,
            ),
            (credential_state::Entity, credential_state::Column::State),
            (
                credential_state::Entity,
                credential_state::Column::SuspendEndDate,
            ),
        ])
        .from(credential_state::Entity)
        .join_subquery(
            JoinType::InnerJoin,
            Query::select()
                .column((
                    credential_state::Entity,
                    credential_state::Column::CredentialId,
                ))
                .expr_as(
                    Func::max(Expr::col((
                        credential_state::Entity,
                        credential_state::Column::CreatedDate,
                    ))),
                    Alias::new("created_date"),
                )
                .from(credential_state::Entity)
                .inner_join(
                    credential_ids_name.clone(),
                    Expr::col((
                        credential_state::Entity,
                        credential_state::Column::CredentialId,
                    ))
                    .equals((credential_ids_name.clone(), Alias::new("id"))),
                )
                .group_by_col((
                    credential_state::Entity,
                    credential_state::Column::CredentialId,
                ))
                .take(),
            latest_credential_state.clone(),
            all![
                Expr::col((
                    credential_state::Entity,
                    credential_state::Column::CredentialId
                ))
                .equals((latest_credential_state.clone(), Alias::new("credential_id"))),
                Expr::col((
                    credential_state::Entity,
                    credential_state::Column::CreatedDate
                ))
                .equals((latest_credential_state, Alias::new("created_date"))),
            ],
        )
        .take();

    let with = WithClause::new()
        .cte(
            CommonTableExpression::new()
                .query(credential_states)
                .table_name(credential_states_name.clone())
                .to_owned(),
        )
        .cte(
            CommonTableExpression::new()
                .query(credential_ids)
                .table_name(credential_ids_name.clone())
                .to_owned(),
        )
        .to_owned();

    let mut query = Query::select()
        .columns([
            (credential::Entity, credential::Column::Id),
            (credential::Entity, credential::Column::CreatedDate),
            (credential::Entity, credential::Column::LastModified),
            (credential::Entity, credential::Column::IssuanceDate),
            (credential::Entity, credential::Column::DeletedAt),
            (credential::Entity, credential::Column::Credential),
            (credential::Entity, credential::Column::RedirectUri),
            (credential::Entity, credential::Column::Role),
        ])
        .expr_as(
            Expr::col((credential::Entity, credential::Column::Exchange)),
            Alias::new("exchange"),
        )
        .expr_as(
            Expr::col((
                credential_schema::Entity,
                credential_schema::Column::CreatedDate,
            )),
            Alias::new("credential_schema_created_date"),
        )
        .expr_as(
            Expr::col((credential_schema::Entity, credential_schema::Column::Format)),
            Alias::new("credential_schema_format"),
        )
        .expr_as(
            Expr::col((credential_schema::Entity, credential_schema::Column::Id)),
            Alias::new("credential_schema_id"),
        )
        .expr_as(
            Expr::col((
                credential_schema::Entity,
                credential_schema::Column::LastModified,
            )),
            Alias::new("credential_schema_last_modified"),
        )
        .expr_as(
            Expr::col((credential_schema::Entity, credential_schema::Column::Name)),
            Alias::new("credential_schema_name"),
        )
        .expr_as(
            Expr::col((
                credential_schema::Entity,
                credential_schema::Column::RevocationMethod,
            )),
            Alias::new("credential_schema_revocation_method"),
        )
        .expr_as(
            Expr::col((
                credential_schema::Entity,
                credential_schema::Column::WalletStorageType,
            )),
            Alias::new("credential_schema_wallet_storage_type"),
        )
        .expr_as(
            Expr::col((
                credential_schema::Entity,
                credential_schema::Column::SchemaId,
            )),
            Alias::new("credential_schema_schema_id"),
        )
        .expr_as(
            Expr::col((
                credential_schema::Entity,
                credential_schema::Column::SchemaType,
            )),
            Alias::new("credential_schema_schema_type"),
        )
        .expr_as(
            Expr::col((credential_states_name.clone(), Alias::new("created_date"))),
            Alias::new("credential_state_created_date"),
        )
        .expr_as(
            Expr::col((credential_states_name.clone(), Alias::new("state"))),
            Alias::new("credential_state_state"),
        )
        .expr_as(
            Expr::col((
                credential_states_name.clone(),
                Alias::new("suspend_end_date"),
            )),
            Alias::new("credential_state_suspend_end_date"),
        )
        .expr_as(
            Expr::col((did::Entity, did::Column::CreatedDate)),
            Alias::new("issuer_did_created_date"),
        )
        .expr_as(
            Expr::col((did::Entity, did::Column::Deactivated)),
            Alias::new("issuer_did_deactivated"),
        )
        .expr_as(
            Expr::col((did::Entity, did::Column::Did)),
            Alias::new("issuer_did_did"),
        )
        .expr_as(
            Expr::col((did::Entity, did::Column::Id)),
            Alias::new("issuer_did_id"),
        )
        .expr_as(
            Expr::col((did::Entity, did::Column::LastModified)),
            Alias::new("issuer_did_last_modified"),
        )
        .expr_as(
            Expr::col((did::Entity, did::Column::Method)),
            Alias::new("issuer_did_method"),
        )
        .expr_as(
            Expr::col((did::Entity, did::Column::Name)),
            Alias::new("issuer_did_name"),
        )
        .expr_as(
            Expr::col((did::Entity, did::Column::TypeField)),
            Alias::new("issuer_did_type_field"),
        )
        .from(credential_ids_name.clone())
        .inner_join(
            credential::Entity,
            Expr::col((credential::Entity, credential::Column::Id))
                .equals((credential_ids_name, Alias::new("id"))),
        )
        .inner_join(
            credential_schema::Entity,
            Expr::col((credential::Entity, credential::Column::CredentialSchemaId))
                .equals((credential_schema::Entity, credential_schema::Column::Id)),
        )
        .inner_join(
            credential_states_name.clone(),
            Expr::col((credential::Entity, credential::Column::Id))
                .equals((credential_states_name, Alias::new("credential_id"))),
        )
        .left_join(
            did::Entity,
            Expr::col((credential::Entity, credential::Column::IssuerDidId))
                .equals((did::Entity, did::Column::Id)),
        )
        .take()
        .with_list_query(query_params);

    if let Some(include) = &query_params.include {
        if include.contains(&CredentialListIncludeEntityTypeEnum::LayoutProperties) {
            query = query
                .expr_as(
                    Expr::col((
                        credential_schema::Entity,
                        credential_schema::Column::LayoutProperties,
                    )),
                    Alias::new("credential_schema_schema_layout_properties"),
                )
                .take();
        }
    }

    query.with(with)
}

fn get_credential_count_query(
    organisation_id: Option<OrganisationId>,
    query_params: &GetCredentialQuery,
) -> WithQuery {
    let credential_ids_name = Alias::new("credential_ids");
    let credential_ids = Query::select()
        .column((credential::Entity, credential::Column::Id))
        .from(credential::Entity)
        .inner_join(
            credential_schema::Entity,
            Expr::col((credential::Entity, credential::Column::CredentialSchemaId))
                .equals((credential_schema::Entity, credential_schema::Column::Id)),
        )
        .and_where_option(organisation_id.map(|organisation_id| {
            Expr::col((
                credential_schema::Entity,
                credential_schema::Column::OrganisationId,
            ))
            .eq(organisation_id)
        }))
        .and_where(Expr::col((credential::Entity, credential::Column::DeletedAt)).is_null())
        .order_by(
            (credential::Entity, credential::Column::CreatedDate),
            Order::Desc,
        )
        .take();

    let latest_credential_state = Alias::new("latest_credential_state");
    let credential_states_name = Alias::new("credential_states");
    let credential_states = Query::select()
        .columns([
            (
                credential_state::Entity,
                credential_state::Column::CredentialId,
            ),
            (
                credential_state::Entity,
                credential_state::Column::CreatedDate,
            ),
            (credential_state::Entity, credential_state::Column::State),
            (
                credential_state::Entity,
                credential_state::Column::SuspendEndDate,
            ),
        ])
        .from(credential_state::Entity)
        .join_subquery(
            JoinType::InnerJoin,
            Query::select()
                .column((
                    credential_state::Entity,
                    credential_state::Column::CredentialId,
                ))
                .expr_as(
                    Func::max(Expr::col((
                        credential_state::Entity,
                        credential_state::Column::CreatedDate,
                    ))),
                    Alias::new("created_date"),
                )
                .from(credential_state::Entity)
                .inner_join(
                    credential_ids_name.clone(),
                    Expr::col((
                        credential_state::Entity,
                        credential_state::Column::CredentialId,
                    ))
                    .equals((credential_ids_name.clone(), Alias::new("id"))),
                )
                .group_by_col((
                    credential_state::Entity,
                    credential_state::Column::CredentialId,
                ))
                .take(),
            latest_credential_state.clone(),
            all![
                Expr::col((
                    credential_state::Entity,
                    credential_state::Column::CredentialId
                ))
                .equals((latest_credential_state.clone(), Alias::new("credential_id"))),
                Expr::col((
                    credential_state::Entity,
                    credential_state::Column::CreatedDate
                ))
                .equals((latest_credential_state, Alias::new("created_date"))),
            ],
        )
        .take();

    let with = WithClause::new()
        .cte(
            CommonTableExpression::new()
                .query(credential_states)
                .table_name(credential_states_name.clone())
                .to_owned(),
        )
        .cte(
            CommonTableExpression::new()
                .query(credential_ids)
                .table_name(credential_ids_name.clone())
                .to_owned(),
        )
        .to_owned();

    let query = Query::select()
        .expr_as(Expr::col(Asterisk).count(), Alias::new("count"))
        .from(credential_ids_name.clone())
        .inner_join(
            credential::Entity,
            Expr::col((credential::Entity, credential::Column::Id))
                .equals((credential_ids_name, Alias::new("id"))),
        )
        .inner_join(
            credential_schema::Entity,
            Expr::col((credential::Entity, credential::Column::CredentialSchemaId))
                .equals((credential_schema::Entity, credential_schema::Column::Id)),
        )
        .inner_join(
            credential_states_name.clone(),
            Expr::col((credential::Entity, credential::Column::Id))
                .equals((credential_states_name, Alias::new("credential_id"))),
        )
        .left_join(
            did::Entity,
            Expr::col((credential::Entity, credential::Column::IssuerDidId))
                .equals((did::Entity, did::Column::Id)),
        )
        .take()
        .with_list_query(query_params);

    query.with(with)
}

#[autometrics]
#[async_trait::async_trait]
impl CredentialRepository for CredentialProvider {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        let issuer_did = request.issuer_did.clone();
        let holder_did_id = request.holder_did.as_ref().map(|did| did.id);
        let schema = request
            .schema
            .to_owned()
            .ok_or(DataLayerError::MappingError)?;

        let claims = request
            .claims
            .to_owned()
            .ok_or(DataLayerError::MappingError)?;

        let interaction_id = request
            .interaction
            .as_ref()
            .map(|interaction| interaction.id);

        let revocation_list_id = request
            .revocation_list
            .as_ref()
            .map(|revocation_list| revocation_list.id);

        let key_id = request.key.as_ref().map(|key| key.id);

        if claims.iter().any(|claim| claim.credential_id != request.id) {
            return Err(anyhow::anyhow!("Claim credential-id mismatch!").into());
        }

        request_to_active_model(
            &request,
            schema,
            issuer_did,
            holder_did_id,
            interaction_id,
            revocation_list_id,
            key_id,
        )
        .insert(&self.db)
        .await
        .map_err(|e| match e.sql_err() {
            Some(SqlErr::UniqueConstraintViolation(_)) => DataLayerError::AlreadyExists,
            _ => DataLayerError::Db(e.into()),
        })?;

        if !claims.is_empty() {
            self.claim_repository.create_claim_list(claims).await?;
        }

        if let Some(states) = request.state {
            for state in states {
                self.update_credential(UpdateCredentialRequest {
                    id: request.id.to_owned(),
                    state: Some(state),
                    credential: None,
                    holder_did_id: None,
                    issuer_did_id: None,
                    interaction: None,
                    key: None,
                    redirect_uri: None,
                })
                .await?;
            }
        }

        Ok(request.id)
    }

    async fn delete_credential(&self, id: &CredentialId) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let credential = credential::ActiveModel {
            id: Unchanged(*id),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        credential::Entity::update(credential)
            .filter(credential::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map(|_| ())
            .map_err(|error| match error {
                sea_orm::DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
                error => DataLayerError::Db(error.into()),
            })
    }

    async fn get_credential(
        &self,
        id: &CredentialId,
        relations: &CredentialRelations,
    ) -> Result<Option<Credential>, DataLayerError> {
        let credential = credential::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        match credential {
            None => Ok(None),
            Some(credential) => {
                let credential = self
                    .credential_model_to_repository_model(credential, relations)
                    .await?;

                Ok(Some(credential))
            }
        }
    }

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .filter(credential::Column::InteractionId.eq(interaction_id.to_string()))
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        self.credentials_to_repository(credentials, relations).await
    }

    async fn get_credentials_by_issuer_did_id(
        &self,
        issuer_did_id: &DidId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .filter(credential::Column::IssuerDidId.eq(issuer_did_id))
            .order_by_asc(credential::Column::CreatedDate)
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        self.credentials_to_repository(credentials, relations).await
    }

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQueryFilters,
    ) -> Result<GetCredentialList, DataLayerError> {
        let limit = query_params
            .query
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as _);

        let count_query =
            get_credential_count_query(query_params.organisation_id, &query_params.query);
        let items_count = CredentialCountEntityModel::find_by_statement(
            self.db.get_database_backend().build(&count_query),
        )
        .one(&self.db)
        .await
        .map_err(|e| DataLayerError::Db(e.into()))?
        .ok_or_else(|| DataLayerError::Db(anyhow::anyhow!("missing count")))?;

        let list_query =
            get_credential_list_query(query_params.organisation_id, &query_params.query);
        let credentials = CredentialListEntityModel::find_by_statement(
            self.db.get_database_backend().build(&list_query),
        )
        .all(&self.db)
        .await
        .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(GetCredentialList {
            values: credentials_to_repository(credentials)?,
            total_pages: calculate_pages_count(items_count.count as _, limit.unwrap_or(0)),
            total_items: items_count.count as _,
        })
    }

    async fn update_credential(
        &self,
        request: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        let id = &request.id;

        let holder_did_id = match request.holder_did_id {
            None => Unchanged(Default::default()),
            Some(holder_did) => Set(Some(holder_did)),
        };

        let issuer_did_id = match request.issuer_did_id {
            None => Unchanged(Default::default()),
            Some(issuer_did) => Set(Some(issuer_did)),
        };

        let credential = match request.credential {
            None => Unchanged(Default::default()),
            Some(token) => Set(token),
        };

        let interaction_id = match request.interaction {
            None => Unchanged(Default::default()),
            Some(interaction_id) => Set(Some(interaction_id.to_string())),
        };

        let key_id = match request.key {
            None => Unchanged(Default::default()),
            Some(key_id) => Set(Some(key_id)),
        };

        let redirect_uri = match request.redirect_uri {
            None => Unchanged(Default::default()),
            Some(redirect_uri) => Set(redirect_uri),
        };

        let update_model = credential::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            holder_did_id,
            issuer_did_id,
            credential,
            interaction_id,
            key_id,
            redirect_uri,
            ..Default::default()
        };

        if let Some(state) = request.state {
            credential_state::Entity::insert(get_credential_state_active_model(*id, state))
                .exec(&self.db)
                .await
                .map_err(|e| DataLayerError::Db(e.into()))?;
        }

        update_model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::Db(e.into()),
        })?;

        Ok(())
    }

    async fn get_credentials_by_claim_names(
        &self,
        claim_names: Vec<String>,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .join(JoinType::InnerJoin, credential::Relation::Claim.def())
            .join(
                JoinType::InnerJoin,
                claim::Relation::ClaimSchema
                    .def()
                    .on_condition(move |_left, _right| {
                        Expr::col((claim_schema::Entity, claim_schema::Column::Key))
                            .is_in(&claim_names)
                            .into_condition()
                    }),
            )
            .distinct()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        self.credentials_to_repository(credentials, relations).await
    }

    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: String,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .join(
                JoinType::InnerJoin,
                credential::Relation::CredentialSchema
                    .def()
                    .on_condition(move |_left, _right| {
                        Expr::col((
                            credential_schema::Entity,
                            credential_schema::Column::SchemaId,
                        ))
                        .eq(&schema_id)
                        .into_condition()
                    }),
            )
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        self.credentials_to_repository(credentials, relations).await
    }

    async fn get_credential_by_claim_id(
        &self,
        claim_id: &ClaimId,
        relations: &CredentialRelations,
    ) -> Result<Option<Credential>, DataLayerError> {
        let claim_id = claim_id.to_string();
        let credential = credential::Entity::find()
            .join(
                JoinType::InnerJoin,
                credential::Relation::Claim
                    .def()
                    .on_condition(move |_left, _right| {
                        Expr::col((claim::Entity, claim::Column::Id))
                            .eq(&claim_id)
                            .into_condition()
                    }),
            )
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(match credential {
            None => None,
            Some(credential) => Some(
                self.credential_model_to_repository_model(credential, relations)
                    .await?,
            ),
        })
    }
}

async fn get_related_did(
    repo: &dyn DidRepository,
    id: Option<&DidId>,
    relations: Option<&DidRelations>,
) -> Result<Option<Did>, DataLayerError> {
    let did = match id.zip(relations) {
        None => None,
        Some((id, relations)) => {
            let did = repo.get_did(id, relations).await?.ok_or(
                DataLayerError::MissingRequiredRelation {
                    relation: "credential-did",
                    id: id.to_string(),
                },
            )?;

            Some(did)
        }
    };

    Ok(did)
}
