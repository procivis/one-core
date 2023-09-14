use one_core::model::credential::UpdateCredentialRequest;
use one_core::{
    common_mapper::vector_into,
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::ClaimSchemaRelations,
        credential::{
            Credential, CredentialId, CredentialRelations, CredentialState,
            CredentialStateRelations,
        },
        credential::{GetCredentialList, GetCredentialQuery},
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        did::{Did, DidRelations},
        organisation::OrganisationRelations,
    },
    repository::{
        claim_repository::ClaimRepository, credential_repository::CredentialRepository,
        credential_schema_repository::CredentialSchemaRepository, did_repository::DidRepository,
        error::DataLayerError,
    },
};
use sea_orm::{
    sea_query::{Alias, Expr, IntoCondition, Query},
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, ModelTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait, Select, Set, SqlErr,
    Unchanged,
};
use std::{str::FromStr, sync::Arc};
use time::OffsetDateTime;

use uuid::Uuid;

use crate::credential::mapper::{
    entities_to_credential, get_credential_state_active_model, request_to_active_model,
};
use crate::entity::credential_state;
use crate::list_query::SelectWithListQuery;
use crate::{
    common::calculate_pages_count,
    credential::CredentialProvider,
    entity::{credential, credential_claim, credential_schema},
};

async fn get_credential_schema(
    schema_id: &Uuid,
    relations: &Option<CredentialSchemaRelations>,
    repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
) -> Result<Option<CredentialSchema>, DataLayerError> {
    match relations {
        None => Ok(None),
        Some(schema_relations) => Ok(Some(
            repository
                .get_credential_schema(schema_id, schema_relations)
                .await?,
        )),
    }
}

async fn get_claims(
    credential: &credential::Model,
    relations: &Option<ClaimRelations>,
    db: &DatabaseConnection,
    repository: Arc<dyn ClaimRepository + Send + Sync>,
) -> Result<Option<Vec<Claim>>, DataLayerError> {
    let ids: Vec<Uuid> = credential
        .find_related(credential_claim::Entity)
        .all(db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
        .into_iter()
        .map(|claim| Uuid::from_str(&claim.claim_id).map_err(|_| DataLayerError::MappingError))
        .collect::<Result<Vec<_>, _>>()?;

    match relations {
        None => Ok(None),
        Some(claim_relations) => Ok(Some(repository.get_claim_list(ids, claim_relations).await?)),
    }
}

async fn get_did(
    did_id: &Uuid,
    relations: &Option<DidRelations>,
    repository: Arc<dyn DidRepository + Send + Sync>,
) -> Result<Option<Did>, DataLayerError> {
    match relations {
        None => Ok(None),
        Some(did_relations) => Ok(Some(repository.get_did(did_id, did_relations).await?)),
    }
}

impl CredentialProvider {
    async fn credential_model_to_repository_model(
        &self,
        credential: credential::Model,
        relations: &CredentialRelations,
    ) -> Result<Credential, DataLayerError> {
        let credential_id =
            Uuid::from_str(&credential.id).map_err(|_| DataLayerError::MappingError)?;
        let issuer_did_id =
            Uuid::from_str(&credential.issuer_did_id).map_err(|_| DataLayerError::MappingError)?;
        let issuer_did = get_did(
            &issuer_did_id,
            &relations.issuer_did,
            self.did_repository.clone(),
        )
        .await?;

        let holder_did = match &credential.holder_did_id {
            None => None,
            Some(holder_did_id) => {
                let uuid =
                    Uuid::from_str(holder_did_id).map_err(|_| DataLayerError::MappingError)?;
                get_did(&uuid, &relations.holder_did, self.did_repository.clone()).await?
            }
        };

        let states: Option<Vec<CredentialState>> = match &relations.state {
            None => None,
            Some(_) => {
                let credential_states = credential_state::Entity::find()
                    .filter(credential_state::Column::CredentialId.eq(&credential.id))
                    .order_by_desc(credential_state::Column::CreatedDate)
                    .all(&self.db)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            "Error while fetching credential {} state. Error: {}",
                            credential.id,
                            e.to_string()
                        );
                        DataLayerError::GeneralRuntimeError(e.to_string())
                    })?;

                Some(vector_into(credential_states))
            }
        };

        let schema_id = Uuid::from_str(&credential.credential_schema_id)
            .map_err(|_| DataLayerError::MappingError)?;
        let schema = get_credential_schema(
            &schema_id,
            &relations.schema,
            self.credential_schema_repository.clone(),
        )
        .await?;

        let claims = get_claims(
            &credential,
            &relations.claims,
            &self.db,
            self.claim_repository.clone(),
        )
        .await?;

        Ok(entities_to_credential(
            credential_id,
            credential,
            states,
            issuer_did,
            holder_did,
            claims,
            schema,
        ))
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

fn get_credential_list_query(query_params: GetCredentialQuery) -> Select<credential::Entity> {
    credential::Entity::find()
        .select_only()
        .columns([
            credential::Column::Id,
            credential::Column::CreatedDate,
            credential::Column::LastModified,
            credential::Column::IssuanceDate,
            credential::Column::DeletedAt,
            credential::Column::Transport,
            credential::Column::Credential,
            credential::Column::IssuerDidId,
            credential::Column::HolderDidId,
            credential::Column::CredentialSchemaId,
        ])
        // add related schema (to enable sorting by schema name)
        .join(
            sea_orm::JoinType::InnerJoin,
            credential::Relation::CredentialSchema.def(),
        )
        // add related issuer did (to enable sorting)
        .join(
            sea_orm::JoinType::LeftJoin,
            credential::Relation::IssuerDid.def(),
        )
        // find most recent state (to enable sorting)
        .join(
            sea_orm::JoinType::InnerJoin,
            credential::Relation::CredentialState.def(),
        )
        .filter(
            credential_state::Column::CreatedDate
                .in_subquery(
                    Query::select()
                        .expr(
                            Expr::col((
                                Alias::new("inner_state"),
                                credential_state::Column::CreatedDate,
                            ))
                            .max(),
                        )
                        .from_as(credential_state::Entity, Alias::new("inner_state"))
                        .cond_where(
                            Expr::col((
                                Alias::new("inner_state"),
                                credential_state::Column::CredentialId,
                            ))
                            .equals((
                                credential_state::Entity,
                                credential_state::Column::CredentialId,
                            )),
                        )
                        .to_owned(),
                )
                .into_condition(),
        )
        // list query
        .with_list_query(&query_params, &Some(vec![credential_schema::Column::Name]))
        .with_organisation_id(&query_params, &credential_schema::Column::OrganisationId)
        // fallback ordering
        .order_by_desc(credential::Column::CreatedDate)
        .order_by_desc(credential::Column::Id)
}

#[async_trait::async_trait]
impl CredentialRepository for CredentialProvider {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        let issuer_did = request
            .issuer_did
            .to_owned()
            .ok_or(DataLayerError::MappingError)?;
        let holder_did_id = match request.holder_did.to_owned() {
            None => None,
            Some(did) => Some(did.id),
        };
        let schema = request
            .schema
            .to_owned()
            .ok_or(DataLayerError::MappingError)?;
        let claims = request
            .claims
            .to_owned()
            .ok_or(DataLayerError::MappingError)?;

        let credential = request_to_active_model(&request, schema, issuer_did, holder_did_id)
            .insert(&self.db)
            .await
            .map_err(|e| match e.sql_err() {
                Some(SqlErr::UniqueConstraintViolation(_)) => DataLayerError::AlreadyExists,
                _ => DataLayerError::GeneralRuntimeError(e.to_string()),
            })?;

        self.claim_repository
            .create_claim_list(claims.to_owned())
            .await?;

        let credential_claim_models: Vec<credential_claim::ActiveModel> = claims
            .into_iter()
            .map(|claim| credential_claim::ActiveModel {
                claim_id: Set(claim.id.to_string()),
                credential_id: Set(credential.id.clone()),
            })
            .collect();
        credential_claim::Entity::insert_many(credential_claim_models)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        if let Some(states) = request.state {
            for state in states {
                self.update_credential(UpdateCredentialRequest {
                    id: request.id.to_owned(),
                    credential: None,
                    holder_did_id: None,
                    state: Some(state),
                })
                .await?;
            }
        }

        Ok(request.id)
    }

    async fn get_credential(
        &self,
        id: &CredentialId,
        relations: &CredentialRelations,
    ) -> Result<Credential, DataLayerError> {
        let credential: credential::Model = credential::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        self.credential_model_to_repository_model(credential, relations)
            .await
    }

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQuery,
    ) -> Result<GetCredentialList, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = get_credential_list_query(query_params);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let credentials = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(GetCredentialList {
            values: self
                .credentials_to_repository(
                    credentials,
                    &CredentialRelations {
                        state: Some(CredentialStateRelations {}),
                        claims: None,
                        issuer_did: Some(DidRelations {}),
                        holder_did: Some(DidRelations {}),
                        schema: Some(CredentialSchemaRelations {
                            claim_schema: Some(ClaimSchemaRelations {}),
                            organisation: Some(OrganisationRelations {}),
                        }),
                    },
                )
                .await?,
            total_pages: calculate_pages_count(items_count, limit),
            total_items: items_count,
        })
    }

    async fn update_credential(
        &self,
        request: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        let id = &request.id;

        let holder_did_id = match request.holder_did_id {
            None => Unchanged(Default::default()),
            Some(holder_did) => Set(Some(holder_did.to_string())),
        };

        let credential = match request.credential {
            None => Unchanged(Default::default()),
            Some(token) => Set(token),
        };

        let update_model = credential::ActiveModel {
            id: Unchanged(id.to_string()),
            last_modified: Set(OffsetDateTime::now_utc()),
            holder_did_id,
            credential,
            ..Default::default()
        };

        if let Some(state) = request.state {
            credential_state::Entity::insert(get_credential_state_active_model(id, state))
                .exec(&self.db)
                .await
                .map_err(|e| match e.sql_err() {
                    Some(SqlErr::ForeignKeyConstraintViolation(_)) => {
                        DataLayerError::RecordNotFound
                    }
                    _ => DataLayerError::GeneralRuntimeError(e.to_string()),
                })?;
        }

        update_model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        Ok(())
    }
}
