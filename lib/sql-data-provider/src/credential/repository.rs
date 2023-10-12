use crate::{
    common::{calculate_pages_count, get_did},
    credential::{
        mapper::{get_credential_state_active_model, request_to_active_model},
        CredentialProvider,
    },
    entity::{
        claim, claim_schema, credential, credential_claim, credential_schema,
        credential_schema_claim_schema, credential_state,
    },
    list_query::SelectWithListQuery,
};
use one_core::{
    common_mapper::vector_into,
    model::{
        claim::{Claim, ClaimId, ClaimRelations},
        claim_schema::ClaimSchemaRelations,
        credential::{
            Credential, CredentialId, CredentialRelations, CredentialState,
            CredentialStateRelations, GetCredentialList, GetCredentialQuery,
            UpdateCredentialRequest,
        },
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        did::DidRelations,
        interaction::InteractionId,
        organisation::OrganisationRelations,
    },
    repository::{
        claim_repository::ClaimRepository, credential_repository::CredentialRepository,
        credential_schema_repository::CredentialSchemaRepository, error::DataLayerError,
    },
};
use sea_orm::{
    sea_query::{Alias, Expr, IntoCondition, Query},
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, JoinType,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait, Select, Set, SqlErr,
    Unchanged,
};
use std::{str::FromStr, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

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
    relations: &ClaimRelations,
    db: &DatabaseConnection,
    claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
) -> Result<Vec<Claim>, DataLayerError> {
    let ids: Vec<ClaimId> = credential_claim::Entity::find()
        .select_only()
        .columns([
            credential_claim::Column::ClaimId,
            credential_claim::Column::CredentialId,
        ])
        .filter(credential_claim::Column::CredentialId.eq(&credential.id))
        .join(
            sea_orm::JoinType::LeftJoin,
            credential_claim::Relation::Claim.def(),
        )
        .join(
            sea_orm::JoinType::LeftJoin,
            claim::Relation::ClaimSchema.def(),
        )
        .join(
            sea_orm::JoinType::LeftJoin,
            claim_schema::Relation::CredentialSchemaClaimSchema.def(),
        )
        // sorting claims according to the order from credential_schema
        .order_by_asc(credential_schema_claim_schema::Column::Order)
        .all(db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
        .into_iter()
        .map(|claim| Uuid::from_str(&claim.claim_id).map_err(|_| DataLayerError::MappingError))
        .collect::<Result<Vec<_>, _>>()?;

    claim_repository.get_claim_list(ids, relations).await
}

impl CredentialProvider {
    async fn credential_model_to_repository_model(
        &self,
        credential: credential::Model,
        relations: &CredentialRelations,
    ) -> Result<Credential, DataLayerError> {
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

        let state: Option<Vec<CredentialState>> = match &relations.state {
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
                    let interaction_id =
                        Uuid::from_str(interaction_id).map_err(|_| DataLayerError::MappingError)?;
                    Some(
                        self.interaction_repository
                            .get_interaction(&interaction_id, interaction_relations)
                            .await?,
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
                    let revocation_list_id = Uuid::from_str(revocation_list_id)
                        .map_err(|_| DataLayerError::MappingError)?;
                    Some(
                        self.revocation_list_repository
                            .get_revocation_list(&revocation_list_id, revocation_list_relations)
                            .await?,
                    )
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
            ..credential.try_into()?
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

        let credential = request_to_active_model(
            &request,
            schema,
            issuer_did,
            holder_did_id,
            interaction_id,
            revocation_list_id,
        )
        .insert(&self.db)
        .await
        .map_err(|e| match e.sql_err() {
            Some(SqlErr::UniqueConstraintViolation(_)) => DataLayerError::AlreadyExists,
            _ => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        if !claims.is_empty() {
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
        }

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

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .filter(credential::Column::InteractionId.eq(&interaction_id.to_string()))
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        self.credentials_to_repository(credentials, relations).await
    }

    async fn get_credentials_by_issuer_did_id(
        &self,
        issuer_did_id: &Uuid,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .filter(credential::Column::IssuerDidId.eq(&issuer_did_id.to_string()))
            .order_by_asc(credential::Column::CreatedDate)
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        self.credentials_to_repository(credentials, relations).await
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
                        state: Some(CredentialStateRelations::default()),
                        claims: None,
                        issuer_did: Some(DidRelations::default()),
                        holder_did: Some(DidRelations::default()),
                        schema: Some(CredentialSchemaRelations {
                            claim_schemas: Some(ClaimSchemaRelations {}),
                            organisation: Some(OrganisationRelations {}),
                        }),
                        ..Default::default()
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

    async fn get_credentials_by_claim_names(
        &self,
        claim_names: Vec<String>,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .join(
                JoinType::LeftJoin,
                credential::Relation::CredentialClaim.def(),
            )
            .join(JoinType::LeftJoin, credential_claim::Relation::Claim.def())
            .join(
                JoinType::LeftJoin,
                claim::Relation::ClaimSchema
                    .def()
                    .on_condition(move |_left, _right| {
                        Expr::col(claim_schema::Column::Key)
                            .is_in(&claim_names)
                            .into_condition()
                    }),
            )
            .distinct()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        self.credentials_to_repository(credentials, relations).await
    }
}
