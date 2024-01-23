use crate::{
    common::calculate_pages_count,
    credential::{
        entity_model::CredentialListEntityModel,
        mapper::{
            credentials_to_repository, get_credential_state_active_model, request_to_active_model,
        },
        CredentialProvider,
    },
    entity::{
        claim, claim_schema, credential, credential_schema, credential_schema_claim_schema,
        credential_state, did,
    },
    list_query_generic::SelectWithListQuery,
};
use autometrics::autometrics;
use dto_mapper::convert_inner;
use one_core::{
    model::{
        claim::{Claim, ClaimId, ClaimRelations},
        credential::{
            Credential, CredentialId, CredentialRelations, CredentialState, GetCredentialList,
            GetCredentialQuery, UpdateCredentialRequest,
        },
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        did::{Did, DidRelations},
        interaction::InteractionId,
    },
    repository::{
        claim_repository::ClaimRepository, credential_repository::CredentialRepository,
        credential_schema_repository::CredentialSchemaRepository, did_repository::DidRepository,
        error::DataLayerError,
    },
};
use sea_orm::{
    sea_query::{Alias, Expr, IntoCondition, Query},
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait,
    FromQueryResult, JoinType, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait,
    Select, Set, SqlErr, Unchanged,
};
use shared_types::DidId;
use std::{str::FromStr, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

async fn get_credential_schema(
    schema_id: &Uuid,
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
        .filter(claim::Column::CredentialId.eq(&credential.id))
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
                        DataLayerError::Db(e.into())
                    })?;

                Some(convert_inner(credential_states))
            }
        };

        let schema_id = Uuid::from_str(&credential.credential_schema_id)?;
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
                    let key_id = Uuid::from_str(key_id)?;
                    let key = self
                        .key_repository
                        .get_key(&key_id, key_relations)
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
            credential::Column::RedirectUri,
            credential::Column::Role,
        ])
        .column_as(
            credential_schema::Column::CreatedDate,
            "credential_schema_created_date",
        )
        .column_as(
            credential_schema::Column::Format,
            "credential_schema_format",
        )
        .column_as(credential_schema::Column::Id, "credential_schema_id")
        .column_as(
            credential_schema::Column::LastModified,
            "credential_schema_last_modified",
        )
        .column_as(credential_schema::Column::Name, "credential_schema_name")
        .column_as(
            credential_schema::Column::RevocationMethod,
            "credential_schema_revocation_method",
        )
        .column_as(
            credential_state::Column::CreatedDate,
            "credential_state_created_date",
        )
        .column_as(credential_state::Column::State, "credential_state_state")
        .column_as(did::Column::CreatedDate, "issuer_did_created_date")
        .column_as(did::Column::Deactivated, "issuer_did_deactivated")
        .column_as(did::Column::Did, "issuer_did_did")
        .column_as(did::Column::Id, "issuer_did_id")
        .column_as(did::Column::LastModified, "issuer_did_last_modified")
        .column_as(did::Column::Method, "issuer_did_method")
        .column_as(did::Column::Name, "issuer_did_name")
        .column_as(did::Column::TypeField, "issuer_did_type_field")
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
            Condition::all()
                .add(
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
                .add(credential::Column::DeletedAt.is_null()),
        )
        // list query
        .with_list_query(&query_params)
        // fallback ordering
        .order_by_desc(credential::Column::CreatedDate)
        .order_by_desc(credential::Column::Id)
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
            return Err(DataLayerError::Db(anyhow::anyhow!(
                "Claim credential-id mismatch!",
            )));
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
                    ..Default::default()
                })
                .await?;
            }
        }

        Ok(request.id)
    }

    async fn delete_credential(&self, id: &CredentialId) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let credential = credential::ActiveModel {
            id: Unchanged(id.to_string()),
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
        let credential = credential::Entity::find_by_id(id.to_string())
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
            .filter(credential::Column::InteractionId.eq(&interaction_id.to_string()))
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
        let issuer_did_id = issuer_did_id.to_string();

        let credentials = credential::Entity::find()
            .filter(credential::Column::IssuerDidId.eq(&issuer_did_id))
            .order_by_asc(credential::Column::CreatedDate)
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        self.credentials_to_repository(credentials, relations).await
    }

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQuery,
    ) -> Result<GetCredentialList, DataLayerError> {
        let limit = query_params
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as _);

        let query = get_credential_list_query(query_params);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let credentials = query
            .into_model::<CredentialListEntityModel>()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(GetCredentialList {
            values: credentials_to_repository(credentials)?,
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
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
            Some(key_id) => Set(Some(key_id.to_string())),
        };

        let redirect_uri = match request.redirect_uri {
            None => Unchanged(Default::default()),
            Some(redirect_uri) => Set(redirect_uri),
        };

        let update_model = credential::ActiveModel {
            id: Unchanged(id.to_string()),
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
            credential_state::Entity::insert(get_credential_state_active_model(id, state))
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
            .join(JoinType::LeftJoin, credential::Relation::Claim.def())
            .join(
                JoinType::LeftJoin,
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
