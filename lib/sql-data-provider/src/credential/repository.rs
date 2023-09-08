use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

use sea_orm::sea_query::IntoCondition;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, ModelTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait, Select, Set, SqlErr,
    Unchanged,
};

use one_core::common_mapper::vector_into;
use one_core::model::credential::{CredentialState, CredentialStateRelations};
use one_core::{
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::ClaimSchemaRelations,
        credential::{Credential, CredentialId, CredentialRelations},
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

        let receiver_did = match &credential.receiver_did_id {
            None => None,
            Some(receiver_did_id) => {
                let uuid =
                    Uuid::from_str(receiver_did_id).map_err(|_| DataLayerError::MappingError)?;
                get_did(&uuid, &relations.receiver_did, self.did_repository.clone()).await?
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
            receiver_did,
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

fn get_select_credentials_query(
    base_query: Select<credential::Entity>,
    organisation_id: Option<String>,
) -> Select<credential::Entity> {
    base_query
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
            credential::Column::ReceiverDidId,
            credential::Column::CredentialSchemaId,
        ])
        // add related schema
        .join_rev(
            sea_orm::JoinType::InnerJoin,
            credential::Relation::CredentialSchema
                .def()
                .rev()
                .on_condition(move |_left, _right| match &organisation_id {
                    None => Condition::all(),
                    Some(id) => credential_schema::Column::OrganisationId
                        .eq(id)
                        .into_condition(),
                }),
        )
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
        let receiver_did = match request.receiver_did.to_owned() {
            None => None,
            Some(did) => Some(did.id.to_string()),
        };
        let schema = request
            .schema
            .to_owned()
            .ok_or(DataLayerError::MappingError)?;
        let claims = request
            .claims
            .to_owned()
            .ok_or(DataLayerError::MappingError)?;

        let credential = request_to_active_model(&request, schema, issuer_did, receiver_did)
            .insert(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

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
                self.set_credential_state(&request.id, state).await?;
            }
        }

        Ok(request.id)
    }

    async fn get_all_credential_list(&self) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let relations = CredentialRelations {
            state: Some(CredentialStateRelations {}),
            claims: None,
            issuer_did: Some(DidRelations {}),
            receiver_did: Some(DidRelations {}),
            schema: Some(CredentialSchemaRelations {
                claim_schema: Some(ClaimSchemaRelations {}),
                organisation: Some(OrganisationRelations {}),
            }),
        };

        self.credentials_to_repository(credentials, &relations)
            .await
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

        let query = get_select_credentials_query(
            credential::Entity::find()
                .with_list_query(&query_params, &Some(vec![credential_schema::Column::Name])),
            Some(query_params.organisation_id),
        );

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let credentials = query
            .to_owned()
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
                        receiver_did: Some(DidRelations {}),
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

    async fn set_credential_state(
        &self,
        id: &CredentialId,
        state: CredentialState,
    ) -> Result<(), DataLayerError> {
        let update_model = credential::ActiveModel {
            id: Unchanged(id.to_string()),
            last_modified: Set(state.created_date),
            ..Default::default()
        };

        credential_state::Entity::insert(get_credential_state_active_model(id, state))
            .exec(&self.db)
            .await
            .map_err(|e| match e.sql_err() {
                Some(SqlErr::ForeignKeyConstraintViolation(_)) => DataLayerError::RecordNotFound,
                _ => DataLayerError::GeneralRuntimeError(e.to_string()),
            })?;

        update_model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        Ok(())
    }
}
