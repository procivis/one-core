use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use autometrics::autometrics;
use one_core::model::claim::{Claim, ClaimId, ClaimRelations};
use one_core::model::credential::{
    Clearable, Credential, CredentialRelations, GetCredentialList, GetCredentialQuery,
    UpdateCredentialRequest,
};
use one_core::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use one_core::model::identifier::{Identifier, IdentifierRelations};
use one_core::model::interaction::InteractionId;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::service::credential::dto::CredentialListIncludeEntityTypeEnum;
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::NotSet;
use sea_orm::sea_query::{Expr, IntoCondition};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, FromQueryResult, JoinType,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait, Select, Set, SqlErr,
    Unchanged,
};
use shared_types::{CredentialId, CredentialSchemaId, IdentifierId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::calculate_pages_count;
use crate::credential::CredentialProvider;
use crate::credential::entity_model::CredentialListEntityModel;
use crate::credential::mapper::{credentials_to_repository, request_to_active_model};
use crate::entity::{
    claim, claim_schema, credential, credential_schema, credential_schema_claim_schema, identifier,
};
use crate::list_query_generic::{SelectWithFilterJoin, SelectWithListQuery};
use crate::mapper::to_update_data_layer_error;

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
        let issuer_identifier = get_related_identifier(
            self.identifier_repository.as_ref(),
            credential.issuer_identifier_id.as_ref(),
            relations.issuer_identifier.as_ref(),
        )
        .await?;

        let holder_identifier = get_related_identifier(
            self.identifier_repository.as_ref(),
            credential.holder_identifier_id.as_ref(),
            relations.holder_identifier.as_ref(),
        )
        .await?;

        let schema = get_credential_schema(
            &credential.credential_schema_id,
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

        let issuer_certificate = if let Some(certificate_relations) = &relations.issuer_certificate
        {
            match &credential.issuer_certificate_id {
                None => None,
                Some(certificate_id) => {
                    let certificate = self
                        .certificate_repository
                        .get(*certificate_id, certificate_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "credential-certificate",
                            id: certificate_id.to_string(),
                        })?;
                    Some(certificate)
                }
            }
        } else {
            None
        };

        Ok(Credential {
            issuer_identifier,
            holder_identifier,
            claims,
            schema,
            revocation_list,
            interaction,
            key,
            issuer_certificate,
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

fn get_credential_list_query(query_params: GetCredentialQuery) -> Select<credential::Entity> {
    let mut query = credential::Entity::find()
        .select_only()
        .columns([
            credential::Column::Id,
            credential::Column::CreatedDate,
            credential::Column::LastModified,
            credential::Column::IssuanceDate,
            credential::Column::DeletedAt,
            credential::Column::RedirectUri,
            credential::Column::Role,
            credential::Column::State,
            credential::Column::SuspendEndDate,
            credential::Column::Protocol,
            credential::Column::Profile,
        ])
        .join(
            sea_orm::JoinType::InnerJoin,
            credential::Relation::CredentialSchema.def(),
        )
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
            credential_schema::Column::WalletStorageType,
            "credential_schema_wallet_storage_type",
        )
        .column_as(
            credential_schema::Column::ImportedSourceUrl,
            "credential_schema_imported_source_url",
        )
        .column_as(
            credential_schema::Column::SchemaId,
            "credential_schema_schema_id",
        )
        .column_as(
            credential_schema::Column::SchemaType,
            "credential_schema_schema_type",
        )
        .column_as(
            credential_schema::Column::AllowSuspension,
            "credential_schema_allow_suspension",
        )
        .column_as(
            credential_schema::Column::ExternalSchema,
            "credential_schema_external_schema",
        )
        .join(
            JoinType::LeftJoin,
            credential::Relation::IssuerIdentifier.def(),
        )
        .column_as(identifier::Column::Id, "issuer_identifier_id")
        .column_as(
            identifier::Column::CreatedDate,
            "issuer_identifier_created_date",
        )
        .column_as(
            identifier::Column::LastModified,
            "issuer_identifier_last_modified",
        )
        .column_as(identifier::Column::Name, "issuer_identifier_name")
        .column_as(identifier::Column::Type, "issuer_identifier_type")
        .column_as(identifier::Column::IsRemote, "issuer_identifier_is_remote")
        .column_as(identifier::Column::State, "issuer_identifier_state")
        .filter(credential::Column::DeletedAt.is_null())
        // list query
        .with_filter_join(&query_params)
        .with_list_query(&query_params);

    if query_params.sorting.is_some() || query_params.pagination.is_some() {
        // fallback ordering
        query = query
            .order_by_desc(credential::Column::CreatedDate)
            .order_by_desc(credential::Column::Id);
    }

    if let Some(include) = query_params.include {
        if include.contains(&CredentialListIncludeEntityTypeEnum::LayoutProperties) {
            query = query.column_as(
                credential_schema::Column::LayoutProperties,
                "credential_schema_schema_layout_properties",
            );
        }

        if include.contains(&CredentialListIncludeEntityTypeEnum::Credential) {
            query = query.column(credential::Column::Credential);
        }
    }

    query
}

#[autometrics]
#[async_trait::async_trait]
impl CredentialRepository for CredentialProvider {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        let issuer_identifier_id = request
            .issuer_identifier
            .as_ref()
            .map(|identifier| identifier.id);

        let issuer_certificate_id = request.issuer_certificate.as_ref().map(|cert| cert.id);

        let holder_identifier_id = request
            .holder_identifier
            .as_ref()
            .map(|identifier| identifier.id);
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
            issuer_identifier_id,
            issuer_certificate_id,
            holder_identifier_id,
            interaction_id,
            revocation_list_id,
            convert_inner(key_id),
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

        Ok(request.id)
    }

    async fn delete_credential(&self, credential: &Credential) -> Result<(), DataLayerError> {
        let now = OffsetDateTime::now_utc();

        let credential = credential::ActiveModel {
            id: Unchanged(credential.id),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        credential::Entity::update(credential)
            .filter(credential::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map(|_| ())
            .map_err(to_update_data_layer_error)
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

    async fn get_credentials_by_issuer_identifier_id(
        &self,
        issuer_identifier_id: IdentifierId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        let credentials = credential::Entity::find()
            .filter(credential::Column::IssuerIdentifierId.eq(issuer_identifier_id))
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

        let (items_count, credentials) = tokio::join!(
            query.to_owned().count(&self.db),
            query
                .into_model::<CredentialListEntityModel>()
                .all(&self.db)
        );

        let items_count = items_count.map_err(|e| DataLayerError::Db(e.into()))?;
        let credentials = credentials.map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(GetCredentialList {
            values: credentials_to_repository(credentials)?,
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
            total_items: items_count,
        })
    }

    async fn update_credential(
        &self,
        credential_id: CredentialId,
        request: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        let holder_identifier_id = match request.holder_identifier_id {
            None => Unchanged(Default::default()),
            Some(identifier_id) => Set(Some(identifier_id)),
        };

        let issuer_identifier_id = match request.issuer_identifier_id {
            None => Unchanged(Default::default()),
            Some(identifier_id) => Set(Some(identifier_id)),
        };

        let issuer_certificate_id = match request.issuer_certificate_id {
            None => Unchanged(Default::default()),
            Some(certificate_id) => Set(Some(certificate_id)),
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

        let suspend_end_date = match request.suspend_end_date {
            Clearable::ForceSet(date) => match date {
                None => Set(None),
                Some(suspend) => Set(Some(suspend)),
            },
            Clearable::DontTouch => Unchanged(Default::default()),
        };

        let state = match request.state {
            None => NotSet,
            Some(state) => Set(state.into()),
        };

        let update_model = credential::ActiveModel {
            id: Unchanged(credential_id),
            last_modified: Set(OffsetDateTime::now_utc()),
            holder_identifier_id,
            issuer_identifier_id,
            issuer_certificate_id,
            credential,
            interaction_id,
            key_id,
            redirect_uri,
            suspend_end_date,
            state,
            ..Default::default()
        };

        if let Some(claims) = request.claims {
            if claims
                .iter()
                .any(|claim| claim.credential_id != credential_id)
            {
                return Err(anyhow::anyhow!("Claim credential-id mismatch!").into());
            }

            self.claim_repository
                .delete_claims_for_credential(credential_id)
                .await?;

            self.claim_repository.create_claim_list(claims).await?;
        }

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

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

    async fn delete_credential_blobs(
        &self,
        request: HashSet<CredentialId>,
    ) -> Result<(), DataLayerError> {
        credential::Entity::update_many()
            .filter(credential::Column::Id.is_in(request))
            .set(credential::ActiveModel {
                credential: Set(vec![]),
                ..Default::default()
            })
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(())
    }
}

async fn get_related_identifier(
    repo: &dyn IdentifierRepository,
    id: Option<&IdentifierId>,
    relations: Option<&IdentifierRelations>,
) -> Result<Option<Identifier>, DataLayerError> {
    let identifier = match id.zip(relations) {
        None => None,
        Some((id, relations)) => {
            let identifier =
                repo.get(*id, relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "credential-identifier",
                        id: id.to_string(),
                    })?;

            Some(identifier)
        }
    };

    Ok(identifier)
}
