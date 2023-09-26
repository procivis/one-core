use super::{
    mapper::{create_list_response, proof_schema_claim_to_active_model},
    ProofSchemaProvider,
};
use crate::{
    entity::{
        claim_schema, credential_schema_claim_schema, proof_schema, proof_schema_claim_schema,
    },
    error_mapper::to_data_layer_error,
    list_query::SelectWithListQuery,
};
use one_core::{
    model::{
        claim_schema::{ClaimSchemaId, ClaimSchemaRelations},
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        proof_schema::{
            GetProofSchemaList, GetProofSchemaQuery, ProofSchema, ProofSchemaClaim,
            ProofSchemaClaimRelations, ProofSchemaId, ProofSchemaRelations,
        },
    },
    repository::{error::DataLayerError, proof_schema_repository::ProofSchemaRepository},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait, Set,
};
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

#[async_trait::async_trait]
impl ProofSchemaRepository for ProofSchemaProvider {
    async fn create_proof_schema(
        &self,
        request: ProofSchema,
    ) -> Result<ProofSchemaId, DataLayerError> {
        if request.organisation.is_none() {
            return Err(DataLayerError::IncorrectParameters);
        }

        let active_model = proof_schema::ActiveModel::try_from(&request)?;
        let id = request.id;

        let claim_schemas = request
            .claim_schemas
            .ok_or(DataLayerError::IncorrectParameters)?;
        if claim_schemas.is_empty() {
            return Err(DataLayerError::IncorrectParameters);
        }

        active_model
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let proof_schema_claim_schema_relations: Vec<proof_schema_claim_schema::ActiveModel> =
            claim_schemas
                .into_iter()
                .enumerate()
                .map(|(i, claim_schema)| {
                    proof_schema_claim_to_active_model(claim_schema, &id, i as u32)
                })
                .collect();

        proof_schema_claim_schema::Entity::insert_many(proof_schema_claim_schema_relations)
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(id)
    }

    async fn get_proof_schema(
        &self,
        id: &ProofSchemaId,
        relations: &ProofSchemaRelations,
    ) -> Result<ProofSchema, DataLayerError> {
        let proof_schema_model: proof_schema::Model =
            crate::entity::ProofSchema::find_by_id(id.to_string())
                .one(&self.db)
                .await
                .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
                .ok_or(DataLayerError::RecordNotFound)?;

        let organisation_id = proof_schema_model.organisation_id.to_owned();
        let mut proof_schema = ProofSchema::try_from(proof_schema_model)?;

        if let Some(claim_relations) = &relations.claim_schemas {
            proof_schema.claim_schemas =
                Some(self.get_related_claim_schemas(id, claim_relations).await?);
        }

        if let Some(organisation_relations) = &relations.organisation {
            let organisation_id =
                Uuid::from_str(&organisation_id).map_err(|_| DataLayerError::MappingError)?;

            proof_schema.organisation = Some(
                self.organisation_repository
                    .get_organisation(&organisation_id, organisation_relations)
                    .await?,
            );
        }

        Ok(proof_schema)
    }

    async fn get_proof_schema_list(
        &self,
        query_params: GetProofSchemaQuery,
    ) -> Result<GetProofSchemaList, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = crate::entity::ProofSchema::find()
            .filter(proof_schema::Column::DeletedAt.is_null())
            .with_organisation_id(&query_params, &proof_schema::Column::OrganisationId)
            .with_list_query(&query_params, &Some(vec![proof_schema::Column::Name]))
            .order_by_desc(proof_schema::Column::CreatedDate)
            .order_by_desc(proof_schema::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let proof_schemas: Vec<proof_schema::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        create_list_response(proof_schemas, limit, items_count)
    }

    async fn delete_proof_schema(
        &self,
        id: &ProofSchemaId,
        deleted_at: OffsetDateTime,
    ) -> Result<(), DataLayerError> {
        let result = crate::entity::ProofSchema::find_by_id(id.to_string())
            .filter(proof_schema::Column::DeletedAt.is_null())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let schema = result.ok_or(DataLayerError::RecordNotFound)?;

        let mut value: proof_schema::ActiveModel = schema.into();
        value.deleted_at = Set(Some(deleted_at));
        value
            .update(&self.db)
            .await
            .map_err(|_| DataLayerError::RecordNotUpdated)?;

        Ok(())
    }
}

impl ProofSchemaProvider {
    async fn get_related_credential_schema(
        &self,
        credential_schema_id: String,
        credential_schema_relations: &CredentialSchemaRelations,
    ) -> Result<CredentialSchema, DataLayerError> {
        let credential_schema_id =
            Uuid::from_str(&credential_schema_id).map_err(|_| DataLayerError::MappingError)?;

        self.credential_schema_repository
            .get_credential_schema(&credential_schema_id, credential_schema_relations)
            .await
    }

    async fn get_related_claim_schemas(
        &self,
        proof_schema_id: &ProofSchemaId,
        relations: &ProofSchemaClaimRelations,
    ) -> Result<Vec<ProofSchemaClaim>, DataLayerError> {
        #[derive(FromQueryResult)]
        struct ProofSchemaClaimCombinedModel {
            pub id: String,
            pub required: bool,
            pub credential_schema_id: String,
        }

        let proof_schema_claims = crate::entity::ProofSchemaClaimSchema::find()
            .filter(
                proof_schema_claim_schema::Column::ProofSchemaId.eq(proof_schema_id.to_string()),
            )
            .order_by_asc(proof_schema_claim_schema::Column::Order)
            .join(
                sea_orm::JoinType::LeftJoin,
                proof_schema_claim_schema::Relation::ClaimSchema.def(),
            )
            .join(
                sea_orm::JoinType::LeftJoin,
                claim_schema::Relation::CredentialSchemaClaimSchema.def(),
            )
            .select_only()
            .columns([proof_schema_claim_schema::Column::Required])
            .columns([claim_schema::Column::Id])
            .columns([credential_schema_claim_schema::Column::CredentialSchemaId])
            .into_model::<ProofSchemaClaimCombinedModel>()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let claim_schema_ids = proof_schema_claims
            .iter()
            .map(|item| Uuid::from_str(&item.id))
            .collect::<Result<Vec<ClaimSchemaId>, _>>()
            .map_err(|_| DataLayerError::MappingError)?;

        let claim_schemas = self
            .claim_schema_repository
            .get_claim_schema_list(claim_schema_ids, &ClaimSchemaRelations::default())
            .await?;

        let proof_schema_claims_with_credential_schema_ids: Vec<(ProofSchemaClaim, String)> =
            proof_schema_claims
                .into_iter()
                .zip(claim_schemas)
                .map(|(model, schema)| {
                    (
                        ProofSchemaClaim {
                            schema,
                            required: model.required,
                            credential_schema: None,
                        },
                        model.credential_schema_id,
                    )
                })
                .collect();

        if let Some(credential_schema_relations) = &relations.credential_schema {
            let mut claim_schemas = Vec::<ProofSchemaClaim>::with_capacity(
                proof_schema_claims_with_credential_schema_ids.len(),
            );

            for (proof_schema_claim, credential_schema_id) in
                proof_schema_claims_with_credential_schema_ids
            {
                let credential_schema = self
                    .get_related_credential_schema(
                        credential_schema_id,
                        credential_schema_relations,
                    )
                    .await?;

                claim_schemas.push(ProofSchemaClaim {
                    credential_schema: Some(credential_schema),
                    ..proof_schema_claim
                })
            }

            Ok(claim_schemas)
        } else {
            Ok(proof_schema_claims_with_credential_schema_ids
                .into_iter()
                .map(|(proof_schema_claim, _)| proof_schema_claim)
                .collect())
        }
    }
}
