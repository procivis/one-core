use std::str::FromStr;

use anyhow::anyhow;
use autometrics::autometrics;
use one_core::model::claim_schema::ClaimSchemaRelations;
use one_core::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use one_core::model::proof_schema::{
    GetProofSchemaList, GetProofSchemaQuery, ProofInputClaimSchema, ProofInputSchema,
    ProofInputSchemaRelations, ProofSchema, ProofSchemaRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::proof_schema_repository::ProofSchemaRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait, Unchanged,
};
use shared_types::{ClaimSchemaId, CredentialSchemaId, ProofSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::mapper::create_list_response;
use super::ProofSchemaProvider;
use crate::entity::{proof_input_claim_schema, proof_input_schema, proof_schema};
use crate::list_query::SelectWithListQuery;
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl ProofSchemaRepository for ProofSchemaProvider {
    async fn create_proof_schema(
        &self,
        request: ProofSchema,
    ) -> Result<ProofSchemaId, DataLayerError> {
        if request.organisation.is_none() {
            return Err(DataLayerError::IncorrectParameters);
        }

        let proof_schema_id = request.id;
        let proof_schema = proof_schema::ActiveModel::try_from(&request)?;

        let proof_input_schemas = request
            .input_schemas
            .ok_or(DataLayerError::IncorrectParameters)?;
        if proof_input_schemas.is_empty() {
            return Err(DataLayerError::IncorrectParameters);
        }

        let proof_input_schemas_active_model = proof_input_schemas
            .iter()
            .enumerate()
            .map(|(order, schema)| {
                let now = OffsetDateTime::now_utc();
                let credential_schema = schema
                    .credential_schema
                    .as_ref()
                    .ok_or(DataLayerError::IncorrectParameters)?;

                let input_schema = proof_input_schema::ActiveModel {
                    order: Set(order as i32),
                    created_date: Set(now),
                    last_modified: Set(now),
                    validity_constraint: Set(schema.validity_constraint),
                    credential_schema: Set(credential_schema.id.to_string()),
                    proof_schema: Set(proof_schema_id),
                    ..Default::default()
                };

                Ok::<_, DataLayerError>(input_schema)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let proof_input_schemas_with_order: Vec<(i32, ProofInputSchema)> =
            proof_input_schemas_active_model
                .iter()
                .zip(proof_input_schemas)
                .map(|(p1, p2)| (*p1.order.as_ref(), p2))
                .collect();

        let tx = self
            .db
            .begin()
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        proof_schema
            .insert(&tx)
            .await
            .map_err(to_data_layer_error)?;

        proof_input_schema::Entity::insert_many(proof_input_schemas_active_model)
            .exec(&tx)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        // we need proof_input_schema's id to construct the proof_input_claim_schema record
        // but this id is generated by the db when inserted so we need to fetch what we just inserted
        let retrieved_proof_input_schema = proof_input_schema::Entity::find()
            .filter(proof_input_schema::Column::ProofSchema.eq(proof_schema_id.to_string()))
            .all(&tx)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        if retrieved_proof_input_schema.len() != proof_input_schemas_with_order.len() {
            return Err(DataLayerError::Db(anyhow!(
                "Length of retrieved proof input schemas is different from the proof input schemas in the request for proof schema: {proof_schema_id}"
            )));
        }

        let mut retrieved_proof_input_schema = retrieved_proof_input_schema;
        retrieved_proof_input_schema.sort_by_key(|k| k.order);

        let mut proof_input_schemas = proof_input_schemas_with_order;
        proof_input_schemas.sort_by_key(|(order, _)| *order);

        let mut proof_input_claim_schemas = vec![];
        for (model, (order, request)) in retrieved_proof_input_schema
            .into_iter()
            .zip(proof_input_schemas)
        {
            let credential_schema = request
                .credential_schema
                .as_ref()
                .ok_or(DataLayerError::IncorrectParameters)?;

            if model.credential_schema != credential_schema.id.to_string()
                || order != model.order
                || model.validity_constraint != request.validity_constraint
            {
                return Err(DataLayerError::Db(anyhow!(
                    "Inserted proof input schema model doesn't match request proof input schema for proof schema: {proof_schema_id}"
                )));
            }

            let claim_schemas = request
                .claim_schemas
                .ok_or(DataLayerError::IncorrectParameters)?;

            for (order, claim_schema) in claim_schemas.iter().enumerate() {
                let schema = proof_input_claim_schema::ActiveModel {
                    claim_schema_id: Set(claim_schema.schema.id.to_string()),
                    proof_input_schema_id: Set(model.id),
                    order: Set(order as i32),
                    required: Set(claim_schema.required),
                };

                proof_input_claim_schemas.push(schema)
            }
        }
        proof_input_claim_schema::Entity::insert_many(proof_input_claim_schemas)
            .exec(&tx)
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        tx.commit()
            .await
            .map_err(|err| DataLayerError::Db(err.into()))?;

        Ok(proof_schema_id)
    }

    async fn get_proof_schema(
        &self,
        id: &ProofSchemaId,
        relations: &ProofSchemaRelations,
    ) -> Result<Option<ProofSchema>, DataLayerError> {
        let proof_schema_model = crate::entity::proof_schema::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let Some(proof_schema_model) = proof_schema_model else {
            return Ok(None);
        };

        let organisation_id = proof_schema_model.organisation_id.to_owned();
        let mut proof_schema = ProofSchema::from(proof_schema_model);

        if let Some(input_relations) = &relations.proof_inputs {
            proof_schema.input_schemas =
                Some(self.get_related_input_schemas(id, input_relations).await?);
        }

        if let Some(organisation_relations) = &relations.organisation {
            proof_schema.organisation = Some(
                self.organisation_repository
                    .get_organisation(&organisation_id, organisation_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "proof_schema-organisation",
                        id: organisation_id.to_string(),
                    })?,
            );
        }

        Ok(Some(proof_schema))
    }

    async fn get_proof_schema_list(
        &self,
        query_params: GetProofSchemaQuery,
    ) -> Result<GetProofSchemaList, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = crate::entity::proof_schema::Entity::find()
            .filter(proof_schema::Column::DeletedAt.is_null())
            .with_organisation_id(&query_params, &proof_schema::Column::OrganisationId)
            .with_ids(&query_params, &proof_schema::Column::Id)
            .with_list_query(&query_params, &Some(vec![proof_schema::Column::Name]))
            .order_by_desc(proof_schema::Column::CreatedDate)
            .order_by_desc(proof_schema::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let proof_schemas: Vec<proof_schema::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        create_list_response(proof_schemas, limit, items_count)
    }

    async fn delete_proof_schema(
        &self,
        id: &ProofSchemaId,
        deleted_at: OffsetDateTime,
    ) -> Result<(), DataLayerError> {
        let schema = proof_schema::ActiveModel {
            id: Unchanged(*id),
            deleted_at: Set(Some(deleted_at)),
            ..Default::default()
        };

        proof_schema::Entity::update(schema)
            .filter(proof_schema::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map_err(|error| match error {
                sea_orm::DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
                err => DataLayerError::Db(err.into()),
            })?;

        Ok(())
    }
}

impl ProofSchemaProvider {
    async fn get_related_credential_schema(
        &self,
        credential_schema_id: String,
        credential_schema_relations: &CredentialSchemaRelations,
    ) -> Result<CredentialSchema, DataLayerError> {
        let credential_schema_id = CredentialSchemaId::from_str(&credential_schema_id)?;

        self.credential_schema_repository
            .get_credential_schema(&credential_schema_id, credential_schema_relations)
            .await?
            .ok_or(DataLayerError::MissingRequiredRelation {
                relation: "proof_schema-credential_schema",
                id: credential_schema_id.to_string(),
            })
    }

    async fn get_related_input_schemas(
        &self,
        proof_schema_id: &ProofSchemaId,
        relations: &ProofInputSchemaRelations,
    ) -> Result<Vec<ProofInputSchema>, DataLayerError> {
        let mut inputs = Vec::new();

        let input_schemas = crate::entity::proof_input_schema::Entity::find()
            .filter(proof_input_schema::Column::ProofSchema.eq(proof_schema_id.to_string()))
            .order_by_asc(proof_input_schema::Column::Order)
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        for input_schema in input_schemas {
            let mut new_input = ProofInputSchema {
                validity_constraint: input_schema.validity_constraint,
                claim_schemas: None,
                credential_schema: None,
            };

            if relations.claim_schemas.is_some() {
                let input_schema_claim_schema =
                    crate::entity::proof_input_claim_schema::Entity::find()
                        .filter(
                            proof_input_claim_schema::Column::ProofInputSchemaId
                                .eq(input_schema.id),
                        )
                        .order_by_asc(proof_input_claim_schema::Column::Order)
                        .all(&self.db)
                        .await
                        .map_err(|e| DataLayerError::Db(e.into()))?;

                let claim_schema_ids = input_schema_claim_schema
                    .iter()
                    .map(|item| Uuid::from_str(&item.claim_schema_id).map(Into::into))
                    .collect::<Result<Vec<ClaimSchemaId>, _>>()?;

                let claim_schemas = self
                    .claim_schema_repository
                    .get_claim_schema_list(claim_schema_ids, &ClaimSchemaRelations::default())
                    .await?;

                let input_schema_claims = input_schema_claim_schema
                    .into_iter()
                    .zip(claim_schemas)
                    .map(|(model, schema)| ProofInputClaimSchema {
                        schema,
                        required: model.required,
                        order: model.order as u32,
                    })
                    .collect();

                new_input.claim_schemas = Some(input_schema_claims);
            }

            if let Some(credential_schema_relations) = &relations.credential_schema {
                let credential_schema = self
                    .get_related_credential_schema(
                        input_schema.credential_schema,
                        credential_schema_relations,
                    )
                    .await?;

                new_input.credential_schema = Some(credential_schema);
            }

            inputs.push(new_input)
        }
        Ok(inputs)
    }
}
