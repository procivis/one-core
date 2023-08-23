use std::collections::HashMap;

use one_core::{
    config::{
        data_structure::{DatatypeEntity, FormatEntity, RevocationEntity},
        validator::{
            datatype::validate_datatypes, format::validate_format, revocation::validate_revocation,
        },
    },
    repository::{
        data_provider::{CreateCredentialSchemaFromJwtRequest, CreateCredentialSchemaResponse},
        error::DataLayerError,
    },
};
use sea_orm::{ActiveModelTrait, EntityTrait, Set, SqlErr};
use time::OffsetDateTime;

use crate::{
    entity::{claim_schema, credential_schema, credential_schema_claim_schema},
    OldProvider,
};

impl OldProvider {
    pub async fn create_credential_schema_from_jwt(
        &self,
        request: CreateCredentialSchemaFromJwtRequest,
        formats: &HashMap<String, FormatEntity>,
        revocation_methods: &HashMap<String, RevocationEntity>,
        datatypes: &HashMap<String, DatatypeEntity>,
    ) -> Result<CreateCredentialSchemaResponse, DataLayerError> {
        let now = OffsetDateTime::now_utc();

        // To be moved to credential service
        validate_format(&request.format, formats)?;
        validate_revocation(&request.revocation_method, revocation_methods)?;
        validate_datatypes(
            &request
                .claims
                .iter()
                .map(|f| &f.datatype)
                .collect::<Vec<&String>>(),
            datatypes,
        )
        .map_err(DataLayerError::ConfigValidationError)?;

        let credential_schema = credential_schema::ActiveModel {
            id: Set(request.id.to_string()),
            name: Set(request.name),
            created_date: Set(now),
            last_modified: Set(now),
            format: Set(request.format),
            deleted_at: Set(None),
            revocation_method: Set(request.revocation_method),
            organisation_id: Set(request.organisation_id.to_string()),
        }
        .insert(&self.db)
        .await
        .map_err(|e| match e.sql_err() {
            Some(sql_error) if matches!(sql_error, SqlErr::UniqueConstraintViolation(_)) => {
                DataLayerError::AlreadyExists
            }
            Some(_) | None => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;

        if !request.claims.is_empty() {
            let claim_schema_models: Vec<claim_schema::ActiveModel> = request
                .claims
                .iter()
                .map(|claim_data| claim_schema::ActiveModel {
                    id: Set(claim_data.id.to_string()),
                    created_date: Set(now),
                    last_modified: Set(now),
                    key: Set(claim_data.key.clone()),
                    datatype: Set(claim_data.datatype.clone()),
                })
                .collect();

            let credential_schema_claim_schema_relations: Vec<
                credential_schema_claim_schema::ActiveModel,
            > = claim_schema_models
                .iter()
                .enumerate()
                .map(
                    |(i, claim_schema)| credential_schema_claim_schema::ActiveModel {
                        claim_schema_id: claim_schema.id.clone(),
                        credential_schema_id: Set(credential_schema.id.clone()),
                        required: Set(false),
                        order: Set(i as u32),
                    },
                )
                .collect();

            claim_schema::Entity::insert_many(claim_schema_models)
                .exec(&self.db)
                .await
                .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

            credential_schema_claim_schema::Entity::insert_many(
                credential_schema_claim_schema_relations,
            )
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;
        }

        Ok(CreateCredentialSchemaResponse {
            id: credential_schema.id,
        })
    }
}
