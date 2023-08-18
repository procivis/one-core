use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait};
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::{data_structure::DatatypeEntity, validator::datatype::validate_value},
    data_layer::{
        common_queries::{fetch_credential_schema_claim_schemas, insert_credential_state},
        data_model::{
            CreateCredentialRequest, CredentialSchemaClaimSchemaCombined, EntityResponse,
        },
        entities::{claim, credential, credential_claim, credential_state, CredentialSchema, Did},
        DataLayer, DataLayerError,
    },
};

fn get_datatype(
    claim_schema_id: &str,
    schemas_combined: &[CredentialSchemaClaimSchemaCombined],
) -> Result<String, DataLayerError> {
    match schemas_combined.iter().find(|f| f.id == claim_schema_id) {
        None => Err(DataLayerError::RecordNotFound),
        Some(value) => Ok(value.datatype.to_owned()),
    }
}

impl DataLayer {
    pub async fn create_credential(
        &self,
        request: CreateCredentialRequest,
        datatypes: &HashMap<String, DatatypeEntity>,
    ) -> Result<EntityResponse, DataLayerError> {
        let did: super::entities::did::Model = Did::find_by_id(request.issuer_did.to_string())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        let credential_schema =
            CredentialSchema::find_by_id(request.credential_schema_id.to_string())
                .one(&self.db)
                .await
                .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
                .ok_or(DataLayerError::RecordNotFound)?;

        let schemas_combined =
            fetch_credential_schema_claim_schemas(&self.db, &[credential_schema.id]).await?;

        for request_claim in request.claim_values.iter() {
            let schema_id = request_claim.claim_id;
            let datatype = get_datatype(&schema_id.to_string(), &schemas_combined)?;

            validate_value(&request_claim.value, &datatype, datatypes)
                .map_err(DataLayerError::DatatypeValidationError)?;
        }

        let now = OffsetDateTime::now_utc();

        let credential = credential::ActiveModel {
            id: Set(request.credential_id.unwrap_or(Uuid::new_v4().to_string())),
            credential_schema_id: Set(request.credential_schema_id.to_string()),
            created_date: Set(now),
            last_modified: Set(now),
            issuance_date: Set(now),
            deleted_at: Set(None),
            transport: Set(request.transport.into()),
            credential: Set(request.credential.unwrap_or(vec![])),
            issuer_did_id: Set(did.id),
            receiver_did_id: Set(request.receiver_did_id.map(|uuid| uuid.to_string())),
        }
        .insert(&self.db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let claim_models: Vec<claim::ActiveModel> = request
            .claim_values
            .into_iter()
            .map(|request_claim| claim::ActiveModel {
                id: Set(Uuid::new_v4().to_string()),
                claim_schema_id: Set(request_claim.claim_id.to_string()),
                value: Set(request_claim.value),
                created_date: Set(now),
                last_modified: Set(now),
            })
            .collect();

        let credential_claim_models: Vec<credential_claim::ActiveModel> = claim_models
            .clone()
            .into_iter()
            .map(|claim| credential_claim::ActiveModel {
                claim_id: claim.id,
                credential_id: Set(credential.id.clone()),
            })
            .collect();

        claim::Entity::insert_many(claim_models)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        credential_claim::Entity::insert_many(credential_claim_models)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        insert_credential_state(
            &self.db,
            &credential.id,
            now,
            credential_state::CredentialState::Created,
        )
        .await?;

        Ok(EntityResponse { id: credential.id })
    }
}

#[cfg(test)]
mod tests {
    use crate::data_layer::{
        data_model::{CreateCredentialRequestClaim, Transport},
        entities::{Claim, Credential, CredentialState},
        test_utilities::*,
    };

    use super::*;

    #[tokio::test]
    async fn create_credential_test_simple() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();
        let datatypes = get_datatypes();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let did = insert_did(&data_layer.db, "did name", "test123", &organisation_id)
            .await
            .unwrap();
        let credential_schema_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id, "test123")
                .await
                .unwrap();

        let new_claims: Vec<(Uuid, bool, u32, &str)> = (0..4)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i, "STRING"))
            .collect();
        insert_many_claims_schema_to_database(&data_layer.db, &credential_schema_id, &new_claims)
            .await
            .unwrap();

        let claim_count = Claim::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, claim_count);
        let credential_count = Credential::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, credential_count);
        let credential_state_count = CredentialState::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, credential_state_count);

        let result = data_layer
            .create_credential(
                CreateCredentialRequest {
                    credential_id: None,
                    credential_schema_id: credential_schema_id.parse().unwrap(),
                    issuer_did: did.parse().unwrap(),
                    transport: Transport::ProcivisTemporary,
                    claim_values: vec![CreateCredentialRequestClaim {
                        claim_id: new_claims[0].0,
                        value: "placeholder".to_string(),
                    }],
                    receiver_did_id: None,
                    credential: None,
                },
                &datatypes,
            )
            .await;
        assert!(result.is_ok());

        let claim_count = Claim::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(1, claim_count);
        let credential_count = Credential::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(1, credential_count);
        let credential_state_count = CredentialState::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(1, credential_state_count);
    }

    #[tokio::test]
    async fn create_credential_test_claim_data_validation() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();
        let datatypes = get_datatypes();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let did = insert_did(&data_layer.db, "test123", "test123", &organisation_id)
            .await
            .unwrap();
        let credential_schema_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id, "test123")
                .await
                .unwrap();

        let new_claims: Vec<(Uuid, bool, u32, &str)> = vec![
            (Uuid::new_v4(), false, 0, "NUMBER"),
            (Uuid::new_v4(), true, 1, "DATE"),
        ];
        insert_many_claims_schema_to_database(&data_layer.db, &credential_schema_id, &new_claims)
            .await
            .unwrap();

        let claim_count = Claim::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, claim_count);
        let credential_count = Credential::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, credential_count);
        let credential_state_count = CredentialState::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, credential_state_count);

        let failed_to_verify_number = data_layer
            .create_credential(
                CreateCredentialRequest {
                    credential_id: None,
                    credential_schema_id: credential_schema_id.parse().unwrap(),
                    issuer_did: did.parse().unwrap(),
                    transport: Transport::ProcivisTemporary,
                    claim_values: vec![CreateCredentialRequestClaim {
                        claim_id: new_claims[0].0,
                        value: "this is not a number".to_string(),
                    }],
                    receiver_did_id: None,
                    credential: None,
                },
                &datatypes,
            )
            .await;
        assert!(failed_to_verify_number
            .is_err_and(|e| matches!(e, DataLayerError::DatatypeValidationError(_))));

        let failed_to_verify_date = data_layer
            .create_credential(
                CreateCredentialRequest {
                    credential_id: None,
                    credential_schema_id: credential_schema_id.parse().unwrap(),
                    issuer_did: did.parse().unwrap(),
                    transport: Transport::ProcivisTemporary,
                    claim_values: vec![CreateCredentialRequestClaim {
                        claim_id: new_claims[1].0,
                        value: "this is not a date".to_string(),
                    }],
                    receiver_did_id: None,
                    credential: None,
                },
                &datatypes,
            )
            .await;
        assert!(failed_to_verify_date
            .is_err_and(|e| matches!(e, DataLayerError::DatatypeValidationError(_))));

        let claim_count = Claim::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, claim_count);
        let credential_count = Credential::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(0, credential_count);
        let credential_state_count = CredentialState::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(0, credential_state_count);

        let correct_insert = data_layer
            .create_credential(
                CreateCredentialRequest {
                    credential_id: None,
                    credential_schema_id: credential_schema_id.parse().unwrap(),
                    issuer_did: did.parse().unwrap(),
                    transport: Transport::ProcivisTemporary,
                    claim_values: vec![
                        CreateCredentialRequestClaim {
                            claim_id: new_claims[0].0,
                            value: "123".to_string(),
                        },
                        CreateCredentialRequestClaim {
                            claim_id: new_claims[1].0,
                            value: "2005-04-02T21:37:42.069Z".to_string(),
                        },
                    ],
                    receiver_did_id: None,
                    credential: None,
                },
                &datatypes,
            )
            .await;
        assert!(correct_insert.is_ok());

        let claim_count = Claim::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(2, claim_count);
        let credential_count = Credential::find().all(&data_layer.db).await.unwrap().len();
        assert_eq!(1, credential_count);
        let credential_state_count = CredentialState::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len();
        assert_eq!(1, credential_state_count);
    }
}
