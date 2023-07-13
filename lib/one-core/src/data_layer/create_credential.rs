use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait};
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};
use uuid::Uuid;

use crate::data_layer::entities::credential_state;
use crate::data_layer::{
    common_queries::{fetch_credential_schema_claim_schemas, insert_credential_state},
    data_model::{CreateCredentialRequest, CredentialSchemaClaimSchemaCombined, EntityResponse},
    entities::{claim, claim_schema::Datatype, credential, CredentialSchema, Did},
    DataLayer, DataLayerError,
};

fn is_valid_data(value: &str, datatype: Datatype) -> bool {
    match datatype {
        Datatype::String => true,
        Datatype::Date => {
            let format =
                format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
            PrimitiveDateTime::parse(value, &format).is_ok()
        }
        Datatype::Number => value.parse::<f64>().is_ok(),
    }
}

fn get_datatype(
    claim_schema_id: &str,
    schemas_combined: &[CredentialSchemaClaimSchemaCombined],
) -> Result<Datatype, DataLayerError> {
    match schemas_combined.iter().find(|f| f.id == claim_schema_id) {
        None => Err(DataLayerError::RecordNotFound),
        Some(value) => Ok(value.datatype.to_owned()),
    }
}

impl DataLayer {
    pub async fn create_credential(
        &self,
        request: CreateCredentialRequest,
    ) -> Result<EntityResponse, DataLayerError> {
        let did = Did::find_by_id(request.issuer_did.to_string())
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

            if !is_valid_data(&request_claim.value, datatype) {
                return Err(DataLayerError::IncorrectParameters);
            }
        }

        let now = OffsetDateTime::now_utc();

        let credential = credential::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            credential_schema_id: Set(request.credential_schema_id.to_string()),
            created_date: Set(now),
            last_modified: Set(now),
            issuance_date: Set(now),
            deleted_at: Set(None),
            transport: Set(request.transport.into()),
            credential: Set(vec![0, 0, 0, 0]),
            did_id: Set(Some(did.id)),
        }
        .insert(&self.db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let claim_models: Vec<claim::ActiveModel> = request
            .claim_values
            .into_iter()
            .map(|request_claim| claim::ActiveModel {
                claim_schema_id: Set(request_claim.claim_id.to_string()),
                credential_id: Set(credential.id.clone()),
                value: Set(request_claim.value),
                created_date: Set(now),
                last_modified: Set(now),
            })
            .collect();

        claim::Entity::insert_many(claim_models)
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

        let new_claims: Vec<(Uuid, bool, u32, Datatype)> = (0..4)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i, Datatype::String))
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
            .create_credential(CreateCredentialRequest {
                credential_schema_id: credential_schema_id.parse().unwrap(),
                issuer_did: did.parse().unwrap(),
                transport: Transport::ProcivisTemporary,
                claim_values: vec![CreateCredentialRequestClaim {
                    claim_id: new_claims[0].0,
                    value: "placeholder".to_string(),
                }],
            })
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

        let new_claims: Vec<(Uuid, bool, u32, Datatype)> = vec![
            (Uuid::new_v4(), false, 0, Datatype::Number),
            (Uuid::new_v4(), true, 1, Datatype::Date),
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
            .create_credential(CreateCredentialRequest {
                credential_schema_id: credential_schema_id.parse().unwrap(),
                issuer_did: did.parse().unwrap(),
                transport: Transport::ProcivisTemporary,
                claim_values: vec![CreateCredentialRequestClaim {
                    claim_id: new_claims[0].0,
                    value: "this is not a number".to_string(),
                }],
            })
            .await;
        assert!(failed_to_verify_number.is_err_and(|e| e == DataLayerError::IncorrectParameters));

        let failed_to_verify_date = data_layer
            .create_credential(CreateCredentialRequest {
                credential_schema_id: credential_schema_id.parse().unwrap(),
                issuer_did: did.parse().unwrap(),
                transport: Transport::ProcivisTemporary,
                claim_values: vec![CreateCredentialRequestClaim {
                    claim_id: new_claims[1].0,
                    value: "this is not a date".to_string(),
                }],
            })
            .await;
        assert!(failed_to_verify_date.is_err_and(|e| e == DataLayerError::IncorrectParameters));

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
            .create_credential(CreateCredentialRequest {
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
            })
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
