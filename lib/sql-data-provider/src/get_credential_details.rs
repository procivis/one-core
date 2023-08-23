use one_core::repository::{
    data_provider::{DetailCredentialResponse, ListCredentialSchemaResponse},
    error::DataLayerError,
};
use sea_orm::{DatabaseConnection, EntityTrait};

use crate::{
    common_queries::{fetch_claim_claim_schemas, get_credential_state},
    data_model::{convert_credential_state, detail_credential_claim_response_from_model},
    entity::{credential, credential_schema, Credential, CredentialSchema, Did},
    OldProvider,
};

async fn get_did_value(
    db: &DatabaseConnection,
    did_id: &str,
) -> Result<Option<String>, DataLayerError> {
    let did = Did::find_by_id(did_id)
        .one(db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;
    match did {
        None => Ok(None),
        Some(value) => Ok(Some(value.did)),
    }
}

impl OldProvider {
    pub async fn get_credential_details(
        &self,
        uuid: &str,
    ) -> Result<DetailCredentialResponse, DataLayerError> {
        let credential: credential::Model = Credential::find_by_id(uuid)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        let did = get_did_value(&self.db, &credential.issuer_did_id).await?;
        let credential_state = get_credential_state(&self.db, &credential.id).await?;

        let schema: credential_schema::Model =
            CredentialSchema::find_by_id(&credential.credential_schema_id)
                .one(&self.db)
                .await
                .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
                .ok_or(DataLayerError::RecordNotFound)?;

        let claims =
            fetch_claim_claim_schemas(&self.db, vec![credential.id.clone()].as_slice()).await?;

        Ok(DetailCredentialResponse {
            id: credential.id,
            created_date: credential.created_date,
            issuance_date: credential.issuance_date,
            state: convert_credential_state(credential_state),
            last_modified: credential.last_modified,
            schema: ListCredentialSchemaResponse {
                id: schema.id,
                created_date: schema.created_date,
                last_modified: schema.last_modified,
                name: schema.name,
                format: schema.format,
                revocation_method: schema.revocation_method,
                organisation_id: schema.organisation_id.to_owned(),
            },
            issuer_did: did,
            claims: claims
                .into_iter()
                .map(detail_credential_claim_response_from_model)
                .collect(),
            credential: credential.credential,
        })
    }
}

#[cfg(test)]
mod tests {
    use one_core::repository::data_provider::CredentialState;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::{
        common_queries::insert_credential_state, entity::credential_state, test_utilities::*,
    };

    #[tokio::test]
    async fn get_credential_details_test_simple() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let did_id = insert_did(&data_layer.db, "did name", "test123", &organisation_id)
            .await
            .unwrap();
        let credential_schema_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id, "test123")
                .await
                .unwrap();
        let claim_schemas: Vec<(Uuid, bool, u32, &str)> = (0..4)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i, "STRING"))
            .collect();
        insert_many_claims_schema_to_database(
            &data_layer.db,
            &credential_schema_id,
            &claim_schemas,
        )
        .await
        .unwrap();

        let non_existing_credential = data_layer
            .get_credential_details(&Uuid::new_v4().to_string())
            .await;
        assert!(non_existing_credential.is_err());

        let credential_id = insert_credential(&data_layer.db, &credential_schema_id, &did_id)
            .await
            .unwrap();

        let claim_values: Vec<(Uuid, String)> = claim_schemas
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, (claim_schema_id, _, _, _))| (claim_schema_id, format!("value-{i}")))
            .rev() // try to insert items in different order than the defined claim_schema order
            .collect();
        insert_many_credential_claims_to_database(&data_layer.db, &credential_id, &claim_values)
            .await
            .unwrap();

        let credential = data_layer.get_credential_details(&credential_id).await;
        assert!(credential.is_ok());
        let credential = credential.unwrap();
        assert_eq!(CredentialState::Created, credential.state);

        let now = OffsetDateTime::now_utc();
        insert_credential_state(
            &data_layer.db,
            &credential_id,
            now,
            credential_state::CredentialState::Offered,
        )
        .await
        .unwrap();

        let credential = data_layer.get_credential_details(&credential_id).await;
        assert!(credential.is_ok());
        let credential = credential.unwrap();
        assert_eq!(CredentialState::Offered, credential.state);

        // check that claims are sorted based on claim_schema order
        assert_eq!(4, credential.claims.len());
        for (n, (claim_schema_id, _, _, _)) in claim_schemas.iter().enumerate() {
            assert_eq!(claim_schema_id.to_string(), credential.claims[n].schema.id);
        }
    }
}
