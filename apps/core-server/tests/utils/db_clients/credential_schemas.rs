use std::sync::Arc;

use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaId, CredentialSchemaRelations,
    WalletStorageTypeEnum,
};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct CredentialSchemasDB {
    repository: Arc<dyn CredentialSchemaRepository>,
}

impl CredentialSchemasDB {
    pub fn new(repository: Arc<dyn CredentialSchemaRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
    ) -> CredentialSchema {
        let claim_schema = ClaimSchema {
            id: Uuid::new_v4(),
            key: "firstName".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schemas = vec![CredentialSchemaClaim {
            schema: claim_schema.to_owned(),
            required: true,
        }];

        let credential_schema = CredentialSchema {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: "JWT".to_string(),
            revocation_method: revocation_method.to_owned(),
            claim_schemas: Some(claim_schemas),
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema.clone())
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_picture_claim(
        &self,
        name: &str,
        organisation: &Organisation,
    ) -> CredentialSchema {
        let claim_schema = ClaimSchema {
            id: Uuid::new_v4(),
            key: "firstName".to_string(),
            data_type: "PICTURE".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schemas = vec![CredentialSchemaClaim {
            schema: claim_schema.to_owned(),
            required: true,
        }];

        let credential_schema = CredentialSchema {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: name.to_owned(),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: "JWT".to_string(),
            revocation_method: "NONE".to_owned(),
            claim_schemas: Some(claim_schemas),
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema.clone())
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_claims(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
        new_claim_schemas: &[(Uuid, &str, bool, &str)],
        format: &str,
    ) -> CredentialSchema {
        let claim_schemas = new_claim_schemas
            .iter()
            .map(|(id, name, required, data_type)| CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: id.to_owned(),
                    key: name.to_string(),
                    data_type: data_type.to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                },
                required: *required,
            })
            .collect();

        let credential_schema = CredentialSchema {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: name.to_owned(),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: format.to_string(),
            revocation_method: revocation_method.to_owned(),
            claim_schemas: Some(claim_schemas),
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema.clone())
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn get(&self, credential_schema_id: &CredentialSchemaId) -> CredentialSchema {
        self.repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn delete(&self, id: &CredentialSchemaId) {
        self.repository.delete_credential_schema(id).await.unwrap();
    }
}
