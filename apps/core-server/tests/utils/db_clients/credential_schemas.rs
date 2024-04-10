use std::sync::Arc;

use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::model::credential_schema::{
    BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema, CredentialSchemaClaim,
    CredentialSchemaId, CredentialSchemaRelations, CredentialSchemaType, LayoutProperties,
    LayoutType, LogoProperties, WalletStorageTypeEnum,
};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

#[derive(Debug, Default, Clone)]
pub struct TestingCreateSchemaParams {
    pub format: Option<String>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
}

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
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let id = Uuid::new_v4();
        let claim_schema = ClaimSchema {
            id: Uuid::new_v4().into(),
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
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            wallet_storage_type: Some(
                params
                    .wallet_storage_type
                    .unwrap_or(WalletStorageTypeEnum::Software),
            ),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: params.format.unwrap_or("JWT".to_string()),
            revocation_method: revocation_method.to_owned(),
            claim_schemas: Some(claim_schemas),
            layout_type: LayoutType::Card,
            layout_properties: Some(LayoutProperties {
                primary_attribute: Some("firstName".to_owned()),
                secondary_attribute: Some("firstName".to_owned()),
                background: Some(BackgroundProperties {
                    color: Some("#DA2727".to_owned()),
                    image: None,
                }),
                logo: Some(LogoProperties {
                    font_color: Some("#DA2727".to_owned()),
                    background_color: Some("#DA2727".to_owned()),
                    image: None,
                }),
                picture_attribute: Some("firstName".to_owned()),
                code: Some(CodeProperties {
                    attribute: "firstName".to_owned(),
                    r#type: CodeTypeEnum::Barcode,
                }),
            }),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: id.to_string(),
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_nested_claims(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let claim_schema_address = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "address".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_street = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "address/street".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "address/coordinates".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates_x = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "address/coordinates/x".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates_y = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "address/coordinates/y".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schemas = vec![
            CredentialSchemaClaim {
                schema: claim_schema_address.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_address_street.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_address_coordinates.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_address_coordinates_x.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_address_coordinates_y.to_owned(),
                required: true,
            },
        ];

        let id = Uuid::new_v4();
        let credential_schema = CredentialSchema {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            wallet_storage_type: Some(
                params
                    .wallet_storage_type
                    .unwrap_or(WalletStorageTypeEnum::Software),
            ),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: params.format.unwrap_or("JWT".to_string()),
            revocation_method: revocation_method.to_owned(),
            claim_schemas: Some(claim_schemas),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: format!("ssi/schema/{id}"),
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema)
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
            id: Uuid::new_v4().into(),
            key: "firstName".to_string(),
            data_type: "PICTURE".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schemas = vec![CredentialSchemaClaim {
            schema: claim_schema.to_owned(),
            required: true,
        }];

        let new_id = Uuid::new_v4();
        let credential_schema = CredentialSchema {
            id: new_id.to_owned(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: name.to_owned(),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: "JWT".to_string(),
            revocation_method: "NONE".to_owned(),
            claim_schemas: Some(claim_schemas),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: new_id.to_string(),
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema.clone())
            .await
            .unwrap();

        self.get(&id).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_claims(
        &self,
        id: &Uuid,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
        new_claim_schemas: &[(Uuid, &str, bool, &str)],
        format: &str,
        schema_id: &str,
    ) -> CredentialSchema {
        let claim_schemas = new_claim_schemas
            .iter()
            .map(|(id, name, required, data_type)| CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: (*id).into(),
                    key: name.to_string(),
                    data_type: data_type.to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                },
                required: *required,
            })
            .collect();

        let credential_schema = CredentialSchema {
            id: id.to_owned(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: name.to_owned(),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: format.to_string(),
            revocation_method: revocation_method.to_owned(),
            claim_schemas: Some(claim_schemas),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: schema_id.to_owned(),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
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
