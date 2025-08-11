use std::sync::Arc;

use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::model::credential_schema::{
    BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema, CredentialSchemaClaim,
    CredentialSchemaRelations, CredentialSchemaType, GetCredentialSchemaQuery, LayoutProperties,
    LayoutType, LogoProperties, WalletStorageTypeEnum,
};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use shared_types::CredentialSchemaId;
use sql_data_provider::test_utilities::get_dummy_date;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Default, Clone)]
pub struct TestingCreateSchemaParams {
    pub id: Option<CredentialSchemaId>,
    pub schema_id: Option<String>,
    pub format: Option<String>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_type: Option<CredentialSchemaType>,
    pub allow_suspension: Option<bool>,
    pub imported_source_url: Option<String>,
    pub claim_schemas: Option<Vec<CredentialSchemaClaim>>,
    pub external_schema: bool,
    pub deleted_at: Option<OffsetDateTime>,
}

pub struct CredentialSchemasDB {
    repository: Arc<dyn CredentialSchemaRepository>,
}

impl CredentialSchemasDB {
    pub fn new(repository: Arc<dyn CredentialSchemaRepository>) -> Self {
        Self { repository }
    }

    pub async fn create_with_result(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
        params: TestingCreateSchemaParams,
    ) -> Result<CredentialSchema, DataLayerError> {
        let claim_schemas = params.claim_schemas.unwrap_or_else(|| {
            let claim_schema = ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "firstName".to_string(),
                data_type: "STRING".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            };
            let claim_schema1 = ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "isOver18".to_string(),
                data_type: "BOOLEAN".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            };
            vec![
                CredentialSchemaClaim {
                    schema: claim_schema,
                    required: true,
                },
                CredentialSchemaClaim {
                    schema: claim_schema1,
                    required: false,
                },
            ]
        });

        let id = params.id.unwrap_or(Uuid::new_v4().into());
        let credential_schema = CredentialSchema {
            id,
            imported_source_url: params.imported_source_url.unwrap_or("CORE_URL".to_string()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            wallet_storage_type: Some(
                params
                    .wallet_storage_type
                    .unwrap_or(WalletStorageTypeEnum::Software),
            ),
            organisation: Some(organisation.clone()),
            deleted_at: params.deleted_at,
            format: params.format.unwrap_or("JWT".to_string()),
            revocation_method: revocation_method.to_owned(),
            external_schema: params.external_schema,
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
            schema_type: params
                .schema_type
                .unwrap_or(CredentialSchemaType::ProcivisOneSchema2024),
            schema_id: params.schema_id.unwrap_or_else(|| id.to_string()),
            allow_suspension: params.allow_suspension.unwrap_or(true),
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await?;

        Ok(self.get(&id).await)
    }

    pub async fn create(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        self.create_with_result(name, organisation, revocation_method, params)
            .await
            .unwrap()
    }

    pub async fn create_special_chars(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let id = Uuid::new_v4();
        let claim_schema = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "first name#".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
        };
        let claim_schemas = vec![CredentialSchemaClaim {
            schema: claim_schema.to_owned(),
            required: true,
        }];

        let credential_schema = CredentialSchema {
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            external_schema: params.external_schema,
            wallet_storage_type: Some(
                params
                    .wallet_storage_type
                    .unwrap_or(WalletStorageTypeEnum::Software),
            ),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: params.format.unwrap_or("JSON_LD_BBSPLUS".to_string()),
            revocation_method: revocation_method.to_owned(),
            claim_schemas: Some(claim_schemas),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: params
                .schema_type
                .unwrap_or(CredentialSchemaType::ProcivisOneSchema2024),
            schema_id: id.to_string(),
            allow_suspension: true,
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_array_claims(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let claim_schema_root_namespace: ClaimSchema = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "namespace".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_root_field: ClaimSchema = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "namespace/root_field".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_root_array = ClaimSchema {
            array: true,
            id: Uuid::new_v4().into(),
            key: "namespace/root_array".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_nested = ClaimSchema {
            array: true,
            id: Uuid::new_v4().into(),
            key: "namespace/root_array/nested".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_field = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "namespace/root_array/nested/field".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schemas = vec![
            CredentialSchemaClaim {
                schema: claim_schema_root_namespace.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_root_field.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_root_array.to_owned(),
                required: false,
            },
            CredentialSchemaClaim {
                schema: claim_schema_nested.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_field.to_owned(),
                required: true,
            },
        ];

        let id = Uuid::new_v4();
        let credential_schema = CredentialSchema {
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
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
            external_schema: params.external_schema,
            claim_schemas: Some(claim_schemas),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: params
                .schema_type
                .unwrap_or(CredentialSchemaType::ProcivisOneSchema2024),
            schema_id: params.schema_id.unwrap_or("doctype".to_string()),
            allow_suspension: true,
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
            array: false,
            id: Uuid::new_v4().into(),
            key: "address".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_street = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/street".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates_x = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/x".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates_y = ClaimSchema {
            array: false,
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
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
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
            external_schema: params.external_schema,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: params
                .schema_type
                .unwrap_or(CredentialSchemaType::ProcivisOneSchema2024),
            schema_id: format!("ssi/schema/{id}"),
            allow_suspension: true,
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_nested_claims_and_root_field(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let claim_schema_name = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "name".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
        };
        let claim_schema_address = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_street = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/street".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates_x = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/x".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates_y = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/y".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schemas = vec![
            CredentialSchemaClaim {
                schema: claim_schema_name.to_owned(),
                required: true,
            },
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
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
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
            external_schema: params.external_schema,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: params
                .schema_type
                .unwrap_or(CredentialSchemaType::ProcivisOneSchema2024),
            schema_id: format!("ssi/schema/{id}"),
            allow_suspension: true,
        };

        let id = self
            .repository
            .create_credential_schema(credential_schema)
            .await
            .unwrap();

        self.get(&id).await
    }

    pub async fn create_with_nested_hell(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
        params: TestingCreateSchemaParams,
    ) -> CredentialSchema {
        let claim_schema_name = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "name".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
        };
        let claim_schema_string_array = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "string_array".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: true,
        };
        let claim_schema_object_array = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "object_array".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: true,
        };
        let claim_schema_object_array_field1 = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "object_array/field1".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
        };
        let claim_schema_object_array_field2 = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "object_array/field2".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
        };
        let claim_schema_address = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_street = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/street".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_nested_string_array = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "address/coordinates/string_array".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: true,
        };
        let claim_schema_nested_object_array = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "address/coordinates/object_array".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: true,
        };
        let claim_schema_nested_object_array_field1 = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "address/coordinates/object_array/field1".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
        };
        let claim_schema_nested_object_array_field2 = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "address/coordinates/object_array/field2".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
        };
        let claim_schema_address_coordinates_x = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/x".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schema_address_coordinates_y = ClaimSchema {
            array: false,
            id: Uuid::new_v4().into(),
            key: "address/coordinates/y".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };
        let claim_schemas = vec![
            CredentialSchemaClaim {
                schema: claim_schema_name.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_string_array.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_object_array.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_object_array_field1.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_object_array_field2.to_owned(),
                required: true,
            },
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
                schema: claim_schema_nested_string_array.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_nested_object_array.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_nested_object_array_field1.to_owned(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: claim_schema_nested_object_array_field2.to_owned(),
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
            id: id.into(),
            imported_source_url: "CORE_URL".to_string(),
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
            external_schema: params.external_schema,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: params
                .schema_type
                .unwrap_or(CredentialSchemaType::ProcivisOneSchema2024),
            schema_id: format!("ssi/schema/{id}"),
            allow_suspension: true,
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
            array: false,
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
            id: new_id.into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: name.to_owned(),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: "JWT".to_string(),
            external_schema: false,
            revocation_method: "NONE".to_owned(),
            claim_schemas: Some(claim_schemas),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: new_id.to_string(),
            allow_suspension: true,
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
        new_claim_schemas: &[(Uuid, &str, bool, &str, bool)],
        format: &str,
        schema_id: &str,
    ) -> CredentialSchema {
        let claim_schemas = new_claim_schemas
            .iter()
            .map(
                |(id, name, required, data_type, array)| CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: (*id).into(),
                        key: name.to_string(),
                        data_type: data_type.to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: *array,
                    },
                    required: *required,
                },
            )
            .collect();

        let schema_type = match format {
            "SD_JWT_VC" => CredentialSchemaType::SdJwtVc,
            "MDOC" => CredentialSchemaType::Mdoc,
            _ => CredentialSchemaType::ProcivisOneSchema2024,
        };
        let credential_schema = CredentialSchema {
            id: id.to_owned().into(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: name.to_owned(),
            organisation: Some(organisation.clone()),
            deleted_at: None,
            format: format.to_string(),
            revocation_method: revocation_method.to_owned(),
            external_schema: false,
            claim_schemas: Some(claim_schemas),
            layout_type: LayoutType::Card,
            layout_properties: Some(LayoutProperties {
                background: Some(BackgroundProperties {
                    color: Some("color".to_string()),
                    image: None,
                }),
                logo: None,
                primary_attribute: None,
                secondary_attribute: None,
                picture_attribute: None,
                code: None,
            }),
            schema_id: schema_id.to_owned(),
            schema_type,
            allow_suspension: true,
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

    pub async fn delete(&self, credential_schema: &CredentialSchema) {
        self.repository
            .delete_credential_schema(credential_schema)
            .await
            .unwrap();
    }

    pub async fn list(&self) -> Vec<CredentialSchema> {
        let response = self
            .repository
            .get_credential_schema_list(
                GetCredentialSchemaQuery {
                    pagination: None,
                    sorting: None,
                    filtering: None,
                    include: Some(vec![
                        CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
                    ]),
                },
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations {}),
                    organisation: Some(OrganisationRelations {}),
                },
            )
            .await
            .unwrap();
        response.values
    }
}
