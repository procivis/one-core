use mockall::predicate::*;
use shared_types::CredentialSchemaId;
use std::sync::Arc;
use std::vec;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::credential_schema::{CredentialSchemaType, LayoutType, WalletStorageTypeEnum};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::credential_formatter::{FormatterCapabilities, MockCredentialFormatter};
use crate::service::credential_schema::dto::{
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesRequestDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaFilterValue,
    CredentialSchemaLogoPropertiesRequestDTO,
};
use crate::service::test_utilities::generic_formatter_capabilities;
use crate::{
    config::{core_config::CoreConfig, ConfigValidationError},
    model::{
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential_schema::{
            CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations,
            GetCredentialSchemaList,
        },
        organisation::{Organisation, OrganisationRelations},
    },
    repository::{
        credential_schema_repository::MockCredentialSchemaRepository,
        history_repository::MockHistoryRepository,
        mock::organisation_repository::MockOrganisationRepository,
    },
    service::{
        credential_schema::{
            dto::{
                CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO,
                CredentialClaimSchemaRequestDTO, GetCredentialSchemaQueryDTO,
            },
            mapper::{renest_claim_schemas, unnest_claim_schemas},
            CredentialSchemaService,
        },
        error::{BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError},
        test_utilities::generic_config,
    },
};

use super::dto::CredentialSchemaLayoutPropertiesRequestDTO;
use super::validator::{
    check_background_properties, check_claims_presence_in_layout_properties, check_logo_properties,
};

fn setup_service(
    credential_schema_repository: MockCredentialSchemaRepository,
    history_repository: MockHistoryRepository,
    organisation_repository: MockOrganisationRepository,
    formatter_provider: MockCredentialFormatterProvider,
    config: CoreConfig,
) -> CredentialSchemaService {
    CredentialSchemaService::new(
        Some("http://127.0.0.1:4321".to_string()),
        Arc::new(credential_schema_repository),
        Arc::new(history_repository),
        Arc::new(organisation_repository),
        Arc::new(formatter_provider),
        Arc::new(config),
    )
}

fn generic_credential_schema() -> CredentialSchema {
    let now = OffsetDateTime::now_utc();
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        name: "".to_string(),
        format: "".to_string(),
        revocation_method: "".to_string(),
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "".to_string(),
                data_type: "".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        }]),
        organisation: Some(Organisation {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
        }),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    }
}

#[tokio::test]
async fn test_get_credential_schema_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let history_repository = MockHistoryRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        organisation: Some(OrganisationRelations::default()),
    };

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let result = service.get_credential_schema(&schema.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, schema.id);
}

#[tokio::test]
async fn test_get_credential_schema_deleted() {
    let mut repository = MockCredentialSchemaRepository::default();
    let history_repository = MockHistoryRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let schema = CredentialSchema {
        deleted_at: Some(OffsetDateTime::now_utc()),
        ..generic_credential_schema()
    };
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let result = service.get_credential_schema(&schema.id).await;

    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::EntityNotFound(EntityNotFoundError::CredentialSchema(_))
    )));
}

#[tokio::test]
async fn test_get_credential_schema_fail() {
    let mut repository = MockCredentialSchemaRepository::default();
    let history_repository = MockHistoryRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        organisation: Some(OrganisationRelations::default()),
    };

    let mut schema = generic_credential_schema();
    schema.organisation = None;
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let organisation_is_none = service.get_credential_schema(&schema.id).await;
    assert!(organisation_is_none.is_err_and(|e| matches!(e, ServiceError::MappingError(_))));
}

#[tokio::test]
async fn test_get_credential_schema_list_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let history_repository = MockHistoryRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 1,
        total_items: 3,
    };

    {
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_, _| Ok(clone.clone()));
    }

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let result = service
        .get_credential_schema_list(GetCredentialSchemaQueryDTO {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(Uuid::new_v4().into()).condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(3, result.total_items);
    assert_eq!(1, result.total_pages);
    assert_eq!(response.values[0].id, result.values[0].id);
    assert_eq!(response.values[1].id, result.values[1].id);
    assert_eq!(response.values[2].id, result.values[2].id);
}

#[tokio::test]
async fn test_delete_credential_schema() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut history_repository = MockHistoryRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let schema_id: CredentialSchemaId = Uuid::new_v4().into();

    repository
        .expect_get_credential_schema()
        .returning(|_, _| Ok(Some(generic_credential_schema())));

    repository
        .expect_delete_credential_schema()
        .times(1)
        .with(eq(schema_id))
        .returning(move |_| Ok(()));

    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let result = service.delete_credential_schema(&schema_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_schema_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut history_repository = MockHistoryRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    history_repository
        .expect_create_history()
        .times(1)
        .returning(|history| Ok(history.id));

    let now = OffsetDateTime::now_utc();
    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
    };
    let schema_id: CredentialSchemaId = Uuid::new_v4().into();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 0,
        total_items: 0,
    };

    {
        let organisation = organisation.clone();
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .with(
                eq(organisation.id.to_owned()),
                eq(OrganisationRelations::default()),
            )
            .returning(move |_, _| Ok(Some(organisation.clone())));
        repository
            .expect_create_credential_schema()
            .times(1)
            .returning(move |request| {
                assert_eq!(
                    CredentialSchemaType::ProcivisOneSchema2024,
                    request.schema_type
                );
                Ok(schema_id)
            });
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_, _| Ok(clone.clone()));
    }

    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            revocation_methods: vec!["NONE".to_string()],
            ..Default::default()
        });
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;
    assert!(result.is_ok());
    assert_eq!(schema_id, result.unwrap());
}

#[tokio::test]
async fn test_create_credential_schema_success_mdoc_with_custom_schema_id() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut history_repository = MockHistoryRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    history_repository
        .expect_create_history()
        .times(1)
        .returning(|history| Ok(history.id));

    let now = OffsetDateTime::now_utc();
    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
    };
    let schema_id: CredentialSchemaId = Uuid::new_v4().into();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 0,
        total_items: 0,
    };

    let custom_schema_id = "custom_schema_id";
    {
        let organisation = organisation.clone();
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .with(
                eq(organisation.id.to_owned()),
                eq(OrganisationRelations::default()),
            )
            .returning(move |_, _| Ok(Some(organisation.clone())));
        repository
            .expect_create_credential_schema()
            .times(1)
            .returning(move |request| {
                assert_eq!(custom_schema_id, request.schema_id);
                assert_eq!(CredentialSchemaType::Mdoc, request.schema_type);
                Ok(schema_id.to_owned())
            });
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_, _| Ok(clone.clone()));
    }

    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            revocation_methods: vec!["NONE".to_string()],
            ..Default::default()
        });
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "MDOC".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![CredentialClaimSchemaRequestDTO {
                    key: "X".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    claims: vec![],
                }],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: Some(custom_schema_id.to_string()),
        })
        .await
        .unwrap();
    assert_eq!(schema_id, result);
}

#[tokio::test]
async fn test_create_credential_schema_success_nested_claims() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut history_repository = MockHistoryRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    history_repository
        .expect_create_history()
        .times(1)
        .returning(|history| Ok(history.id));

    let now = OffsetDateTime::now_utc();
    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
    };
    let schema_id = Uuid::new_v4();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 0,
        total_items: 0,
    };

    {
        let organisation = organisation.clone();
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .with(
                eq(organisation.id.to_owned()),
                eq(OrganisationRelations::default()),
            )
            .returning(move |_, _| Ok(Some(organisation.clone())));
        repository
            .expect_create_credential_schema()
            .times(1)
            .returning(move |_| Ok(schema_id.into()));
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_, _| Ok(clone.clone()));
    }

    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            revocation_methods: vec!["NONE".to_string()],
            ..Default::default()
        });
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                ],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await
        .unwrap();
    assert_eq!(schema_id, result.into());
}

#[tokio::test]
async fn test_create_credential_schema_failed_slash_in_claim_name() {
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location/x".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::Validation(ValidationError::CredentialSchemaClaimSchemaSlashInKeyName(
            _
        ))
    ));
}

#[tokio::test]
async fn test_create_credential_schema_failed_nested_claims_not_in_object_type() {
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                ],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::Validation(ValidationError::CredentialSchemaNestedClaimsShouldBeEmpty(
            _
        ))
    ));
}

#[tokio::test]
async fn test_create_credential_schema_failed_nested_claims_object_type_has_empty_claims() {
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::Validation(ValidationError::CredentialSchemaMissingNestedClaims(_))
    ));
}

#[tokio::test]
async fn test_create_credential_schema_failed_nested_claim_fails_validation() {
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![CredentialClaimSchemaRequestDTO {
                    key: "x".to_string(),
                    datatype: "NON_EXISTING_TYPE".to_string(),
                    required: true,
                    claims: vec![],
                }],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::ConfigValidationError(ConfigValidationError::KeyNotFound(_))
    ));
}

#[tokio::test]
async fn test_create_credential_schema_unique_name_error() {
    let mut repository = MockCredentialSchemaRepository::default();
    let history_repository = MockHistoryRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let now = OffsetDateTime::now_utc();
    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
    };

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 1,
        total_items: 1,
    };

    {
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_, _| Ok(response.clone()));
    }

    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            revocation_methods: vec!["NONE".to_string()],
            ..Default::default()
        });
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(
        repository,
        history_repository,
        MockOrganisationRepository::default(),
        formatter_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::CredentialSchemaAlreadyExists)
    )));
}

#[tokio::test]
async fn test_create_credential_schema_failed_unique_claims_error() {
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: None,
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![
                CredentialClaimSchemaRequestDTO {
                    key: "sameRoot".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    claims: vec![],
                },
                CredentialClaimSchemaRequestDTO {
                    key: "sameRoot".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    claims: vec![],
                },
            ],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::Validation(ValidationError::CredentialSchemaDuplicitClaim)
    ));

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: None,
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "parent".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "sameNested".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "sameNested".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                ],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::Validation(ValidationError::CredentialSchemaDuplicitClaim)
    ));
}

#[tokio::test]
async fn test_create_credential_schema_fail_validation() {
    let repository = MockCredentialSchemaRepository::default();
    let history_repository = MockHistoryRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        MockCredentialFormatterProvider::default(),
        generic_config().core,
    );

    let non_existing_format = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "NON_EXISTING_FORMAT".to_string(),
            revocation_method: "NONE".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;
    assert!(non_existing_format.is_err_and(|e| matches!(e, ServiceError::ConfigValidationError(_))));

    let non_existing_revocation_method = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            revocation_method: "TEST".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;
    assert!(non_existing_revocation_method
        .is_err_and(|e| matches!(e, ServiceError::ConfigValidationError(_))));

    let wrong_datatype = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "BLABLA".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;
    assert!(wrong_datatype.is_err_and(|e| matches!(e, ServiceError::ConfigValidationError(_))));

    let no_claims = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;
    assert!(no_claims.is_err_and(|e| matches!(
        e,
        ServiceError::Validation(ValidationError::CredentialSchemaMissingClaims)
    )));
}

#[tokio::test]
async fn test_create_credential_schema_fail_missing_organisation() {
    let mut repository = MockCredentialSchemaRepository::default();
    let history_repository = MockHistoryRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 0,
        total_items: 0,
    };

    {
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .returning(move |_, _| Ok(None));
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_, _| Ok(clone.clone()));
    }

    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            revocation_methods: vec!["NONE".to_string()],
            ..Default::default()
        });
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;

    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::MissingOrganisation(_))
    )));
}

#[tokio::test]
async fn test_create_credential_schema_fail_incompatible_revocation_and_format() {
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    formatter
        .expect_get_capabilities()
        .once()
        .return_once(FormatterCapabilities::default);
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::BusinessLogic(
            BusinessLogicError::RevocationMethodNotCompatibleWithSelectedFormat
        )
    ));
}

#[tokio::test]
async fn test_create_credential_schema_failed_mdoc_not_all_top_claims_are_object() {
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "MDOC".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![
                CredentialClaimSchemaRequestDTO {
                    key: "test".to_string(),
                    datatype: "OBJECT".to_string(),
                    required: true,
                    claims: vec![CredentialClaimSchemaRequestDTO {
                        key: "nested".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    }],
                },
                CredentialClaimSchemaRequestDTO {
                    key: "test2".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    claims: vec![],
                },
            ],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::BusinessLogic(
            BusinessLogicError::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed
        )
    ));
}

#[tokio::test]
async fn test_create_credential_schema_failed_claim_schema_key_too_long() {
    let service = setup_service(
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        generic_config().core,
    );

    let str_of_len_256 = "a".repeat(256);
    let str_of_len_128 = "a".repeat(128);
    let unicode_str_of_len_130_but_byte_len_of_260 = "é".repeat(130);

    let first_level_fail = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: str_of_len_256,
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;
    assert!(matches!(
        first_level_fail,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::ClaimSchemaKeyTooLong
        ))
    ));

    let nested_fail = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: str_of_len_128.to_owned(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![CredentialClaimSchemaRequestDTO {
                    key: str_of_len_128,
                    datatype: "STRING".to_string(),
                    required: true,
                    claims: vec![],
                }],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;
    assert!(matches!(
        nested_fail,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::ClaimSchemaKeyTooLong
        ))
    ));

    let unicode_len_fail = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: unicode_str_of_len_130_but_byte_len_of_260,
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
        })
        .await;
    assert!(matches!(
        unicode_len_fail,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::ClaimSchemaKeyTooLong
        ))
    ));
}

#[tokio::test]
async fn test_unnest_claim_schemas_from_request_no_nested_claims() {
    let request = vec![CredentialClaimSchemaRequestDTO {
        key: "test".to_string(),
        datatype: "STRING".to_string(),
        required: true,
        claims: vec![],
    }];

    let expected = vec![CredentialClaimSchemaRequestDTO {
        key: "test".to_string(),
        datatype: "STRING".to_string(),
        required: true,
        claims: vec![],
    }];

    assert_eq!(expected, unnest_claim_schemas(request));
}

#[tokio::test]
async fn test_unnest_claim_schemas_from_request_single_layer_of_nested_claims() {
    let request = vec![CredentialClaimSchemaRequestDTO {
        key: "location".to_string(),
        datatype: "OBJECT".to_string(),
        required: true,
        claims: vec![
            CredentialClaimSchemaRequestDTO {
                key: "x".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            },
            CredentialClaimSchemaRequestDTO {
                key: "y".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            },
        ],
    }];

    let expected = vec![
        CredentialClaimSchemaRequestDTO {
            key: "location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
    ];

    assert_eq!(expected, unnest_claim_schemas(request));
}

#[tokio::test]
async fn test_unnest_claim_schemas_from_request_multiple_layers_of_nested_claims() {
    let request = vec![CredentialClaimSchemaRequestDTO {
        key: "address".to_string(),
        datatype: "OBJECT".to_string(),
        required: true,
        claims: vec![
            CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                ],
            },
            CredentialClaimSchemaRequestDTO {
                key: "postal_data".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "code".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "street".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                ],
            },
        ],
    }];

    let expected = vec![
        CredentialClaimSchemaRequestDTO {
            key: "address".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/postal_data".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/postal_data/code".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/postal_data/street".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
    ];

    assert_eq!(expected, unnest_claim_schemas(request));
}

#[test]
fn test_renest_claim_schemas_single_layer_of_nested_claims() {
    let now = OffsetDateTime::now_utc();

    let uuid_location = Uuid::new_v4().into();
    let uuid_location_x = Uuid::new_v4().into();
    let uuid_location_y = Uuid::new_v4().into();

    let request = vec![
        CredentialClaimSchemaDTO {
            id: uuid_location,
            created_date: now,
            last_modified: now,
            key: "location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_location_x,
            created_date: now,
            last_modified: now,
            key: "location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_location_y,
            created_date: now,
            last_modified: now,
            key: "location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
    ];

    let expected = vec![CredentialClaimSchemaDTO {
        id: uuid_location,
        created_date: now,
        last_modified: now,
        key: "location".to_string(),
        datatype: "OBJECT".to_string(),
        required: true,
        claims: vec![
            CredentialClaimSchemaDTO {
                id: uuid_location_x,
                created_date: now,
                last_modified: now,
                key: "x".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            },
            CredentialClaimSchemaDTO {
                id: uuid_location_y,
                created_date: now,
                last_modified: now,
                key: "y".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            },
        ],
    }];

    assert_eq!(expected, renest_claim_schemas(request).unwrap());
}

#[test]
fn test_renest_claim_schemas_multiple_layers_of_nested_claims() {
    let now = OffsetDateTime::now_utc();

    let uuid_address = Uuid::new_v4().into();
    let uuid_address_location = Uuid::new_v4().into();
    let uuid_address_location_x = Uuid::new_v4().into();
    let uuid_address_location_y = Uuid::new_v4().into();
    let uuid_address_postal_data = Uuid::new_v4().into();
    let uuid_address_postal_data_street = Uuid::new_v4().into();
    let uuid_address_postal_data_code = Uuid::new_v4().into();

    let request = vec![
        CredentialClaimSchemaDTO {
            id: uuid_address,
            created_date: now,
            last_modified: now,
            key: "address".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_location,
            created_date: now,
            last_modified: now,
            key: "address/location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_postal_data,
            created_date: now,
            last_modified: now,
            key: "address/postal_data".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_location_x,
            created_date: now,
            last_modified: now,
            key: "address/location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_location_y,
            created_date: now,
            last_modified: now,
            key: "address/location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_postal_data_street,
            created_date: now,
            last_modified: now,
            key: "address/postal_data/street".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_postal_data_code,
            created_date: now,
            last_modified: now,
            key: "address/postal_data/code".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
        },
    ];

    let expected = vec![CredentialClaimSchemaDTO {
        id: uuid_address,
        created_date: now,
        last_modified: now,
        key: "address".to_string(),
        datatype: "OBJECT".to_string(),
        required: true,
        claims: vec![
            CredentialClaimSchemaDTO {
                id: uuid_address_location,
                created_date: now,
                last_modified: now,
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![
                    CredentialClaimSchemaDTO {
                        id: uuid_address_location_x,
                        created_date: now,
                        last_modified: now,
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaDTO {
                        id: uuid_address_location_y,
                        created_date: now,
                        last_modified: now,
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                ],
            },
            CredentialClaimSchemaDTO {
                id: uuid_address_postal_data,
                created_date: now,
                last_modified: now,
                key: "postal_data".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![
                    CredentialClaimSchemaDTO {
                        id: uuid_address_postal_data_street,
                        created_date: now,
                        last_modified: now,
                        key: "street".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaDTO {
                        id: uuid_address_postal_data_code,
                        created_date: now,
                        last_modified: now,
                        key: "code".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                ],
            },
        ],
    }];

    assert_eq!(expected, renest_claim_schemas(request).unwrap());
}

#[test]
fn test_renest_claim_schemas_failed_missing_parent_claim_schema() {
    let now = OffsetDateTime::now_utc();

    let uuid_location_x = Uuid::new_v4().into();

    let request = vec![CredentialClaimSchemaDTO {
        id: uuid_location_x,
        created_date: now,
        last_modified: now,
        key: "location/x".to_string(),
        datatype: "STRING".to_string(),
        required: true,
        claims: vec![],
    }];
    assert!(matches!(
        renest_claim_schemas(request),
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::MissingParentClaimSchema { .. }
        ))
    ));
}

#[test]
fn test_claims_presence_in_layout_properties_validation_ok() {
    let claims = vec![
        CredentialClaimSchemaRequestDTO {
            key: "claim1".to_owned(),
            datatype: "STRING".to_owned(),
            required: true,
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "claim2".to_owned(),
            datatype: "STRING".to_owned(),
            required: true,
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "claim21".to_owned(),
                datatype: "STRING".to_owned(),
                required: true,
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "claim211".to_owned(),
                        datatype: "STRING".to_owned(),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "claim212".to_owned(),
                        datatype: "STRING".to_owned(),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "claim213".to_owned(),
                        datatype: "STRING".to_owned(),
                        required: true,
                        claims: vec![],
                    },
                ],
            }],
        },
    ];
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: None,
        picture_attribute: Some("claim2/claim21/claim213".to_owned()),
        code: Some(CredentialSchemaCodePropertiesRequestDTO {
            attribute: "claim2/claim21/claim212".to_owned(),
            r#type: CredentialSchemaCodeTypeEnum::Barcode,
        }),
        primary_attribute: Some("claim1".to_owned()),
        secondary_attribute: Some("claim2/claim21/claim211".to_owned()),
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims,
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(let Ok(()) = check_claims_presence_in_layout_properties(&request))
}

#[test]
fn test_claims_presence_in_layout_properties_validation_missing_primary_attribute() {
    let claims = vec![CredentialClaimSchemaRequestDTO {
        key: "claim2".to_owned(),
        datatype: "STRING".to_owned(),
        required: true,
        claims: vec![CredentialClaimSchemaRequestDTO {
            key: "claim21".to_owned(),
            datatype: "STRING".to_owned(),
            required: true,
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "claim211".to_owned(),
                datatype: "STRING".to_owned(),
                required: true,
                claims: vec![],
            }],
        }],
    }];
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: None,
        picture_attribute: None,
        code: None,
        primary_attribute: Some("claim1".to_owned()),
        secondary_attribute: Some("claim2/claim21/claim211".to_owned()),
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims,
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Err(ServiceError::Validation(ValidationError::MissingLayoutAttribute(_))) = check_claims_presence_in_layout_properties(&request)
    )
}

#[test]
fn test_background_attributes_combination_failed_both() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: Some(CredentialSchemaBackgroundPropertiesRequestDTO {
            color: Some("Color".to_owned()),
            image: Some("Image".to_owned()),
        }),
        logo: None,
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Err(ServiceError::Validation(ValidationError::AttributeCombinationNotAllowed)) = check_background_properties(&request)
    )
}

#[test]
fn test_background_attributes_combination_failed_none() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: Some(CredentialSchemaBackgroundPropertiesRequestDTO {
            color: None,
            image: None,
        }),
        logo: None,
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Err(ServiceError::Validation(ValidationError::AttributeCombinationNotAllowed)) = check_background_properties(&request)
    )
}

#[test]
fn test_background_attributes_combination_ok_image() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: Some(CredentialSchemaBackgroundPropertiesRequestDTO {
            color: None,
            image: Some("Image".to_owned()),
        }),
        logo: None,
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Ok(()) = check_background_properties(&request)
    )
}

#[test]
fn test_background_attributes_combination_ok_color() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: Some(CredentialSchemaBackgroundPropertiesRequestDTO {
            color: Some("Color".to_owned()),
            image: None,
        }),
        logo: None,
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Ok(()) = check_background_properties(&request)
    )
}

#[test]
fn test_logo_attributes_combination_ok_background_plus_font() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: Some(CredentialSchemaLogoPropertiesRequestDTO {
            font_color: Some("Color".to_owned()),
            background_color: Some("Color".to_owned()),
            image: None,
        }),
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Ok(()) = check_logo_properties(&request)
    )
}

#[test]
fn test_logo_attributes_combination_ok_image() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: Some(CredentialSchemaLogoPropertiesRequestDTO {
            font_color: None,
            background_color: None,
            image: Some("Image".to_owned()),
        }),
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Ok(()) = check_logo_properties(&request)
    )
}

#[test]
fn test_logo_attributes_combination_mix1_fail() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: Some(CredentialSchemaLogoPropertiesRequestDTO {
            font_color: None,
            background_color: Some("Color".to_owned()),
            image: Some("Image".to_owned()),
        }),
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Err(ServiceError::Validation(ValidationError::AttributeCombinationNotAllowed)) = check_logo_properties(&request)
    )
}

#[test]
fn test_logo_attributes_combination_mix2_fail() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: Some(CredentialSchemaLogoPropertiesRequestDTO {
            font_color: Some("Color".to_owned()),
            background_color: None,
            image: Some("Image".to_owned()),
        }),
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Err(ServiceError::Validation(ValidationError::AttributeCombinationNotAllowed)) = check_logo_properties(&request)
    )
}

#[test]
fn test_logo_attributes_combination_mix3_fail() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: Some(CredentialSchemaLogoPropertiesRequestDTO {
            font_color: Some("Color".to_owned()),
            background_color: None,
            image: None,
        }),
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Err(ServiceError::Validation(ValidationError::AttributeCombinationNotAllowed)) = check_logo_properties(&request)
    )
}

#[test]
fn test_logo_attributes_combination_empty_fail() {
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: Some(CredentialSchemaLogoPropertiesRequestDTO {
            font_color: None,
            background_color: None,
            image: None,
        }),
        picture_attribute: None,
        code: None,
        primary_attribute: None,
        secondary_attribute: None,
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims: Vec::new(),
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Err(ServiceError::Validation(ValidationError::AttributeCombinationNotAllowed)) = check_logo_properties(&request)
    )
}

#[test]
fn test_claims_presence_in_layout_properties_validation_missing_secondary_attribute() {
    let claims = vec![CredentialClaimSchemaRequestDTO {
        key: "claim1".to_owned(),
        datatype: "STRING".to_owned(),
        required: true,
        claims: vec![],
    }];
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: None,
        picture_attribute: None,
        code: None,
        primary_attribute: Some("claim1".to_owned()),
        secondary_attribute: Some("other-claim".to_owned()),
    });

    let request = CreateCredentialSchemaRequestDTO {
        claims,
        layout_properties,
        ..dummy_request()
    };

    assert2::assert!(
        let Err(ServiceError::Validation(ValidationError::MissingLayoutAttribute(_))) = check_claims_presence_in_layout_properties(&request)
    )
}

#[test]
fn test_claims_presence_in_layout_properties_validation_attributes_not_specified() {
    let claims = vec![CredentialClaimSchemaRequestDTO {
        key: "claim1".to_owned(),
        datatype: "STRING".to_owned(),
        required: true,
        claims: vec![],
    }];

    let request = CreateCredentialSchemaRequestDTO {
        claims,
        layout_properties: None,
        ..dummy_request()
    };

    assert2::assert!(let Ok(()) = check_claims_presence_in_layout_properties(&request))
}

fn dummy_request() -> CreateCredentialSchemaRequestDTO {
    CreateCredentialSchemaRequestDTO {
        name: "AnyName".to_owned(),
        format: "AnyFormat".to_owned(),
        revocation_method: "None".to_owned(),
        organisation_id: Uuid::new_v4().into(),
        claims: vec![],
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: None,
    }
}
