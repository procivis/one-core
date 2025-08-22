use std::sync::Arc;
use std::vec;

use assert2::let_assert;
use mockall::predicate::*;
use shared_types::CredentialSchemaId;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::CredentialSchemaLayoutPropertiesRequestDTO;
use super::validator::{
    check_background_properties, check_claims_presence_in_layout_properties, check_logo_properties,
};
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, RevocationType};
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, CredentialSchemaType,
    GetCredentialSchemaList, LayoutType, WalletStorageTypeEnum,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::OrganisationRelations;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{Features, FormatterCapabilities};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::{Operation, RevocationMethodCapabilities};
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::credential_schema::CredentialSchemaService;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaFilterValue,
    CredentialSchemaLogoPropertiesRequestDTO, GetCredentialSchemaQueryDTO,
    ImportCredentialSchemaClaimSchemaDTO, ImportCredentialSchemaRequestDTO,
    ImportCredentialSchemaRequestSchemaDTO,
};
use crate::service::credential_schema::mapper::{renest_claim_schemas, unnest_claim_schemas};
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::test_utilities::{
    dummy_organisation, generic_config, generic_formatter_capabilities,
};

fn setup_service(
    credential_schema_repository: MockCredentialSchemaRepository,
    history_repository: MockHistoryRepository,
    organisation_repository: MockOrganisationRepository,
    formatter_provider: MockCredentialFormatterProvider,
    revocation_method_provider: MockRevocationMethodProvider,
    config: CoreConfig,
) -> CredentialSchemaService {
    CredentialSchemaService::new(
        Some("http://127.0.0.1:4321".to_string()),
        Arc::new(credential_schema_repository),
        Arc::new(history_repository),
        Arc::new(organisation_repository),
        Arc::new(formatter_provider),
        Arc::new(revocation_method_provider),
        Arc::new(config),
    )
}

fn generic_credential_schema() -> CredentialSchema {
    let now = OffsetDateTime::now_utc();
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: now,
        last_modified: now,
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        name: "".to_string(),
        format: "".to_string(),
        revocation_method: "".to_string(),
        external_schema: false,
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "".to_string(),
                data_type: "".to_string(),
                created_date: now,
                last_modified: now,
                array: false,
                metadata: false,
            },
            required: true,
        }]),
        organisation: Some(dummy_organisation(None)),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
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
        MockRevocationMethodProvider::default(),
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
        MockRevocationMethodProvider::default(),
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
        MockRevocationMethodProvider::default(),
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
        MockRevocationMethodProvider::default(),
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

    let credential_schema = generic_credential_schema();
    let schema_id: CredentialSchemaId = credential_schema.id;

    repository
        .expect_get_credential_schema()
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    repository
        .expect_delete_credential_schema()
        .times(1)
        .withf(move |schema| schema.id == schema_id)
        .returning(move |_| Ok(()));

    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        MockCredentialFormatterProvider::default(),
        MockRevocationMethodProvider::default(),
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

    let organisation = dummy_organisation(None);
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
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _| Ok("schema id".to_string()));
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: organisation.id.to_owned(),
            external_schema: false,
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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

    let organisation = dummy_organisation(None);
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
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            features: vec![Features::SelectiveDisclosure, Features::RequiresSchemaId],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..Default::default()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _| Ok(custom_schema_id.to_string()));
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "MDOC".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: organisation.id.to_owned(),
            external_schema: false,
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "OBJECT".to_string(),
                array: Some(false),
                required: true,
                claims: vec![CredentialClaimSchemaRequestDTO {
                    key: "X".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: Some(false),
                    claims: vec![],
                }],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: Some(custom_schema_id.to_string()),
            allow_suspension: Some(true),
        })
        .await
        .unwrap();
    assert_eq!(schema_id, result);
}

#[tokio::test]
async fn test_create_credential_schema_success_sdjwtvc_external() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut history_repository = MockHistoryRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    let mut revocation_method = MockRevocationMethod::default();

    const VCT: &str = "example.vct.test:1";

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            features: [Features::RequiresSchemaId].into(),
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });

    formatter
        .expect_credential_schema_id()
        .withf(|_, request, _| {
            assert!(request.external_schema);
            assert_eq!(request.schema_id, Some(VCT.to_string()));
            true
        })
        .returning(|_, _, _| Ok(VCT.to_string()));

    formatter_provider
        .expect_get_credential_formatter()
        .with(eq("SD_JWT_VC"))
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities { operations: vec![] });

    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq("NONE"))
        .once()
        .return_once(|_| Some(Arc::new(revocation_method)));

    history_repository
        .expect_create_history()
        .times(1)
        .returning(|history| Ok(history.id));

    repository
        .expect_create_credential_schema()
        .times(1)
        .returning(move |request| {
            assert_eq!(CredentialSchemaType::SdJwtVc, request.schema_type);
            Ok(Uuid::new_v4().into())
        });

    repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_, _| {
            Ok(GetCredentialSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    let organisation = dummy_organisation(None);

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
    }

    let service: CredentialSchemaService = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "external credential".to_string(),
            format: "SD_JWT_VC".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            external_schema: true,
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "claim".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: Some(VCT.to_string()),
            allow_suspension: Some(false),
        })
        .await
        .unwrap();
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

    let organisation = dummy_organisation(None);
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
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..Default::default()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _| Ok("some schema id".to_string()));
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            external_schema: false,
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                array: Some(false),
                required: true,
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                    },
                ],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
        })
        .await
        .unwrap();
    assert_eq!(schema_id, result.into());
}

#[tokio::test]
async fn test_create_credential_schema_failed_slash_in_claim_name() {
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(MockCredentialFormatter::default())));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location/x".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(MockCredentialFormatter::default())));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            external_schema: false,
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                    },
                ],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(MockCredentialFormatter::default())));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..Default::default()
        });

    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                array: Some(false),
                claims: vec![CredentialClaimSchemaRequestDTO {
                    key: "x".to_string(),
                    datatype: "NON_EXISTING_TYPE".to_string(),
                    required: true,
                    array: Some(false),
                    claims: vec![],
                }],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::ConfigValidationError(ConfigValidationError::EntryNotFound(_))
    ));
}

#[tokio::test]
async fn test_create_credential_schema_unique_name_error() {
    let mut repository = MockCredentialSchemaRepository::default();
    let history_repository = MockHistoryRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let organisation = dummy_organisation(None);

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
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        repository,
        history_repository,
        MockOrganisationRepository::default(),
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            external_schema: false,
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
        })
        .await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::CredentialSchemaAlreadyExists)
    )));
}

#[tokio::test]
async fn test_create_credential_schema_failed_unique_claims_error() {
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .times(2)
        .returning(|_| Some(Arc::new(MockCredentialFormatter::default())));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: None,
            revocation_method: "NONE".to_string(),
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![
                CredentialClaimSchemaRequestDTO {
                    key: "sameRoot".to_string(),
                    datatype: "STRING".to_string(),
                    array: Some(false),
                    required: true,
                    claims: vec![],
                },
                CredentialClaimSchemaRequestDTO {
                    key: "sameRoot".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: Some(false),
                    claims: vec![],
                },
            ],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "parent".to_string(),
                datatype: "OBJECT".to_string(),
                array: Some(false),
                required: true,
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "sameNested".to_string(),
                        datatype: "STRING".to_string(),
                        array: Some(false),
                        required: true,
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "sameNested".to_string(),
                        array: Some(false),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                    },
                ],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .times(4)
        .returning(|_| Some(Arc::new(MockCredentialFormatter::default())));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let non_existing_format = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "NON_EXISTING_FORMAT".to_string(),
            revocation_method: "NONE".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                array: Some(false),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
        })
        .await;
    assert!(
        non_existing_format.is_err_and(|e| matches!(e, ServiceError::ConfigValidationError(_)))
    );

    let non_existing_revocation_method = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            revocation_method: "TEST".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
        })
        .await;
    assert!(
        non_existing_revocation_method
            .is_err_and(|e| matches!(e, ServiceError::ConfigValidationError(_)))
    );

    let wrong_datatype = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            external_schema: false,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "BLABLA".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
        })
        .await;
    assert!(wrong_datatype.is_err_and(|e| matches!(e, ServiceError::ConfigValidationError(_))));

    let no_claims = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
        })
        .await;
    assert!(no_claims.is_err_and(|e| matches!(
        e,
        ServiceError::Validation(ValidationError::CredentialSchemaMissingClaims)
    )));
}

#[tokio::test]
async fn test_create_credential_schema_fail_unsupported_wallet_storage_type() {
    let mut config = generic_config().core;
    config
        .holder_key_storage
        .get_mut(&WalletStorageTypeEnum::Hardware)
        .unwrap()
        .enabled = Some(false);

    let mut repository = MockCredentialSchemaRepository::default();
    let history_repository = MockHistoryRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let organisation = dummy_organisation(None);

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
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_, _| Ok(clone.clone()));
    }

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _| Ok("schema id".to_string()));
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        revocation_method_provider,
        config,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Hardware),
            revocation_method: "NONE".to_string(),
            organisation_id: organisation.id.to_owned(),
            external_schema: false,
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
        })
        .await;

    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::Validation(ValidationError::WalletStorageTypeDisabled(
            WalletStorageTypeEnum::Hardware
        ))
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
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            external_schema: false,
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
        .returning(|| FormatterCapabilities {
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let revocation_method = MockRevocationMethod::default();

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            external_schema: false,
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
        .returning(generic_formatter_capabilities);
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "MDOC".to_string(),
            external_schema: false,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![
                CredentialClaimSchemaRequestDTO {
                    key: "test".to_string(),
                    datatype: "OBJECT".to_string(),
                    array: Some(false),
                    required: true,
                    claims: vec![CredentialClaimSchemaRequestDTO {
                        key: "nested".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                    }],
                },
                CredentialClaimSchemaRequestDTO {
                    key: "test2".to_string(),
                    datatype: "STRING".to_string(),
                    array: Some(false),
                    required: true,
                    claims: vec![],
                },
            ],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: Some("schema.id".to_string()),
            allow_suspension: Some(true),
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
async fn test_create_credential_schema_failed_mdoc_missing_doctype() {
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            features: vec![
                Features::SelectiveDisclosure,
                Features::RequiresSchemaId,
                Features::SupportsCredentialDesign,
            ],
            ..generic_formatter_capabilities()
        });
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "MDOC".to_string(),
            external_schema: false,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "OBJECT".to_string(),
                array: Some(false),
                required: true,
                claims: vec![CredentialClaimSchemaRequestDTO {
                    key: "nested".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: Some(false),
                    claims: vec![],
                }],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: Some("".to_string()),
            allow_suspension: Some(true),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::BusinessLogic(BusinessLogicError::MissingSchemaId)
    ));
}

#[tokio::test]
async fn test_create_credential_schema_failed_physical_card_invalid_schema_id() {
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            features: vec![
                Features::SelectiveDisclosure,
                Features::RequiresSchemaId,
                Features::SupportsCredentialDesign,
            ],
            allowed_schema_ids: vec!["UtopiaEmploymentDocument".to_string()],
            ..generic_formatter_capabilities()
        });
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "PHYSICAL_CARD".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "nested".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: Some("test".to_string()),
            allow_suspension: Some(true),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::Validation(ValidationError::SchemaIdNotAllowedForFormat)
    ));
}

#[tokio::test]
async fn test_create_credential_schema_failed_schema_id_not_allowed() {
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    formatter
        .expect_get_capabilities()
        .returning(generic_formatter_capabilities);
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            external_schema: false,
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: Some("schema.id".to_string()),
            allow_suspension: Some(true),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        ServiceError::BusinessLogic(BusinessLogicError::SchemaIdNotAllowed)
    ));
}

#[tokio::test]
async fn test_create_credential_schema_failed_claim_schema_key_too_long() {
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .times(3)
        .returning(|_| Some(Arc::new(MockCredentialFormatter::default())));
    let service = setup_service(
        Default::default(),
        Default::default(),
        Default::default(),
        formatter_provider,
        Default::default(),
        generic_config().core,
    );

    let str_of_len_256 = "a".repeat(256);
    let str_of_len_128 = "a".repeat(128);
    let unicode_str_of_len_130_but_byte_len_of_260 = "§".repeat(130);

    let first_level_fail = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            external_schema: false,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: str_of_len_256,
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: str_of_len_128.to_owned(),
                datatype: "OBJECT".to_string(),
                array: Some(false),
                required: true,
                claims: vec![CredentialClaimSchemaRequestDTO {
                    key: str_of_len_128,
                    array: Some(false),
                    datatype: "STRING".to_string(),
                    required: true,
                    claims: vec![],
                }],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
            external_schema: false,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: unicode_str_of_len_130_but_byte_len_of_260,
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
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
        array: Some(false),
        claims: vec![],
    }];

    let expected = vec![CredentialClaimSchemaRequestDTO {
        key: "test".to_string(),
        datatype: "STRING".to_string(),
        array: Some(false),
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
        array: Some(false),
        required: true,
        claims: vec![
            CredentialClaimSchemaRequestDTO {
                key: "x".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
            },
            CredentialClaimSchemaRequestDTO {
                key: "y".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
            },
        ],
    }];

    let expected = vec![
        CredentialClaimSchemaRequestDTO {
            key: "location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
            array: Some(false),
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
        array: Some(false),
        claims: vec![
            CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                array: Some(false),
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                    },
                ],
            },
            CredentialClaimSchemaRequestDTO {
                key: "postal_data".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                array: Some(false),
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "code".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                        array: Some(false),
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "street".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
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
            array: Some(false),
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
            array: Some(false),
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
            array: Some(false),
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/postal_data".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/postal_data/code".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/postal_data/street".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
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
            array: false,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_location_x,
            created_date: now,
            last_modified: now,
            key: "location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: false,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_location_y,
            created_date: now,
            last_modified: now,
            key: "location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: false,
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
        array: false,
        claims: vec![
            CredentialClaimSchemaDTO {
                id: uuid_location_x,
                created_date: now,
                last_modified: now,
                key: "x".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: false,
                claims: vec![],
            },
            CredentialClaimSchemaDTO {
                id: uuid_location_y,
                created_date: now,
                last_modified: now,
                key: "y".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: false,
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
            array: false,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_location,
            created_date: now,
            last_modified: now,
            key: "address/location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            array: false,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_postal_data,
            created_date: now,
            last_modified: now,
            key: "address/postal_data".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            array: false,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_location_x,
            created_date: now,
            last_modified: now,
            key: "address/location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: false,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_location_y,
            created_date: now,
            last_modified: now,
            key: "address/location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: false,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_postal_data_street,
            created_date: now,
            last_modified: now,
            key: "address/postal_data/street".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: false,
            claims: vec![],
        },
        CredentialClaimSchemaDTO {
            id: uuid_address_postal_data_code,
            created_date: now,
            last_modified: now,
            key: "address/postal_data/code".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: false,
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
        array: false,
        claims: vec![
            CredentialClaimSchemaDTO {
                id: uuid_address_location,
                created_date: now,
                last_modified: now,
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                array: false,
                claims: vec![
                    CredentialClaimSchemaDTO {
                        id: uuid_address_location_x,
                        created_date: now,
                        last_modified: now,
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: false,
                        claims: vec![],
                    },
                    CredentialClaimSchemaDTO {
                        id: uuid_address_location_y,
                        created_date: now,
                        last_modified: now,
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: false,
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
                array: false,
                claims: vec![
                    CredentialClaimSchemaDTO {
                        id: uuid_address_postal_data_street,
                        created_date: now,
                        last_modified: now,
                        key: "street".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: false,
                        claims: vec![],
                    },
                    CredentialClaimSchemaDTO {
                        id: uuid_address_postal_data_code,
                        created_date: now,
                        last_modified: now,
                        key: "code".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: false,
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
        array: false,
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
            array: Some(false),
        },
        CredentialClaimSchemaRequestDTO {
            key: "claim2".to_owned(),
            datatype: "STRING".to_owned(),
            required: true,
            array: Some(false),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "claim21".to_owned(),
                datatype: "STRING".to_owned(),
                required: true,
                array: Some(false),
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "claim211".to_owned(),
                        datatype: "STRING".to_owned(),
                        required: true,
                        claims: vec![],
                        array: Some(false),
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "claim212".to_owned(),
                        datatype: "STRING".to_owned(),
                        required: true,
                        claims: vec![],
                        array: Some(false),
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "claim213".to_owned(),
                        datatype: "STRING".to_owned(),
                        required: true,
                        claims: vec![],
                        array: Some(false),
                    },
                ],
            }],
        },
    ];
    let layout_properties = Some(CredentialSchemaLayoutPropertiesRequestDTO {
        background: None,
        logo: None,
        picture_attribute: Some("claim2/claim21/claim213".to_owned()),
        code: Some(CredentialSchemaCodePropertiesDTO {
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
        array: Some(false),
        claims: vec![CredentialClaimSchemaRequestDTO {
            key: "claim21".to_owned(),
            datatype: "STRING".to_owned(),
            required: true,
            array: Some(false),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "claim211".to_owned(),
                datatype: "STRING".to_owned(),
                required: true,
                claims: vec![],
                array: Some(false),
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
            image: Some(
                "data:image/png;base64,AAAAAAAAAAAAAA=="
                    .to_string()
                    .try_into()
                    .unwrap(),
            ),
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
            image: Some(
                "data:image/png;base64,AAAAAAAAAAAAAA=="
                    .to_string()
                    .try_into()
                    .unwrap(),
            ),
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
            image: Some(
                "data:image/png;base64,AAAAAAAAAAAAAA=="
                    .to_string()
                    .try_into()
                    .unwrap(),
            ),
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
            image: Some(
                "data:image/png;base64,AAAAAAAAAAAAAA=="
                    .to_string()
                    .try_into()
                    .unwrap(),
            ),
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
            image: Some(
                "data:image/png;base64,AAAAAAAAAAAAAA=="
                    .to_string()
                    .try_into()
                    .unwrap(),
            ),
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
        array: Some(false),
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
        array: Some(false),
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
        external_schema: false,
        organisation_id: Uuid::new_v4().into(),
        claims: vec![],
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: None,
        allow_suspension: Some(true),
    }
}

#[tokio::test]
async fn test_share_credential_schema_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut history_repository = MockHistoryRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let schema_id: CredentialSchemaId = Uuid::new_v4().into();

    repository
        .expect_get_credential_schema()
        .returning(|_, _| Ok(Some(generic_credential_schema())));

    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        Default::default(),
        Default::default(),
        generic_config().core,
    );

    let result = service.share_credential_schema(&schema_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_import_credential_schema_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut history_repository = MockHistoryRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let now = OffsetDateTime::now_utc();
    let own_organisation_id = Uuid::new_v4();
    let organisation = dummy_organisation(Some(own_organisation_id.into()));
    organisation_repository
        .expect_get_organisation()
        .return_once(|_, _| Ok(Some(organisation)));

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_, _| {
            Ok(GetCredentialSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    repository
        .expect_create_credential_schema()
        .return_once(move |new_schema| {
            assert_eq!(
                own_organisation_id,
                new_schema.organisation.unwrap().id.into()
            );
            Ok(new_schema.id)
        });
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        formatter_provider,
        revocation_method_provider,
        generic_config().core,
    );

    let external_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let result = service
        .import_credential_schema(ImportCredentialSchemaRequestDTO {
            organisation_id: own_organisation_id.into(),
            schema: ImportCredentialSchemaRequestSchemaDTO {
                id: external_schema_id.into(),
                created_date: now,
                imported_source_url: "CORE_URL".to_string(),
                last_modified: now,
                name: "external schema".to_string(),
                format: "JWT".to_string(),
                external_schema: false,
                revocation_method: "NONE".to_string(),
                organisation_id: Uuid::new_v4(),
                claims: vec![ImportCredentialSchemaClaimSchemaDTO {
                    id: Uuid::new_v4(),
                    created_date: now,
                    last_modified: now,
                    key: "name".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: Some(false),
                    claims: vec![],
                }],
                wallet_storage_type: None,
                schema_id: "http://127.0.0.1/ssi/schema/some_schmea".to_string(),
                schema_type: CredentialSchemaType::ProcivisOneSchema2024.into(),
                layout_type: None,
                layout_properties: None,
                allow_suspension: Some(true),
            },
        })
        .await
        .unwrap();
    assert_ne!(external_schema_id, result);
}

#[tokio::test]
async fn test_create_credential_schema_fail_unsupported_datatype() {
    // given
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let organisation = dummy_organisation(None);

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _| Ok("some schema id".to_string()));
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockHistoryRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    // when
    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            revocation_method: "NONE".to_string(),
            external_schema: false,
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                array: Some(false),
                required: true,
                claims: vec![
                    CredentialClaimSchemaRequestDTO {
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(true),
                        claims: vec![],
                    },
                ],
            }],
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
        })
        .await
        .unwrap_err();

    // then
    let_assert!(
        ServiceError::Validation(
            ValidationError::CredentialSchemaClaimSchemaUnsupportedDatatype {
                claim_name,
                data_type
            }
        ) = result
    );
    assert2::assert!(claim_name == "location");
    assert2::assert!(data_type == "OBJECT");
}
