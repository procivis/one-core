use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use maplit::btreemap;
use mockall::predicate::*;
use shared_types::CredentialSchemaId;
use shared_types::i18n::I18nString;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::CredentialSchemaService;
use super::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaMappingDTO,
    CredentialClaimSchemaRequestDTO, CredentialClaimSchemaTranslationsDTO,
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaFilterParamsDTO,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLogoPropertiesRequestDTO,
    CredentialSchemaTransactionCodeRequestDTO, ImportCredentialSchemaClaimSchemaDTO,
    ImportCredentialSchemaRequestDTO, ImportCredentialSchemaRequestSchemaDTO,
};
use super::error::CredentialSchemaServiceError;
use super::mapper::{renest_claim_schemas, unnest_claim_schemas};
use super::validator::{
    check_background_properties, check_claims_presence_in_layout_properties, check_logo_properties,
};
use crate::config::core_config::CoreConfig;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{
    CredentialSchema, GetCredentialSchemaList, KeyStorageSecurity, TransactionCodeType,
};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::proto::credential_schema::importer::{
    CredentialSchemaImporterProto, MockCredentialSchemaImporter,
};
use crate::proto::credential_schema::parser::{
    CredentialSchemaImportParserImpl, MockCredentialSchemaImportParser,
};
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{Features, FormatterCapabilities};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::error::{DataLayerError, EntityKind};
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::test_utilities::{
    dummy_organisation, generic_config, generic_formatter_capabilities, get_dummy_date,
};

fn setup_service(
    credential_schema_repository: MockCredentialSchemaRepository,
    organisation_repository: MockOrganisationRepository,
    formatter_provider: MockCredentialFormatterProvider,
    revocation_method_provider: MockRevocationMethodProvider,
    config: CoreConfig,
) -> CredentialSchemaService {
    let formatter_provider = Arc::new(formatter_provider);
    let credential_schema_repository = Arc::new(credential_schema_repository);
    let revocation_method_provider = Arc::new(revocation_method_provider);
    let config = Arc::new(config);
    let import_parser = CredentialSchemaImportParserImpl::new(
        config.clone(),
        Some("http://127.0.0.1:4321".to_string()),
        formatter_provider.clone(),
        revocation_method_provider.clone(),
    );

    let importer = CredentialSchemaImporterProto::new(
        credential_schema_repository.clone(),
        config.clone(),
        Some("http://127.0.0.1:4321".to_string()),
    );

    CredentialSchemaService::new(
        Some("http://127.0.0.1:4321".to_string()),
        credential_schema_repository,
        Arc::new(organisation_repository),
        formatter_provider,
        revocation_method_provider,
        config,
        Arc::new(NoSessionProvider),
        Arc::new(import_parser),
        Arc::new(importer),
        Arc::new(MockEcosystemDirectory::new()),
    )
}

fn generic_credential_schema() -> CredentialSchema {
    let now = crate::clock::now_utc();
    let credential_schema_id = Uuid::new_v4().into();
    let claim_schema_id = Uuid::new_v4().into();
    CredentialSchema {
        expiration: None,
        ecosystem: None,
        batch_size: None,
        allow_revocation: false,
        id: credential_schema_id,
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: now,
        last_modified: now,
        wallet_attestation: Default::default(),
        name: "testName".to_string(),
        formats: vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_id,
            format: "JWT".into(),
            ecosystem_schema_id: "CredentialSchemaId".to_owned(),
            claim_mappings: Default::default(),
        }]
        .into(),
        claim_schemas: vec![ClaimSchema {
            id: claim_schema_id,
            key: "".to_string(),
            data_type: "".to_string(),
            created_date: now,
            last_modified: now,
            array: false,
            metadata: false,
            required: true,
            translations: vec![LocalizedText {
                entity_id: claim_schema_id.into(),
                field: LocalizedTextField::Name,
                created_date: now,
                last_modified: now,
                lang: "en".to_string(),
                value: "".to_string(),
                entity_type: LocalizedTextEntityType::ClaimSchema,
            }]
            .into(),
        }]
        .into(),
        organisation: dummy_organisation(None).into(),
        layout_properties: None,
        allow_suspension: true,
        transaction_code: None,
        translations: vec![LocalizedText {
            entity_id: credential_schema_id.into(),
            field: LocalizedTextField::Name,
            created_date: now,
            last_modified: now,
            lang: "en".to_string(),
            value: "testName".to_string(),
            entity_type: LocalizedTextEntityType::CredentialSchema,
        }]
        .into(),
        embedded_disclosure_policy: None,
    }
}

#[tokio::test]
async fn test_get_credential_schema_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().returning(|| None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(
        repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service.get_credential_schema(&schema.id).await.unwrap();
    assert_eq!(result.id, schema.id);
}

#[tokio::test]
async fn test_get_credential_schema_deleted() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let schema = CredentialSchema {
        deleted_at: Some(crate::clock::now_utc()),
        ..generic_credential_schema()
    };
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(
        repository,
        organisation_repository,
        MockCredentialFormatterProvider::default(),
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service.get_credential_schema(&schema.id).await;

    assert!(result.is_err_and(|e| matches!(e, CredentialSchemaServiceError::NotFound(_))));
}

#[tokio::test]
async fn test_get_credential_schema_list_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: Some(1),
        total_items: Some(3),
    };

    {
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().returning(|| None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(
        repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let organisation_id = Uuid::new_v4().into();
    let result = service
        .get_credential_schema_list(ListQueryDTO {
            page: 0,
            page_size: 5,
            sort: None,
            sort_direction: None,
            filter: CredentialSchemaFilterParamsDTO {
                name: None,
                exact: None,
                organisation_id,
                schema_id: None,
                formats: None,
                ecosystems: None,
                requires_wallet_instance_attestation: None,
                key_storage_security: None,
                credential_schema_ids: None,
                created_date_after: None,
                created_date_before: None,
                last_modified_after: None,
                last_modified_before: None,
                uses_batch_issuance: None,
                is_multiformat_schema: None,
                schema_ids: None,
            },
            include: None,
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
    let organisation_repository = MockOrganisationRepository::default();

    let credential_schema = generic_credential_schema();
    let schema_id: CredentialSchemaId = credential_schema.id;

    repository
        .expect_get_credential_schema()
        .returning(move |_| Ok(credential_schema.clone()));

    repository
        .expect_delete_credential_schema()
        .times(1)
        .withf(move |schema| schema.id == schema_id)
        .returning(move |_| Ok(()));

    let service = setup_service(
        repository,
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
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let organisation = dummy_organisation(None);
    let schema_id: CredentialSchemaId = Uuid::new_v4().into();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: Some(0),
        total_items: Some(0),
    };

    {
        let organisation = organisation.clone();
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .with(eq(organisation.id.to_owned()))
            .returning(move |_| Ok(organisation.clone()));
        repository
            .expect_create_credential_schema()
            .times(1)
            .returning(move |_| Ok(schema_id));
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            datatypes: vec!["STRING".into()],
            ..generic_formatter_capabilities()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _, _, _| Ok("schema id".to_string()));
    formatter.expect_get_metadata_claims().returning(Vec::new);
    formatter.expect_config_name().return_const("JWT".into());
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let service = setup_service(
        repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(schema_id, result.unwrap());
}

#[tokio::test]
async fn test_create_credential_schema_success_mdoc_with_custom_schema_id() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let organisation = dummy_organisation(None);
    let schema_id: CredentialSchemaId = Uuid::new_v4().into();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: Some(0),
        total_items: Some(0),
    };

    let custom_schema_id = "custom_schema_id";
    {
        let organisation = organisation.clone();
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .with(eq(organisation.id.to_owned()))
            .returning(move |_| Ok(organisation.clone()));
        repository
            .expect_create_credential_schema()
            .times(1)
            .returning(move |_| Ok(schema_id.to_owned()));
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            features: vec![Features::SelectiveDisclosure, Features::SupportsSchemaId],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..generic_formatter_capabilities()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _, _, _| Ok(custom_schema_id.to_string()));
    formatter.expect_get_metadata_claims().returning(Vec::new);
    formatter.expect_config_name().return_const("JWT".into());
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let service = setup_service(
        repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "MDOC".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: organisation.id.to_owned(),
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
                    mappings: None,
                    translations: None,
                }],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: Some(custom_schema_id.to_string()),
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await
        .unwrap();
    assert_eq!(schema_id, result);
}

#[tokio::test]
async fn test_create_credential_schema_success_nested_claims() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let organisation = dummy_organisation(None);
    let schema_id = Uuid::new_v4();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: Some(0),
        total_items: Some(0),
    };

    {
        let organisation = organisation.clone();
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .with(eq(organisation.id.to_owned()))
            .returning(move |_| Ok(organisation.clone()));
        repository
            .expect_create_credential_schema()
            .times(1)
            .returning(move |_| Ok(schema_id.into()));
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..generic_formatter_capabilities()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _, _, _| Ok("some schema id".to_string()));
    formatter.expect_get_metadata_claims().returning(Vec::new);
    formatter.expect_config_name().return_const("JWT".into());
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let service = setup_service(
        repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
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
                        mappings: None,
                        translations: None,
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                        mappings: None,
                        translations: None,
                    },
                ],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await
        .unwrap();
    assert_eq!(schema_id, Uuid::from(result));
}

#[tokio::test]
async fn test_create_credential_schema_failed_slash_in_claim_name() {
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Ok(Arc::new(MockCredentialFormatter::default())));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location/x".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0108);
}

#[tokio::test]
async fn test_create_credential_schema_failed_nested_claims_not_in_object_type() {
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Ok(Arc::new(MockCredentialFormatter::default())));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
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
                        mappings: None,
                        translations: None,
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                        mappings: None,
                        translations: None,
                    },
                ],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0107);
}

#[tokio::test]
async fn test_create_credential_schema_failed_nested_claims_object_type_has_empty_claims() {
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Ok(Arc::new(MockCredentialFormatter::default())));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0106);
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
        .return_once(|_| Ok(Arc::new(formatter)));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
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
                    mappings: None,
                    translations: None,
                }],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await
        .unwrap_err();

    assert_eq!(result.error_code(), ErrorCode::BR_0089);
}

#[tokio::test]
async fn test_create_credential_schema_unique_name_error() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let organisation = dummy_organisation(None);

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: Some(1),
        total_items: Some(1),
    };

    {
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(response.clone()));
    }

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            datatypes: vec!["STRING".into()],
            ..generic_formatter_capabilities()
        });
    formatter.expect_config_name().return_const("JWT".into());
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Ok(Arc::new(formatter)));

    let service = setup_service(
        repository,
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "testName".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0007);
}

#[tokio::test]
async fn test_create_credential_schema_failed_unique_claims_error() {
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .times(2)
        .returning(|_| Ok(Arc::new(MockCredentialFormatter::default())));
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![
                CredentialClaimSchemaRequestDTO {
                    key: "sameRoot".to_string(),
                    datatype: "STRING".to_string(),
                    array: Some(false),
                    required: true,
                    claims: vec![],
                    mappings: None,
                    translations: None,
                },
                CredentialClaimSchemaRequestDTO {
                    key: "sameRoot".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: Some(false),
                    claims: vec![],
                    mappings: None,
                    translations: None,
                },
            ],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0133);

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
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
                        mappings: None,
                        translations: None,
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "sameNested".to_string(),
                        array: Some(false),
                        datatype: "STRING".to_string(),
                        required: true,
                        claims: vec![],
                        mappings: None,
                        translations: None,
                    },
                ],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0133);
}

#[tokio::test]
async fn test_create_credential_schema_fail_validation() {
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::default();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let non_existing_format = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "NON_EXISTING_FORMAT".into(),
            revocation_method: None,
            key_storage_security: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                array: Some(false),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(
        non_existing_format.unwrap_err().error_code(),
        ErrorCode::BR_0089
    );

    let non_existing_revocation_method = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            revocation_method: Some("TEST".into()),
            key_storage_security: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(
        non_existing_revocation_method.unwrap_err().error_code(),
        ErrorCode::BR_0110
    );

    let wrong_datatype = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "BLABLA".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(wrong_datatype.unwrap_err().error_code(), ErrorCode::BR_0089);

    let no_claims = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            key_storage_security: None,
            format: "JWT".into(),
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(no_claims.unwrap_err().error_code(), ErrorCode::BR_0008);
}

#[tokio::test]
async fn test_create_credential_schema_fail_unsupported_wallet_storage_type() {
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let organisation = dummy_organisation(None);

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            datatypes: vec!["STRING".into()],
            ..generic_formatter_capabilities()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _, _, _| Ok("schema id".to_string()));
    formatter.expect_config_name().return_const("JWT".into());
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Ok(Arc::new(formatter)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: Some(KeyStorageSecurity::EnhancedBasic),
            revocation_method: None,
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0309);
}

#[tokio::test]
async fn test_create_credential_schema_fail_missing_organisation() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: Some(0),
        total_items: Some(0),
    };

    {
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .returning(move |_| {
                Err(DataLayerError::EntityNotFound {
                    kind: EntityKind::Organisation,
                    id: Uuid::nil(),
                })
            });
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            datatypes: vec!["STRING".into()],
            ..generic_formatter_capabilities()
        });
    formatter.expect_config_name().return_const("JWT".into());
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Ok(Arc::new(formatter)));

    let service = setup_service(
        repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0022);
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
    formatter.expect_revocation_method_id().return_const(None);
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Ok(Arc::new(formatter)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: Some("BITSTRINGSTATUSLIST".into()),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: Some(true),
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;

    match result {
        Err(CredentialSchemaServiceError::RevocationMethodNotCompatibleWithSelectedFormat) => {
            /* Expected */
        }
        other => panic!(
            "Expected Err(CredentialSchemaServiceError::RevocationMethodNotCompatibleWithSelectedFormat), got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_create_credential_schema_failed_mdoc_not_all_top_claims_are_object() {
    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "MDOC".into(),
            key_storage_security: None,
            revocation_method: None,
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
                        mappings: None,
                        translations: None,
                    }],
                    mappings: None,
                    translations: None,
                },
                CredentialClaimSchemaRequestDTO {
                    key: "test2".to_string(),
                    datatype: "STRING".to_string(),
                    array: Some(false),
                    required: true,
                    claims: vec![],
                    mappings: None,
                    translations: None,
                },
            ],
            layout_properties: None,
            schema_id: Some("schema.id".to_string()),
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;

    match result {
        Err(CredentialSchemaServiceError::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed) => {
            /* Expected */
        }
        other => panic!(
            "Expected Err(CredentialSchemaServiceError::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed), got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_create_credential_schema_failed_schema_id_not_allowed() {
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    formatter
        .expect_get_capabilities()
        .returning(generic_formatter_capabilities);
    formatter
        .expect_credential_schema_id()
        .withf(|_, _, schema_id, _, _| {
            assert_eq!(schema_id, &Some("schema.id"));
            true
        })
        .return_once(|_, _, _, _, _| Err(FormatterError::SchemaIdNotAllowed));
    formatter.expect_config_name().return_const("JWT".into());
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(|_| {
            Ok(GetCredentialSchemaList {
                values: vec![],
                total_pages: Some(0),
                total_items: Some(0),
            })
        });

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .once()
        .return_once(|id| Ok(dummy_organisation(Some(*id))));

    let service = setup_service(
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: Some("schema.id".to_string()),
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0139);
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
    let unicode_str_of_len_130_but_byte_len_of_260 = "§".repeat(130);

    let first_level_fail = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: str_of_len_256,
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(
        first_level_fail.unwrap_err().error_code(),
        ErrorCode::BR_0126
    );

    let nested_fail = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
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
                    mappings: None,
                    translations: None,
                }],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(nested_fail.unwrap_err().error_code(), ErrorCode::BR_0126);

    let unicode_len_fail = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: unicode_str_of_len_130_but_byte_len_of_260,
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(
        unicode_len_fail.unwrap_err().error_code(),
        ErrorCode::BR_0126
    );
}

#[tokio::test]
async fn test_unnest_claim_schemas_from_request_no_nested_claims() {
    let request = vec![CredentialClaimSchemaRequestDTO {
        key: "test".to_string(),
        datatype: "STRING".to_string(),
        required: true,
        array: Some(false),
        claims: vec![],
        mappings: None,
        translations: None,
    }];

    let expected = vec![CredentialClaimSchemaRequestDTO {
        key: "test".to_string(),
        datatype: "STRING".to_string(),
        array: Some(false),
        required: true,
        claims: vec![],
        mappings: Some(vec![CredentialClaimSchemaMappingDTO {
            format: "JWT".into(),
            technical_key: "test".to_string(),
            namespace: None,
        }]),
        translations: None,
    }];

    assert_eq!(
        expected,
        unnest_claim_schemas(request, &[&"JWT".into()], &HashMap::new()).unwrap()
    );
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
                mappings: None,
                translations: None,
            },
            CredentialClaimSchemaRequestDTO {
                key: "y".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
                mappings: None,
                translations: None,
            },
        ],
        mappings: None,
        translations: None,
    }];

    let expected = vec![
        CredentialClaimSchemaRequestDTO {
            key: "location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "location".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
        CredentialClaimSchemaRequestDTO {
            key: "location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "location/x".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
        CredentialClaimSchemaRequestDTO {
            key: "location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
            array: Some(false),
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "location/y".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
    ];

    assert_eq!(
        expected,
        unnest_claim_schemas(request, &[&"JWT".into()], &HashMap::new()).unwrap()
    );
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
                        mappings: None,
                        translations: None,
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                        mappings: None,
                        translations: None,
                    },
                ],
                mappings: None,
                translations: None,
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
                        mappings: None,
                        translations: None,
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "street".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                        mappings: None,
                        translations: None,
                    },
                ],
                mappings: None,
                translations: None,
            },
        ],
        mappings: None,
        translations: None,
    }];

    let expected = vec![
        CredentialClaimSchemaRequestDTO {
            key: "address".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "address".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
            array: Some(false),
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "address/location".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/location/x".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            claims: vec![],
            array: Some(false),
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "address/location/x".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/location/y".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "address/location/y".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/postal_data".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "address/postal_data".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/postal_data/code".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "address/postal_data/code".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
        CredentialClaimSchemaRequestDTO {
            key: "address/postal_data/street".to_string(),
            datatype: "STRING".to_string(),
            required: true,
            array: Some(false),
            claims: vec![],
            mappings: Some(vec![CredentialClaimSchemaMappingDTO {
                format: "JWT".into(),
                technical_key: "address/postal_data/street".to_string(),
                namespace: None,
            }]),
            translations: None,
        },
    ];

    assert_eq!(
        expected,
        unnest_claim_schemas(request, &[&"JWT".into()], &HashMap::new()).unwrap()
    );
}

#[test]
fn test_renest_claim_schemas_single_layer_of_nested_claims() {
    let now = crate::clock::now_utc();

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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
        translations: CredentialClaimSchemaTranslationsDTO {
            name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
        },

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
                translations: CredentialClaimSchemaTranslationsDTO {
                    name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
                },
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
                translations: CredentialClaimSchemaTranslationsDTO {
                    name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
                },
            },
        ],
    }];

    assert_eq!(expected, renest_claim_schemas(request).unwrap());
}

#[test]
fn test_renest_claim_schemas_multiple_layers_of_nested_claims() {
    let now = crate::clock::now_utc();

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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
            translations: CredentialClaimSchemaTranslationsDTO {
                name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
            },
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
        translations: CredentialClaimSchemaTranslationsDTO {
            name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
        },

        claims: vec![
            CredentialClaimSchemaDTO {
                id: uuid_address_location,
                created_date: now,
                last_modified: now,
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                array: false,
                translations: CredentialClaimSchemaTranslationsDTO {
                    name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
                },

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
                        translations: CredentialClaimSchemaTranslationsDTO {
                            name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
                        },
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
                        translations: CredentialClaimSchemaTranslationsDTO {
                            name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
                        },
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
                translations: CredentialClaimSchemaTranslationsDTO {
                    name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
                },

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
                        translations: CredentialClaimSchemaTranslationsDTO {
                            name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
                        },
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
                        translations: CredentialClaimSchemaTranslationsDTO {
                            name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
                        },
                    },
                ],
            },
        ],
    }];

    assert_eq!(expected, renest_claim_schemas(request).unwrap());
}

#[test]
fn test_renest_claim_schemas_failed_missing_parent_claim_schema() {
    let now = crate::clock::now_utc();

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
        translations: CredentialClaimSchemaTranslationsDTO {
            name: I18nString(btreemap! { "en".to_string() => "name".to_string()}),
        },
    }];
    assert!(matches!(
        renest_claim_schemas(request),
        Err(CredentialSchemaServiceError::MissingParentClaimSchema { .. })
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
            mappings: None,
            translations: None,
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
                        mappings: None,
                        translations: None,
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "claim212".to_owned(),
                        datatype: "STRING".to_owned(),
                        required: true,
                        claims: vec![],
                        array: Some(false),
                        mappings: None,
                        translations: None,
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "claim213".to_owned(),
                        datatype: "STRING".to_owned(),
                        required: true,
                        claims: vec![],
                        array: Some(false),
                        mappings: None,
                        translations: None,
                    },
                ],
                mappings: None,
                translations: None,
            }],
            mappings: None,
            translations: None,
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

    assert2::assert!(let Ok(()) = check_claims_presence_in_layout_properties(request.layout_properties.as_ref(), &request.claims))
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
                mappings: None,
                translations: None,
            }],
            mappings: None,
            translations: None,
        }],
        mappings: None,
        translations: None,
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
        let Err(CredentialSchemaServiceError::MissingLayoutAttribute(_)) = check_claims_presence_in_layout_properties(request.layout_properties.as_ref(), &request.claims)
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
        let Err(CredentialSchemaServiceError::AttributeCombinationNotAllowed) = check_background_properties(request.layout_properties.as_ref())
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
        let Err(CredentialSchemaServiceError::AttributeCombinationNotAllowed) = check_background_properties(request.layout_properties.as_ref())
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
        let Ok(()) = check_background_properties(request.layout_properties.as_ref())
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
        let Ok(()) = check_background_properties(request.layout_properties.as_ref())
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
        let Ok(()) = check_logo_properties(request.layout_properties.as_ref())
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
        let Ok(()) = check_logo_properties(request.layout_properties.as_ref())
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
        let Err(CredentialSchemaServiceError::AttributeCombinationNotAllowed) = check_logo_properties(request.layout_properties.as_ref())
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
        let Err(CredentialSchemaServiceError::AttributeCombinationNotAllowed) = check_logo_properties(request.layout_properties.as_ref())
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
        let Err(CredentialSchemaServiceError::AttributeCombinationNotAllowed) = check_logo_properties(request.layout_properties.as_ref())
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
        let Err(CredentialSchemaServiceError::AttributeCombinationNotAllowed) = check_logo_properties(request.layout_properties.as_ref())
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
        mappings: None,
        translations: None,
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
        let Err(CredentialSchemaServiceError::MissingLayoutAttribute(_)) = check_claims_presence_in_layout_properties(request.layout_properties.as_ref(), &request.claims)
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
        mappings: None,
        translations: None,
    }];

    let request = CreateCredentialSchemaRequestDTO {
        claims,
        layout_properties: None,
        ..dummy_request()
    };

    assert2::assert!(let Ok(()) = check_claims_presence_in_layout_properties(request.layout_properties.as_ref(), &request.claims))
}

fn dummy_request() -> CreateCredentialSchemaRequestDTO {
    CreateCredentialSchemaRequestDTO {
        name: "AnyName".to_owned(),
        format: "AnyFormat".into(),
        revocation_method: None,
        organisation_id: Uuid::new_v4().into(),
        claims: vec![],
        key_storage_security: None,
        layout_properties: None,
        schema_id: None,
        allow_suspension: Some(true),
        requires_wallet_instance_attestation: false,
        transaction_code: None,
        ecosystem: None,
    }
}

#[tokio::test]
async fn test_share_credential_schema_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let schema_id: CredentialSchemaId = Uuid::new_v4().into();

    repository
        .expect_get_credential_schema()
        .returning(|_| Ok(generic_credential_schema()));

    let service = setup_service(
        repository,
        organisation_repository,
        Default::default(),
        Default::default(),
        generic_config().core,
    );

    let result = service.share_credential_schema(&schema_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_share_credential_schema_v2_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let schema_id: CredentialSchemaId = Uuid::new_v4().into();

    repository
        .expect_get_credential_schema()
        .returning(|_| Ok(generic_credential_schema()));

    let service = setup_service(
        repository,
        organisation_repository,
        Default::default(),
        Default::default(),
        generic_config().core,
    );

    let result = service.share_credential_schema(&schema_id).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.url, "CORE_URL");
}

#[tokio::test]
async fn test_share_credential_schema_v2_not_found() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let schema_id: CredentialSchemaId = Uuid::new_v4().into();

    repository.expect_get_credential_schema().returning(|id| {
        Err(DataLayerError::EntityNotFound {
            kind: EntityKind::CredentialSchema,
            id: (*id).into(),
        })
    });

    let service = setup_service(
        repository,
        organisation_repository,
        Default::default(),
        Default::default(),
        generic_config().core,
    );

    let result = service.share_credential_schema(&schema_id).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_import_credential_schema_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let now = crate::clock::now_utc();
    let own_organisation_id = Uuid::new_v4();
    let organisation = dummy_organisation(Some(own_organisation_id.into()));
    organisation_repository
        .expect_get_organisation()
        .return_once(|_| Ok(organisation));

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);
    formatter.expect_config_name().return_const("JWT".into());
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetCredentialSchemaList {
                values: vec![],
                total_pages: Some(0),
                total_items: Some(0),
            })
        });

    repository
        .expect_create_credential_schema()
        .return_once(move |new_schema| {
            assert_eq!(
                own_organisation_id,
                Uuid::from(new_schema.organisation.id())
            );
            Ok(new_schema.id)
        });

    let service = setup_service(
        repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    let external_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let result = service
        .import_credential_schema(ImportCredentialSchemaRequestDTO {
            organisation_id: own_organisation_id.into(),
            schema: ImportCredentialSchemaRequestSchemaDTO {
                id: external_schema_id.into(),
                created_date: now,
                imported_source_url: "https://source.example/schema".to_string(),
                last_modified: now,
                name: "external schema".to_string(),
                format: "JWT".to_string(),
                revocation_method: None,
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
                    mappings: None,
                    translations: None,
                }],
                key_storage_security: None,
                schema_id: "http://127.0.0.1/ssi/schema/some_schmea".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: Some(true),
                transaction_code: None,
                expiration: None,
                ecosystem: None,
            },
        })
        .await
        .unwrap();
    assert_ne!(external_schema_id, result);
}

#[tokio::test]
async fn test_import_credential_schema_rehosts_source_url_when_enabled() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let now = crate::clock::now_utc();
    let own_organisation_id = Uuid::new_v4();
    let organisation = dummy_organisation(Some(own_organisation_id.into()));
    organisation_repository
        .expect_get_organisation()
        .return_once(|_| Ok(organisation));

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);
    formatter.expect_config_name().return_const("JWT".into());
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetCredentialSchemaList {
                values: vec![],
                total_pages: Some(0),
                total_items: Some(0),
            })
        });

    repository
        .expect_create_credential_schema()
        .return_once(move |new_schema| {
            // source url is rewritten to point at this core instance
            assert_eq!(
                format!("http://127.0.0.1:4321/ssi/schema/v2/{}", new_schema.id),
                new_schema.imported_source_url
            );
            Ok(new_schema.id)
        });

    let mut config = generic_config().core;
    config.global_settings.rehost_imported_schemas = true;

    let service = setup_service(
        repository,
        organisation_repository,
        formatter_provider,
        MockRevocationMethodProvider::default(),
        config,
    );

    let external_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    service
        .import_credential_schema(ImportCredentialSchemaRequestDTO {
            organisation_id: own_organisation_id.into(),
            schema: ImportCredentialSchemaRequestSchemaDTO {
                id: external_schema_id.into(),
                created_date: now,
                imported_source_url: "https://other-core/ssi/schema/v2/external".to_string(),
                last_modified: now,
                name: "external schema".to_string(),
                format: "JWT".to_string(),
                revocation_method: None,
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
                    mappings: None,
                    translations: None,
                }],
                key_storage_security: None,
                schema_id: "http://127.0.0.1/ssi/schema/some_schmea".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: Some(true),
                transaction_code: None,
                expiration: None,
                ecosystem: None,
            },
        })
        .await
        .unwrap();
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
            revocation_methods: vec![],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter
        .expect_credential_schema_id()
        .returning(|_, _, _, _, _| Ok("some schema id".to_string()));
    formatter.expect_config_name().return_const("JWT".into());
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Ok(Arc::new(formatter)));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::default(),
        generic_config().core,
    );

    // when
    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
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
                        mappings: None,
                        translations: None,
                    },
                    CredentialClaimSchemaRequestDTO {
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: true,
                        array: Some(false),
                        claims: vec![],
                        mappings: None,
                        translations: None,
                    },
                ],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0245);
}

#[tokio::test]
async fn test_create_credential_schema_fail_session_org_mismatch() {
    let service = CredentialSchemaService {
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::default()),
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::default()),
        revocation_method_provider: Arc::new(MockRevocationMethodProvider::default()),
        config: Arc::new(generic_config().core),
        core_base_url: None,
        session_provider: Arc::new(StaticSessionProvider::new_random()),
        import_parser: Arc::new(MockCredentialSchemaImportParser::default()),
        importer_proto: Arc::new(MockCredentialSchemaImporter::default()),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::default()),
    };

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            ecosystem: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_create_credential_schema_fail_tx_code_not_supported() {
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);
    formatter.expect_config_name().return_const("JWT".into());
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::new(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: Some(CredentialSchemaTransactionCodeRequestDTO {
                r#type: TransactionCodeType::Numeric,
                length: 4.try_into().unwrap(),
                description: None,
            }),
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0337);
}

#[tokio::test]
async fn test_create_credential_schema_fail_tx_code_description_too_long() {
    let mut formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            datatypes: vec!["STRING".into()],
            features: vec![Features::SupportsTxCode],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);
    formatter.expect_config_name().return_const("JWT".into());
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let service = setup_service(
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        formatter_provider,
        MockRevocationMethodProvider::new(),
        generic_config().core,
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".into(),
            key_storage_security: None,
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                array: Some(false),
                required: true,
                claims: vec![],
                mappings: None,
                translations: None,
            }],
            layout_properties: None,
            schema_id: None,
            allow_suspension: None,
            requires_wallet_instance_attestation: false,
            transaction_code: Some(CredentialSchemaTransactionCodeRequestDTO {
                r#type: TransactionCodeType::Numeric,
                length: 4.try_into().unwrap(),
                description: Some(['a'; 301].iter().collect()),
            }),
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0346);
}

#[tokio::test]
async fn test_list_credential_schema_fail_session_org_mismatch() {
    let service = CredentialSchemaService {
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::default()),
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::default()),
        revocation_method_provider: Arc::new(MockRevocationMethodProvider::default()),
        config: Arc::new(generic_config().core),
        core_base_url: None,
        session_provider: Arc::new(StaticSessionProvider::new_random()),
        import_parser: Arc::new(MockCredentialSchemaImportParser::default()),
        importer_proto: Arc::new(MockCredentialSchemaImporter::default()),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::default()),
    };

    let result = service
        .get_credential_schema_list(ListQueryDTO {
            page: 0,
            page_size: 0,
            sort: None,
            sort_direction: None,
            filter: CredentialSchemaFilterParamsDTO {
                name: None,
                exact: None,
                organisation_id: Uuid::new_v4().into(),
                schema_id: None,
                formats: None,
                ecosystems: None,
                requires_wallet_instance_attestation: None,
                key_storage_security: None,
                credential_schema_ids: None,
                created_date_after: None,
                created_date_before: None,
                last_modified_after: None,
                last_modified_before: None,
                uses_batch_issuance: None,
                is_multiformat_schema: None,
                schema_ids: None,
            },
            include: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_credential_schema_ops_session_org_mismatch() {
    let mut schema_repository = MockCredentialSchemaRepository::default();
    schema_repository
        .expect_get_credential_schema()
        .returning(|_| Ok(generic_credential_schema()));
    let service = CredentialSchemaService {
        credential_schema_repository: Arc::new(schema_repository),
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::default()),
        revocation_method_provider: Arc::new(MockRevocationMethodProvider::default()),
        config: Arc::new(generic_config().core),
        core_base_url: None,
        session_provider: Arc::new(StaticSessionProvider::new_random()),
        import_parser: Arc::new(MockCredentialSchemaImportParser::default()),
        importer_proto: Arc::new(MockCredentialSchemaImporter::default()),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::default()),
    };

    let result = service.get_credential_schema(&Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service
        .delete_credential_schema(&Uuid::new_v4().into())
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service
        .share_credential_schema(&Uuid::new_v4().into())
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service
        .import_credential_schema(ImportCredentialSchemaRequestDTO {
            organisation_id: Uuid::new_v4().into(),
            schema: ImportCredentialSchemaRequestSchemaDTO {
                id: Uuid::new_v4(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "".to_string(),
                format: "".to_string(),
                revocation_method: None,
                organisation_id: Uuid::new_v4(),
                claims: vec![],
                key_storage_security: None,
                schema_id: "".to_string(),
                imported_source_url: "".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: None,
                transaction_code: None,
                expiration: None,
                ecosystem: None,
            },
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}
