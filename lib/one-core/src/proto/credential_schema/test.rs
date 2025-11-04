use std::sync::Arc;

use assert2::{assert, let_assert};
use mockall::predicate::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::{CoreConfig, RevocationType};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, GetCredentialSchemaList, LayoutType,
    WalletStorageTypeEnum,
};
use crate::proto::credential_schema::dto::{
    ImportCredentialSchemaClaimSchemaDTO, ImportCredentialSchemaRequestDTO,
    ImportCredentialSchemaRequestSchemaDTO,
};
use crate::proto::credential_schema::importer::{
    CredentialSchemaImporter, CredentialSchemaImporterProto,
};
use crate::proto::credential_schema::parser::{
    CredentialSchemaImportParser, CredentialSchemaImportParserImpl,
};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::{Operation, RevocationMethodCapabilities};
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::test_utilities::{dummy_organisation, generic_config, get_dummy_date};

fn setup_parser(
    config: CoreConfig,
    formatter_provider: MockCredentialFormatterProvider,
    revocation_method_provider: MockRevocationMethodProvider,
) -> CredentialSchemaImportParserImpl {
    CredentialSchemaImportParserImpl::new(
        Arc::new(config),
        Arc::new(formatter_provider),
        Arc::new(revocation_method_provider),
    )
}

#[test]
fn test_parse_import_credential_schema_success() {
    // given
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut formatter = MockCredentialFormatter::default();

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);

    formatter_provider
        .expect_get_credential_formatter()
        .with(eq("JWT"))
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        });

    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq("NONE"))
        .once()
        .return_once(|_| Some(Arc::new(revocation_method)));

    let parser = setup_parser(
        generic_config().core,
        formatter_provider,
        revocation_method_provider,
    );

    let request = ImportCredentialSchemaRequestDTO {
        organisation: dummy_organisation(None),
        schema: ImportCredentialSchemaRequestSchemaDTO {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "Imported Schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4(),
            claims: vec![ImportCredentialSchemaClaimSchemaDTO {
                id: Uuid::new_v4(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                key: "claim1".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                array: Some(false),
                claims: vec![],
            }],
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            schema_id: "http://example.com/schema".to_string(),
            layout_type: Some(LayoutType::Card),
            layout_properties: None,
            imported_source_url: "http://source.com".to_string(),
            allow_suspension: Some(true),
        },
    };

    // when
    let result = parser.parse_import_credential_schema(request);

    // then
    let_assert!(Ok(schema) = result);
    assert!("Imported Schema" == schema.name);
    assert!("JWT" == schema.format);
}

#[test]
fn test_parse_import_with_nested_claims_success() {
    // given
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut formatter = MockCredentialFormatter::default();

    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);

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
        .return_once(|_| Some(Arc::new(revocation_method)));

    let parser = setup_parser(
        generic_config().core,
        formatter_provider,
        revocation_method_provider,
    );

    let request = ImportCredentialSchemaRequestDTO {
        organisation: dummy_organisation(None),
        schema: ImportCredentialSchemaRequestSchemaDTO {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "Imported Schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4(),
            claims: vec![ImportCredentialSchemaClaimSchemaDTO {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                key: "address".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                array: Some(false),
                claims: vec![ImportCredentialSchemaClaimSchemaDTO {
                    id: Uuid::new_v4(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    key: "street".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: Some(false),
                    claims: vec![],
                }],
            }],
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            schema_id: "http://example.com/schema".to_string(),
            layout_type: Some(LayoutType::Card),
            layout_properties: None,
            imported_source_url: "http://source.com".to_string(),
            allow_suspension: Some(true),
        },
    };

    // when
    let result = parser.parse_import_credential_schema(request);

    // then
    let_assert!(Ok(schema) = result);
    let_assert!(Some(claim_schemas) = schema.claim_schemas);
    assert!(2 == claim_schemas.len())
}

#[tokio::test]
async fn test_importer_import_credential_schema_success() {
    // given
    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "http://source.com".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        name: "Test Schema".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "claim1".to_string(),
                data_type: "STRING".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
                metadata: false,
            },
            required: true,
        }]),
        organisation: Some(dummy_organisation(None)),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://example.com/schema".to_string(),
        allow_suspension: true,
        requires_app_attestation: false,
    };
    let credential_schema_id = credential_schema.id;

    let mut repository = MockCredentialSchemaRepository::default();
    repository
        .expect_get_credential_schema_list()
        .once()
        .returning(|_, _| {
            Ok(GetCredentialSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });
    repository
        .expect_create_credential_schema()
        .once()
        .return_once(move |_| Ok(credential_schema_id));

    let mut formatter = MockCredentialFormatter::default();
    formatter.expect_get_metadata_claims().returning(Vec::new);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let importer =
        CredentialSchemaImporterProto::new(Arc::new(formatter_provider), Arc::new(repository));

    // when
    let result = importer.import_credential_schema(credential_schema).await;

    // then
    let_assert!(Ok(_) = result);
}

#[tokio::test]
async fn test_importer_import_credential_schema_success_duplicate_name() {
    // given
    let mut existing_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "http://source.com".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        name: "Existing Schema".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(vec![]),
        organisation: Some(dummy_organisation(None)),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://example.com/schema".to_string(),
        allow_suspension: true,
        requires_app_attestation: false,
    };

    let existing_schema_clone = existing_schema.clone();
    let mut repository = MockCredentialSchemaRepository::default();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_, _| {
            Ok(GetCredentialSchemaList {
                values: vec![existing_schema_clone],
                total_pages: 0,
                total_items: 1,
            })
        });
    repository
        .expect_create_credential_schema()
        .once()
        .returning(move |_| Ok(existing_schema.id));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .returning(FormatterCapabilities::default);
    formatter.expect_get_metadata_claims().returning(Vec::new);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let importer =
        CredentialSchemaImporterProto::new(Arc::new(formatter_provider), Arc::new(repository));

    existing_schema.schema_id = "http://different.com/schema".to_string();

    // when
    let result = importer
        .import_credential_schema(existing_schema.clone())
        .await;

    // then
    let_assert!(Ok(_) = result);
}

#[tokio::test]
async fn test_importer_import_credential_schema_failure_duplicate_schema_id() {
    // given
    let existing_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "http://source.com".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        name: "Existing Schema".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(vec![]),
        organisation: Some(dummy_organisation(None)),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://example.com/schema".to_string(),
        allow_suspension: true,
        requires_app_attestation: false,
    };

    let existing_schema_clone = existing_schema.clone();
    let mut repository = MockCredentialSchemaRepository::default();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_, _| {
            Ok(GetCredentialSchemaList {
                values: vec![existing_schema_clone],
                total_pages: 0,
                total_items: 1,
            })
        });

    let importer = CredentialSchemaImporterProto::new(
        Arc::new(MockCredentialFormatterProvider::default()),
        Arc::new(repository),
    );

    // when
    let result = importer
        .import_credential_schema(existing_schema.clone())
        .await;

    // then
    let_assert!(
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::CredentialSchemaAlreadyExists
        )) = result
    );
}
