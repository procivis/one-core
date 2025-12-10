use std::sync::Arc;

use mockall::PredicateBooleanExt;
use mockall::predicate::*;
use serde_json::json;
use shared_types::{CredentialSchemaId, OrganisationId, ProofSchemaId};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofSchemaService;
use crate::config::core_config::{
    ConfigEntryDisplay, CoreConfig, KeySecurityLevelFields, KeySecurityLevelType, RevocationType,
};
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::common::GetListResponse;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, GetCredentialSchemaList,
    KeyStorageSecurity, LayoutType,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof_schema::{
    GetProofSchemaList, ProofInputClaimSchema, ProofInputSchema, ProofInputSchemaRelations,
    ProofSchema, ProofSchemaRelations,
};
use crate::proto::credential_schema::importer::{
    CredentialSchemaImporterProto, MockCredentialSchemaImporter,
};
use crate::proto::credential_schema::parser::{
    CredentialSchemaImportParserImpl, MockCredentialSchemaImportParser,
};
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, SessionProvider};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    Features, FormatterCapabilities, SelectiveDisclosure,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::RevocationMethodCapabilities;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::error::DataLayerError;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::proof_schema::ProofSchemaImportError;
use crate::service::proof_schema::dto::{
    CreateProofSchemaClaimRequestDTO, CreateProofSchemaRequestDTO, GetProofSchemaQueryDTO,
    ImportProofSchemaClaimSchemaDTO, ImportProofSchemaCredentialSchemaDTO, ImportProofSchemaDTO,
    ImportProofSchemaInputSchemaDTO, ImportProofSchemaRequestDTO, ProofInputSchemaRequestDTO,
    ProofSchemaFilterValue,
};
use crate::service::test_utilities::{
    dummy_credential_schema, dummy_organisation, dummy_proof_schema, generic_config,
    generic_formatter_capabilities, get_dummy_date,
};

const IMPORT_URL: &str = "http://import.credential.schema";

#[derive(Default)]
struct Repositories {
    pub proof_schema_repository: MockProofSchemaRepository,
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub organisation_repository: MockOrganisationRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub config: Option<CoreConfig>,
    pub session_provider: Option<Arc<dyn SessionProvider>>,
}

fn setup_service(repositories: Repositories) -> ProofSchemaService {
    let formatter_provider = Arc::new(repositories.formatter_provider);
    let credential_schema_repository = Arc::new(repositories.credential_schema_repository);
    let revocation_method_provider = Arc::new(repositories.revocation_method_provider);
    let config = Arc::new(repositories.config.unwrap_or(generic_config().core));

    ProofSchemaService {
        proof_schema_repository: Arc::new(repositories.proof_schema_repository),
        credential_schema_repository: credential_schema_repository.clone(),
        organisation_repository: Arc::new(repositories.organisation_repository),
        formatter_provider: formatter_provider.clone(),
        config: config.clone(),
        base_url: Some("BASE_URL".to_string()),
        client: Arc::new(MockHttpClient::new()),
        session_provider: repositories
            .session_provider
            .unwrap_or(Arc::new(NoSessionProvider)),

        credential_schema_import_parser: Arc::new(CredentialSchemaImportParserImpl::new(
            config,
            formatter_provider.clone(),
            revocation_method_provider,
        )),
        credential_schema_importer: Arc::new(CredentialSchemaImporterProto::new(
            formatter_provider,
            credential_schema_repository,
        )),
    }
}

#[tokio::test]
async fn test_get_proof_schema_exists() {
    let proof_schema = generic_proof_schema();

    let service = setup_service(Repositories {
        proof_schema_repository: proof_schema_repo_expecting_get(proof_schema.clone()),
        ..Default::default()
    });

    let result = service.get_proof_schema(&proof_schema.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, proof_schema.id);
    assert_eq!(result.expire_duration, 0);
    assert_eq!(result.name, proof_schema.name);
}

#[tokio::test]
async fn test_get_proof_schema_deleted() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = ProofSchema {
        deleted_at: Some(OffsetDateTime::now_utc()),
        ..generic_proof_schema()
    };
    {
        let res_clone = proof_schema.clone();
        proof_schema_repository
            .expect_get_proof_schema()
            .returning(move |_id, _relations| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(Repositories {
        proof_schema_repository,
        ..Default::default()
    });

    let result = service.get_proof_schema(&proof_schema.id).await;

    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::EntityNotFound(EntityNotFoundError::ProofSchema(_))
    )));
}

#[tokio::test]
async fn test_get_proof_schema_missing() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .returning(|_id, _relations| Ok(None));

    let service = setup_service(Repositories {
        proof_schema_repository,
        ..Default::default()
    });

    let result = service.get_proof_schema(&Uuid::new_v4().into()).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::EntityNotFound(EntityNotFoundError::ProofSchema(_))
    )));
}

#[tokio::test]
async fn test_get_proof_schema_list_success() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = ProofSchema {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        imported_source_url: Some("CORE_URL".to_string()),
        deleted_at: None,
        name: "name".to_string(),
        expire_duration: 0,
        organisation: None,
        input_schemas: None,
    };
    {
        let res_clone = proof_schema.clone();
        proof_schema_repository
            .expect_get_proof_schema_list()
            .times(1)
            .returning(move |_| {
                Ok(GetProofSchemaList {
                    values: vec![res_clone.clone()],
                    total_pages: 1,
                    total_items: 1,
                })
            });
    }

    let service = setup_service(Repositories {
        proof_schema_repository,
        ..Default::default()
    });

    let organisation_id = Uuid::new_v4().into();
    let query = GetProofSchemaQueryDTO {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
        ..Default::default()
    };
    let result = service.get_proof_schema_list(&organisation_id, query).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 1);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, proof_schema.id);
    assert_eq!(result.values[0].expire_duration, 0);
    assert_eq!(result.values[0].name, proof_schema.name);
}

#[tokio::test]
async fn test_get_proof_schema_list_failure() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema_list()
        .times(1)
        .returning(|_| Err(anyhow::anyhow!("test").into()));

    let service = setup_service(Repositories {
        proof_schema_repository,
        ..Default::default()
    });

    let organisation_id = Uuid::new_v4().into();
    let query = GetProofSchemaQueryDTO {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
        ..Default::default()
    };
    let result = service.get_proof_schema_list(&organisation_id, query).await;

    assert!(matches!(
        result,
        Err(ServiceError::Repository(DataLayerError::Db(_)))
    ));
}

#[tokio::test]
async fn test_delete_proof_schema_success() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    proof_schema_repository
        .expect_get_proof_schema()
        .returning(|_, _| {
            Ok(Some(ProofSchema {
                id: Uuid::new_v4().into(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "name".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: None,
            }))
        });

    let proof_schema_id: ProofSchemaId = Uuid::new_v4().into();
    proof_schema_repository
        .expect_delete_proof_schema()
        .times(1)
        .with(
            eq(proof_schema_id.to_owned()),
            // deletion will happen shortly after
            ge(OffsetDateTime::now_utc())
                .and(lt(OffsetDateTime::now_utc() + time::Duration::SECOND)),
        )
        .returning(|_, _| Ok(()));

    let service = setup_service(Repositories {
        proof_schema_repository,
        ..Default::default()
    });

    let result = service.delete_proof_schema(&proof_schema_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_proof_schema_failure() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    proof_schema_repository
        .expect_get_proof_schema()
        .returning(|_, _| {
            Ok(Some(ProofSchema {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                imported_source_url: Some("CORE_URL".to_string()),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "name".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: None,
            }))
        });

    proof_schema_repository
        .expect_delete_proof_schema()
        .times(1)
        .returning(|_, _| Err(DataLayerError::RecordNotUpdated));

    let service = setup_service(Repositories {
        proof_schema_repository,
        ..Default::default()
    });

    let result = service.delete_proof_schema(&Uuid::new_v4().into()).await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::MissingProofSchema { .. }
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_schema_success() {
    let claim_schema_id = Uuid::new_v4().into();
    let claim_schema = ClaimSchema {
        id: claim_schema_id,
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_, _| {
            let schema = CredentialSchema {
                id: credential_schema_id,
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "credential-schema".to_string(),
                imported_source_url: "CORE_URL".to_string(),
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: None,
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: claim_schema.clone(),
                    required: false,
                }]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: Some(0),
        organisation_id,
        proof_input_schemas: vec![ProofInputSchemaRequestDTO {
            claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                id: claim_schema_id,
                required: true,
            }],
            credential_schema_id,
            validity_constraint: None,
        }],
    };

    let create_request_clone = create_request.clone();
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = generic_proof_schema();

    proof_schema_repository
        .expect_get_proof_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetProofSchemaList {
                values: vec![proof_schema.clone()],
                total_pages: 0,
                total_items: 0,
            })
        });

    proof_schema_repository
        .expect_create_proof_schema()
        .times(1)
        .withf(move |proof_schema| {
            let input_schemas = proof_schema.input_schemas.as_ref().unwrap();
            assert_eq!(1, input_schemas.len());

            let claim_schemas = input_schemas[0].claim_schemas.as_ref().unwrap();
            claim_schemas.len() == 1
                && claim_schemas[0].schema.id == claim_schema_id
                && proof_schema.organisation.as_ref().unwrap().id == organisation_id
                && proof_schema.name == create_request_clone.name
                && proof_schema.expire_duration == create_request_clone.expire_duration.unwrap()
        })
        .returning(|request| Ok(request.id));

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
        ..Default::default()
    });

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_proof_schema_success_mixed_key_storage_security_types() {
    let mut config = generic_config();
    config.core.key_security_level.insert(
        KeySecurityLevelType::Moderate,
        KeySecurityLevelFields {
            display: ConfigEntryDisplay::TranslationId("moderate".to_string()),
            order: None,
            enabled: Some(true),
            capabilities: None,
            params: None,
        },
    );
    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let claim_schema_software_id = Uuid::new_v4().into();
    let claim_schema_software = ClaimSchema {
        id: claim_schema_software_id,
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let claim_schema_hardware_id = Uuid::new_v4().into();
    let claim_schema_hardware = ClaimSchema {
        id: claim_schema_hardware_id,
        ..claim_schema_software.clone()
    };

    let credential_schema_software_id: CredentialSchemaId = Uuid::new_v4().into();
    let credential_schema_hardware_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(move |_, _| {
            let schema_software = CredentialSchema {
                id: credential_schema_software_id,
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "software".to_string(),
                imported_source_url: "CORE_URL".to_string(),
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Basic),
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: claim_schema_software.clone(),
                    required: false,
                }]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "software".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            };

            let schema_hardware = CredentialSchema {
                id: credential_schema_hardware_id,
                name: "hardware".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "hardware".to_owned(),
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: claim_schema_hardware.clone(),
                    required: false,
                }]),
                ..schema_software.clone()
            };

            Ok(GetListResponse {
                values: vec![schema_software, schema_hardware],
                total_pages: 1,
                total_items: 2,
            })
        });

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema_list()
        .once()
        .returning(move |_| {
            Ok(GetProofSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    proof_schema_repository
        .expect_create_proof_schema()
        .times(1)
        .returning(|schema| Ok(schema.id));

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: Some(0),
        organisation_id,
        proof_input_schemas: vec![
            ProofInputSchemaRequestDTO {
                claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                    id: claim_schema_software_id,
                    required: true,
                }],
                credential_schema_id: credential_schema_software_id,
                validity_constraint: None,
            },
            ProofInputSchemaRequestDTO {
                claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                    id: claim_schema_hardware_id,
                    required: true,
                }],
                credential_schema_id: credential_schema_hardware_id,
                validity_constraint: None,
            },
        ],
    };

    let mut capabilities = generic_formatter_capabilities();
    capabilities
        .features
        .push(Features::SupportsCombinedPresentation);
    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .returning(move || capabilities.clone());
    let formatter = Arc::new(formatter);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(formatter.clone()));

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
        config: Some(config.core),
        ..Default::default()
    });

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_ok())
}

#[tokio::test]
async fn test_create_proof_schema_fail_unsupported_wallet_storage_type() {
    let claim_schema_id = Uuid::new_v4().into();
    let claim_schema = ClaimSchema {
        id: claim_schema_id,
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_, _| {
            let schema = CredentialSchema {
                id: credential_schema_id,
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "credential-schema".to_string(),
                imported_source_url: "CORE_URL".to_string(),
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::EnhancedBasic),
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: claim_schema.clone(),
                    required: false,
                }]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: Some(0),
        organisation_id,
        proof_input_schemas: vec![ProofInputSchemaRequestDTO {
            claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                id: claim_schema_id,
                required: true,
            }],
            credential_schema_id,
            validity_constraint: None,
        }],
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetProofSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        config: Some(generic_config().core),
        ..Default::default()
    });

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::Validation(ValidationError::KeyStorageSecurityDisabled(
            KeyStorageSecurity::EnhancedBasic
        ))
    )));
}

#[tokio::test]
async fn test_create_proof_schema_fail_validity_constraint_out_of_range() {
    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: Some(0),
        organisation_id: Uuid::new_v4().into(),
        proof_input_schemas: vec![ProofInputSchemaRequestDTO {
            claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                id: Uuid::new_v4().into(),
                required: true,
            }],
            credential_schema_id: Uuid::new_v4().into(),
            validity_constraint: Some(9007199254740991),
        }],
    };

    let service = setup_service(Default::default());

    let result = service.create_proof_schema(create_request).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::ValidityConstraintOutOfRange
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_schema_with_physical_card_multiple_schemas_fail() {
    let claim_schema_id = Uuid::new_v4().into();
    let claim_schema = ClaimSchema {
        id: claim_schema_id,
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let claim_schema_id_2 = Uuid::new_v4().into();
    let claim_schem_2 = ClaimSchema {
        id: claim_schema_id_2,
        key: "key1".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let credential_schema_id_2: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_, _| {
            let schema = CredentialSchema {
                id: credential_schema_id,
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "credential-schema".to_string(),
                imported_source_url: "CORE_URL".to_string(),
                format: "PHYSICAL_CARD".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: None,
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: claim_schema.clone(),
                    required: false,
                }]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            };

            let schema_2 = CredentialSchema {
                id: credential_schema_id_2,
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "credential-schema-2".to_string(),
                imported_source_url: "CORE_URL".to_string(),
                format: "PHYSICAL_CARD".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: None,
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: claim_schem_2.clone(),
                    required: false,
                }]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            };

            Ok(GetListResponse {
                values: vec![schema, schema_2],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: Some(0),
        organisation_id,
        proof_input_schemas: vec![
            ProofInputSchemaRequestDTO {
                claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                    id: claim_schema_id,
                    required: true,
                }],
                credential_schema_id,
                validity_constraint: None,
            },
            ProofInputSchemaRequestDTO {
                claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                    id: claim_schema_id_2,
                    required: true,
                }],
                credential_schema_id: credential_schema_id_2,
                validity_constraint: None,
            },
        ],
    };
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = generic_proof_schema();

    proof_schema_repository
        .expect_get_proof_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetProofSchemaList {
                values: vec![proof_schema.clone()],
                total_pages: 0,
                total_items: 0,
            })
        });

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
        ..Default::default()
    });

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::Validation(ValidationError::ProofSchemaInvalidCredentialCombination { .. })
    )));
}

#[tokio::test]
async fn test_create_proof_schema_array_object_fail() {
    let claim_schema_root = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let claim_schema_array = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: true,
        metadata: false,
    };

    let claim_schema_array_object = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let claim_schema_array_object_item = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0/item".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let claim_id = claim_schema_array_object_item.id;
    let mut capabilities = generic_formatter_capabilities();
    capabilities.features = vec![Features::SelectiveDisclosure];
    capabilities.selective_disclosure = vec![SelectiveDisclosure::AnyLevel];

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(move || capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_, _| {
            let schema = CredentialSchema {
                id: credential_schema_id,
                imported_source_url: "CORE_URL".to_string(),
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "credential-schema".to_string(),
                format: "SD_JWT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: None,
                claim_schemas: Some(vec![
                    CredentialSchemaClaim {
                        schema: claim_schema_root.clone(),
                        required: false,
                    },
                    CredentialSchemaClaim {
                        schema: claim_schema_array.clone(),
                        required: false,
                    },
                    CredentialSchemaClaim {
                        schema: claim_schema_array_object.clone(),
                        required: false,
                    },
                    CredentialSchemaClaim {
                        schema: claim_schema_array_object_item.clone(),
                        required: false,
                    },
                ]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: Some(0),
        organisation_id,
        proof_input_schemas: vec![ProofInputSchemaRequestDTO {
            claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                id: claim_id,
                required: true,
            }],
            credential_schema_id,
            validity_constraint: None,
        }],
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = generic_proof_schema();

    proof_schema_repository
        .expect_get_proof_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetProofSchemaList {
                values: vec![proof_schema.clone()],
                total_pages: 0,
                total_items: 0,
            })
        });

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
        ..Default::default()
    });

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::Validation(ValidationError::NestedClaimInArrayRequested)
    )));
}

#[tokio::test]
async fn test_create_proof_schema_array_success() {
    let claim_schema_root = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let claim_schema_array = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: true,
        metadata: false,
    };

    let claim_schema_array_object = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let claim_schema_array_object_item = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0/item".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
        metadata: false,
    };

    let claim_id = claim_schema_array.id;

    let mut capabilities = generic_formatter_capabilities();
    capabilities.features = vec![Features::SelectiveDisclosure];
    capabilities.selective_disclosure = vec![SelectiveDisclosure::AnyLevel];

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(move || capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_, _| {
            let schema = CredentialSchema {
                id: credential_schema_id,
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                imported_source_url: "CORE_URL".to_string(),
                last_modified: OffsetDateTime::now_utc(),
                name: "credential-schema".to_string(),
                format: "SD_JWT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: None,
                claim_schemas: Some(vec![
                    CredentialSchemaClaim {
                        schema: claim_schema_root.clone(),
                        required: false,
                    },
                    CredentialSchemaClaim {
                        schema: claim_schema_array.clone(),
                        required: false,
                    },
                    CredentialSchemaClaim {
                        schema: claim_schema_array_object.clone(),
                        required: false,
                    },
                    CredentialSchemaClaim {
                        schema: claim_schema_array_object_item.clone(),
                        required: false,
                    },
                ]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: Some(0),
        organisation_id,
        proof_input_schemas: vec![ProofInputSchemaRequestDTO {
            claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                id: claim_id,
                required: true,
            }],
            credential_schema_id,
            validity_constraint: None,
        }],
    };

    let create_request_clone = create_request.clone();
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = generic_proof_schema();

    proof_schema_repository
        .expect_get_proof_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetProofSchemaList {
                values: vec![proof_schema.clone()],
                total_pages: 0,
                total_items: 0,
            })
        });

    proof_schema_repository
        .expect_create_proof_schema()
        .times(1)
        .withf(move |proof_schema| {
            let input_schemas = proof_schema.input_schemas.as_ref().unwrap();
            assert_eq!(1, input_schemas.len());

            let claim_schemas = input_schemas[0].claim_schemas.as_ref().unwrap();
            claim_schemas.len() == 1
                && claim_schemas[0].schema.id == claim_id
                && proof_schema.organisation.as_ref().unwrap().id == organisation_id
                && proof_schema.name == create_request_clone.name
                && proof_schema.expire_duration == create_request_clone.expire_duration.unwrap()
        })
        .returning(|request| Ok(request.id));

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
        ..Default::default()
    });

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_proof_schema_unique_name_error() {
    let claim_schema_id = Uuid::new_v4().into();
    let organisation_id = Uuid::new_v4().into();

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: Some(0),
        organisation_id,
        proof_input_schemas: vec![ProofInputSchemaRequestDTO {
            credential_schema_id: Uuid::new_v4().into(),
            validity_constraint: None,
            claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                id: claim_schema_id,
                required: true,
            }],
        }],
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = generic_proof_schema();

    proof_schema_repository
        .expect_get_proof_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetProofSchemaList {
                values: vec![proof_schema.clone()],
                total_pages: 1,
                total_items: 1,
            })
        });

    let service = setup_service(Repositories {
        proof_schema_repository,
        ..Default::default()
    });

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::ProofSchemaAlreadyExists)
    )));
}

#[tokio::test]
async fn test_create_proof_schema_claims_dont_exist() {
    let claim_schema_id = Uuid::new_v4().into();
    let credential_schema_id = Uuid::new_v4().into();

    let formatter = MockCredentialFormatter::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_, _| {
            let schema = CredentialSchema {
                id: credential_schema_id,
                imported_source_url: "CORE_URL".to_string(),
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "credential-schema".to_string(),
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: None,
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "key".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
                        metadata: false,
                    },
                    required: false,
                }]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let proof_schema = generic_proof_schema();

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetProofSchemaList {
                values: vec![proof_schema.clone()],
                total_pages: 0,
                total_items: 0,
            })
        });

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(move |_, _| Ok(Some(dummy_organisation(None))));

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
        ..Default::default()
    });

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: Some(0),
            organisation_id,
            proof_input_schemas: vec![ProofInputSchemaRequestDTO {
                credential_schema_id,
                validity_constraint: None,
                claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                    id: claim_schema_id,
                    required: true,
                }],
            }],
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::MissingClaimSchema { .. }
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_schema_no_claims() {
    let service = setup_service(Default::default());

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: Some(0),
            organisation_id: Uuid::new_v4().into(),
            proof_input_schemas: vec![ProofInputSchemaRequestDTO {
                credential_schema_id: Uuid::new_v4().into(),
                validity_constraint: None,
                claim_schemas: vec![],
            }],
        })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::ProofSchemaMissingClaims
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_schema_no_required_claims() {
    let service = setup_service(Default::default());

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: Some(0),
            organisation_id: Uuid::new_v4().into(),
            proof_input_schemas: vec![ProofInputSchemaRequestDTO {
                credential_schema_id: Uuid::new_v4().into(),
                validity_constraint: None,
                claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                    id: Uuid::new_v4().into(),
                    required: false,
                }],
            }],
        })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::ProofSchemaNoRequiredClaim
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_schema_duplicit_claims() {
    let service = setup_service(Default::default());

    let claim_schema = CreateProofSchemaClaimRequestDTO {
        id: Uuid::new_v4().into(),
        required: true,
    };
    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: Some(0),
            organisation_id: Uuid::new_v4().into(),
            proof_input_schemas: vec![ProofInputSchemaRequestDTO {
                credential_schema_id: Uuid::new_v4().into(),
                validity_constraint: None,
                claim_schemas: vec![claim_schema.clone(), claim_schema],
            }],
        })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::ProofSchemaDuplicitClaim
        ))
    ));
}

#[tokio::test]
async fn test_import_proof_schema_ok_for_new_credential_schema() {
    let now = OffsetDateTime::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id), always())
        .return_once(move |_, _| Ok(Some(dummy_organisation(Some(organisation_id)))));

    let mut proof_schema_repository = MockProofSchemaRepository::new();
    proof_schema_repository
        .expect_get_proof_schema_list()
        .returning(|_| {
            Ok(GetProofSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });
    proof_schema_repository
        .expect_create_proof_schema()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .withf(move |schema_id, org, relations| {
            schema_id == "iso-org-test123"
                && org == &organisation_id
                && relations.claim_schemas.is_some()
        })
        .once()
        .returning(|_, _, _| Ok(None));
    credential_schema_repository
        .expect_create_credential_schema()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(|_, _| {
            Ok(GetCredentialSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        imported_source_url: "CORE_URL".to_string(),
        name: "test-proof-schema".to_string(),
        organisation_id,
        expire_duration: 1000,
        proof_input_schemas: vec![ImportProofSchemaInputSchemaDTO {
            claim_schemas: vec![ImportProofSchemaClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                requested: true,
                required: true,
                key: "field".to_string(),
                data_type: "STRING".to_string(),
                claims: vec![],
                array: false,
            }],
            credential_schema: ImportProofSchemaCredentialSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                imported_source_url: "http://import.credential.schema".to_string(),
                last_modified: now,
                name: "test-credential-schema".to_string(),
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_type: None,
                layout_properties: None,
            },
            validity_constraint: None,
        }],
    };

    let mut http_client = MockHttpClient::new();
    http_client
        .expect_get()
        .once()
        .with(eq(IMPORT_URL))
        .returning(|url| {
            let mut inner_client = MockHttpClient::new();
            inner_client.expect_send().once().returning(|_, _, _, _| {
                Ok(Response {
                    body: json!({
                        "createdDate": "2023-06-09T14:19:57.000Z",
                        "lastModified": "2023-06-09T14:19:57.000Z",
                        "format": "JWT",
                        "id": Uuid::new_v4(),
                        "importedSourceUrl": "http://import.credential.schema",
                        "name": "test-credential-schema",
                        "organisationId": Uuid::new_v4(),
                        "revocationMethod": "NONE",
                        "schemaId": "iso-org-test123",
                        "schemaType": "ProcivisOneSchema2024",
                        "walletStorageType": "HARDWARE",
                        "allowSuspension": false,
                        "claims": [{
                            "array": false,
                            "createdDate": "2023-06-09T14:19:57.000Z",
                            "lastModified": "2023-06-09T14:19:57.000Z",
                            "datatype": "STRING",
                            "id": Uuid::new_v4(),
                            "key": "field",
                            "required": true
                        }]

                    })
                    .to_string()
                    .as_bytes()
                    .to_vec(),
                    headers: Default::default(),
                    status: StatusCode(200),
                    request: Request {
                        body: None,
                        headers: Default::default(),
                        method: Method::Get,
                        url: IMPORT_URL.to_string(),
                    },
                })
            });

            RequestBuilder::new(Arc::new(inner_client), Method::Get, url)
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq("JWT"))
        .returning(move |_| Some(formatter.clone()));

    let mut revocation_method = MockRevocationMethod::new();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities { operations: vec![] });
    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq("NONE"))
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let formatter_provider = Arc::new(formatter_provider);
    let credential_schema_repository = Arc::new(credential_schema_repository);
    let revocation_method_provider = Arc::new(revocation_method_provider);
    let config = Arc::new(generic_config().core);

    let service = ProofSchemaService {
        proof_schema_repository: Arc::new(proof_schema_repository),
        credential_schema_repository: credential_schema_repository.clone(),
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider: formatter_provider.clone(),
        config: Arc::new(generic_config().core),
        base_url: None,
        client: Arc::new(http_client),
        session_provider: Arc::new(NoSessionProvider),
        credential_schema_import_parser: Arc::new(CredentialSchemaImportParserImpl::new(
            config.clone(),
            formatter_provider.clone(),
            revocation_method_provider.clone(),
        )),
        credential_schema_importer: Arc::new(CredentialSchemaImporterProto::new(
            formatter_provider,
            credential_schema_repository,
        )),
    };

    service
        .import_proof_schema(ImportProofSchemaRequestDTO {
            schema,
            organisation_id,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_import_proof_ok_existing_but_deleted_credential_schema() {
    let now = OffsetDateTime::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id), always())
        .return_once(move |_, _| Ok(Some(dummy_organisation(Some(organisation_id)))));

    let mut proof_schema_repository = MockProofSchemaRepository::new();
    proof_schema_repository
        .expect_get_proof_schema_list()
        .returning(|_| {
            Ok(GetProofSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });
    proof_schema_repository
        .expect_create_proof_schema()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .withf(move |schema_id, org, relations| {
            schema_id == "iso-org-test123"
                && org == &organisation_id
                && relations.claim_schemas.is_some()
        })
        .once()
        .returning(|_, _, _| {
            Ok(Some(CredentialSchema {
                deleted_at: Some(get_dummy_date()),
                ..dummy_credential_schema()
            }))
        });
    credential_schema_repository
        .expect_create_credential_schema()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(|_, _| {
            Ok(GetCredentialSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        imported_source_url: "CORE_URL".to_string(),
        created_date: now,
        last_modified: now,
        name: "test-proof-schema".to_string(),
        organisation_id,
        expire_duration: 1000,
        proof_input_schemas: vec![ImportProofSchemaInputSchemaDTO {
            claim_schemas: vec![ImportProofSchemaClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                requested: true,
                required: true,
                key: "field".to_string(),
                data_type: "STRING".to_string(),
                claims: vec![],
                array: false,
            }],
            credential_schema: ImportProofSchemaCredentialSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                imported_source_url: "http://import.credential.schema".to_string(),
                last_modified: now,
                name: "test-credential-schema".to_string(),
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_type: None,
                layout_properties: None,
            },
            validity_constraint: None,
        }],
    };

    let mut http_client = MockHttpClient::new();
    http_client
        .expect_get()
        .once()
        .with(eq(IMPORT_URL))
        .returning(|url| {
            let mut inner_client = MockHttpClient::new();
            inner_client.expect_send().once().returning(|_, _, _, _| {
                Ok(Response {
                    body: json!({
                        "createdDate": "2023-06-09T14:19:57.000Z",
                        "lastModified": "2023-06-09T14:19:57.000Z",
                        "format": "JWT",
                        "id": Uuid::new_v4(),
                        "importedSourceUrl": "http://import.credential.schema",
                        "name": "test-credential-schema",
                        "organisationId": Uuid::new_v4(),
                        "revocationMethod": "NONE",
                        "schemaId": "iso-org-test123",
                        "schemaType": "ProcivisOneSchema2024",
                        "walletStorageType": "HARDWARE",
                        "allowSuspension": false,
                        "claims": [{
                            "array": false,
                            "createdDate": "2023-06-09T14:19:57.000Z",
                            "lastModified": "2023-06-09T14:19:57.000Z",
                            "datatype": "STRING",
                            "id": Uuid::new_v4(),
                            "key": "field",
                            "required": true
                        }]

                    })
                    .to_string()
                    .as_bytes()
                    .to_vec(),
                    headers: Default::default(),
                    status: StatusCode(200),
                    request: Request {
                        body: None,
                        headers: Default::default(),
                        method: Method::Get,
                        url: crate::service::proof_schema::test::IMPORT_URL.to_string(),
                    },
                })
            });

            RequestBuilder::new(Arc::new(inner_client), Method::Get, url)
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq("JWT"))
        .returning(move |_| Some(formatter.clone()));

    let mut revocation_method = MockRevocationMethod::new();
    revocation_method
        .expect_get_capabilities()
        .returning(|| RevocationMethodCapabilities { operations: vec![] });
    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq("NONE"))
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let formatter_provider = Arc::new(formatter_provider);
    let credential_schema_repository = Arc::new(credential_schema_repository);
    let revocation_method_provider = Arc::new(revocation_method_provider);
    let config = Arc::new(generic_config().core);

    let service = ProofSchemaService {
        proof_schema_repository: Arc::new(proof_schema_repository),
        credential_schema_repository: credential_schema_repository.clone(),
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider: formatter_provider.clone(),
        config: config.clone(),
        base_url: None,
        client: Arc::new(http_client),
        session_provider: Arc::new(NoSessionProvider),
        credential_schema_import_parser: Arc::new(CredentialSchemaImportParserImpl::new(
            config.clone(),
            formatter_provider.clone(),
            revocation_method_provider.clone(),
        )),
        credential_schema_importer: Arc::new(CredentialSchemaImporterProto::new(
            formatter_provider,
            credential_schema_repository,
        )),
    };

    service
        .import_proof_schema(ImportProofSchemaRequestDTO {
            schema,
            organisation_id,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_import_proof_ok_existing_credential_schema_all_claims_present() {
    let now = OffsetDateTime::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id), always())
        .return_once(move |_, _| Ok(Some(dummy_organisation(Some(organisation_id)))));

    let mut proof_schema_repository = MockProofSchemaRepository::new();
    proof_schema_repository
        .expect_get_proof_schema_list()
        .returning(|_| {
            Ok(GetProofSchemaList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });
    proof_schema_repository
        .expect_create_proof_schema()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();

    let existing_schema_id = Uuid::new_v4().into();

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .withf(move |schema_id, org, relations| {
            schema_id == "iso-org-test123"
                && org == &organisation_id
                && relations.claim_schemas.is_some()
        })
        .once()
        .returning(move |_, _, _| {
            Ok(Some(CredentialSchema {
                id: existing_schema_id,
                deleted_at: None,
                created_date: get_dummy_date(),
                imported_source_url: "CORE_URL".to_string(),
                last_modified: get_dummy_date(),
                name: "test-credential-schema".to_string(),
                format: "MDOC".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "iso-org-test123".to_string(),
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "root/name".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: get_dummy_date(),
                        array: false,
                        last_modified: get_dummy_date(),
                        metadata: false,
                    },
                    required: true,
                }]),
                organisation: None,
                allow_suspension: true,
                requires_app_attestation: false,
            }))
        });

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        imported_source_url: "CORE_URL".to_string(),
        last_modified: now,
        name: "test-proof-schema".to_string(),
        organisation_id,
        expire_duration: 1000,
        proof_input_schemas: vec![ImportProofSchemaInputSchemaDTO {
            claim_schemas: vec![ImportProofSchemaClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                requested: false,
                required: false,
                key: "root".to_string(),
                data_type: "OBJECT".to_string(),
                claims: vec![ImportProofSchemaClaimSchemaDTO {
                    id: Uuid::new_v4().into(),
                    requested: true,
                    required: true,
                    key: "name".to_string(),
                    data_type: "STRING".to_string(),
                    claims: vec![],
                    array: false,
                }],
                array: false,
            }],
            credential_schema: ImportProofSchemaCredentialSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                imported_source_url: "CORE_URL".to_string(),
                last_modified: now,
                name: "test-credential-schema".to_string(),
                format: "MDOC".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_type: None,
                layout_properties: None,
            },
            validity_constraint: None,
        }],
    };

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![RevocationType::None],
            features: vec![Features::SelectiveDisclosure],
            selective_disclosure: vec![SelectiveDisclosure::SecondLevel],
            ..Default::default()
        });

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq("MDOC"))
        .return_once(move |_| Some(Arc::new(formatter)));

    let formatter_provider = Arc::new(formatter_provider);
    let credential_schema_repository = Arc::new(credential_schema_repository);
    let import_parser = CredentialSchemaImportParserImpl::new(
        Arc::new(generic_config().core),
        formatter_provider.clone(),
        Arc::new(MockRevocationMethodProvider::new()),
    );

    let importer = CredentialSchemaImporterProto::new(
        formatter_provider.clone(),
        credential_schema_repository.clone(),
    );

    let service = ProofSchemaService {
        proof_schema_repository: Arc::new(proof_schema_repository),
        credential_schema_repository,
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider,
        config: Arc::new(generic_config().core),
        base_url: None,
        client: Arc::new(MockHttpClient::new()),
        session_provider: Arc::new(NoSessionProvider),
        credential_schema_import_parser: Arc::new(import_parser),
        credential_schema_importer: Arc::new(importer),
    };

    service
        .import_proof_schema(ImportProofSchemaRequestDTO {
            schema,
            organisation_id,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_import_proof_failed_existing_proof_schema() {
    let now = OffsetDateTime::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id), always())
        .return_once(move |_, _| Ok(Some(dummy_organisation(Some(organisation_id)))));

    let mut proof_schema_repository = MockProofSchemaRepository::new();
    proof_schema_repository
        .expect_get_proof_schema_list()
        .returning(|_| {
            Ok(GetProofSchemaList {
                values: vec![dummy_proof_schema()],
                total_pages: 1,
                total_items: 1,
            })
        });

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        imported_source_url: "CORE_URL".to_string(),
        name: "test-proof-schema".to_string(),
        organisation_id,
        expire_duration: 1000,
        proof_input_schemas: vec![ImportProofSchemaInputSchemaDTO {
            claim_schemas: vec![ImportProofSchemaClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                requested: true,
                required: true,
                key: "root/name".to_string(),
                data_type: "STRING".to_string(),
                claims: vec![],
                array: false,
            }],
            credential_schema: ImportProofSchemaCredentialSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                imported_source_url: "CORE_URL".to_string(),
                name: "test-credential-schema".to_string(),
                format: "MDOC".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_type: None,
                layout_properties: None,
            },
            validity_constraint: None,
        }],
    };

    let service = ProofSchemaService {
        proof_schema_repository: Arc::new(proof_schema_repository),
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::new()),
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        config: Arc::new(generic_config().core),
        base_url: None,
        client: Arc::new(MockHttpClient::new()),
        session_provider: Arc::new(NoSessionProvider),
        credential_schema_import_parser: Arc::new(MockCredentialSchemaImportParser::default()),
        credential_schema_importer: Arc::new(MockCredentialSchemaImporter::default()),
    };

    let result = service
        .import_proof_schema(ImportProofSchemaRequestDTO {
            schema,
            organisation_id,
        })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::ProofSchemaAlreadyExists
        ))
    ));
}

#[tokio::test]
async fn test_import_proof_schema_fails_validation_for_unsupported_datatype() {
    let now = OffsetDateTime::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id), always())
        .return_once(move |_, _| Ok(Some(dummy_organisation(Some(organisation_id)))));

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        imported_source_url: "CORE_URL".to_string(),
        name: "test-proof-schema".to_string(),
        organisation_id,
        expire_duration: 1000,
        proof_input_schemas: vec![ImportProofSchemaInputSchemaDTO {
            claim_schemas: vec![ImportProofSchemaClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                requested: true,
                required: true,
                key: "root/name".to_string(),
                data_type: "UNSUPPORTED_DATATYPE".to_string(),
                claims: vec![],
                array: false,
            }],
            credential_schema: ImportProofSchemaCredentialSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                imported_source_url: "CORE_URL".to_string(),
                name: "test-credential-schema".to_string(),
                format: "MDOC".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_type: None,
                layout_properties: None,
            },
            validity_constraint: None,
        }],
    };

    let service = setup_service(Repositories {
        organisation_repository,
        ..Default::default()
    });

    let err = service
        .import_proof_schema(ImportProofSchemaRequestDTO {
            schema,
            organisation_id,
        })
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ServiceError::BusinessLogic(BusinessLogicError::ProofSchemaImport(
            ProofSchemaImportError::UnsupportedDatatype(_)
        ))
    ))
}

#[tokio::test]
async fn test_import_proof_schema_fails_validation_for_unsupported_format() {
    let now = OffsetDateTime::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id), always())
        .return_once(move |_, _| Ok(Some(dummy_organisation(Some(organisation_id)))));

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        imported_source_url: "CORE_URL".to_string(),
        name: "test-proof-schema".to_string(),
        organisation_id,
        expire_duration: 1000,
        proof_input_schemas: vec![ImportProofSchemaInputSchemaDTO {
            claim_schemas: vec![ImportProofSchemaClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                requested: true,
                required: true,
                key: "root".to_string(),
                data_type: "UNSUPPORTED_DATATYPE".to_string(),
                claims: vec![],
                array: false,
            }],
            credential_schema: ImportProofSchemaCredentialSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                imported_source_url: "CORE_URL".to_string(),
                name: "test-credential-schema".to_string(),
                format: "OTHER_FORMAT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_type: None,
                layout_properties: None,
            },
            validity_constraint: None,
        }],
    };

    let service = setup_service(Repositories {
        organisation_repository,
        ..Default::default()
    });

    let err = service
        .import_proof_schema(ImportProofSchemaRequestDTO {
            schema,
            organisation_id,
        })
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ServiceError::BusinessLogic(BusinessLogicError::ProofSchemaImport(
            ProofSchemaImportError::UnsupportedFormat(_)
        ))
    ))
}

fn generic_proof_schema() -> ProofSchema {
    ProofSchema {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        imported_source_url: Some("CORE_URL".to_string()),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        name: "name".to_string(),
        expire_duration: 0,
        organisation: Some(dummy_organisation(None)),
        input_schemas: Some(vec![]),
    }
}

#[tokio::test]
async fn test_get_proof_schema_success_nested_claims() {
    let now = OffsetDateTime::now_utc();
    let location_claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
    };
    let location_x_claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/X".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
    };

    let mut proof_schema = generic_proof_schema();
    proof_schema.input_schemas = Some(vec![ProofInputSchema {
        validity_constraint: None,
        claim_schemas: Some(vec![ProofInputClaimSchema {
            schema: location_x_claim_schema.to_owned(),
            required: true,
            order: 0,
        }]),
        credential_schema: Some(credential_schema_with_claims(vec![
            CredentialSchemaClaim {
                schema: location_claim_schema,
                required: true,
            },
            CredentialSchemaClaim {
                schema: location_x_claim_schema.to_owned(),
                required: true,
            },
        ])),
    }]);

    let service = setup_service(Repositories {
        proof_schema_repository: proof_schema_repo_expecting_get(proof_schema.clone()),
        ..Default::default()
    });

    let result = service.get_proof_schema(&proof_schema.id).await.unwrap();
    assert_eq!(result.id, proof_schema.id);
    assert_eq!(1, result.proof_input_schemas.len());
    assert_eq!(1, result.proof_input_schemas[0].claim_schemas.len());
    assert_eq!(
        "location",
        result.proof_input_schemas[0].claim_schemas[0].key
    );
    assert_eq!(
        "X",
        result.proof_input_schemas[0].claim_schemas[0].claims[0].key
    );
}

#[tokio::test]
async fn test_get_proof_schema_success_nested_claims_not_mandatory() {
    let now = OffsetDateTime::now_utc();
    let location_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
    };
    let location_x_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/X".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
    };
    let location_foo_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/foo".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
    };

    let mut proof_schema = generic_proof_schema();
    proof_schema.input_schemas = Some(vec![ProofInputSchema {
        validity_constraint: None,
        claim_schemas: Some(vec![ProofInputClaimSchema {
            schema: location_cs.to_owned(),
            required: true,
            order: 0,
        }]),
        credential_schema: Some(credential_schema_with_claims(vec![
            CredentialSchemaClaim {
                schema: location_cs,
                required: true,
            },
            CredentialSchemaClaim {
                schema: location_x_cs,
                required: true,
            },
            CredentialSchemaClaim {
                schema: location_foo_cs.to_owned(),
                required: false,
            },
        ])),
    }]);

    let service = setup_service(Repositories {
        proof_schema_repository: proof_schema_repo_expecting_get(proof_schema.clone()),
        ..Default::default()
    });

    let result = service.get_proof_schema(&proof_schema.id).await.unwrap();
    assert_eq!(result.id, proof_schema.id);
    assert_eq!(
        "X",
        result.proof_input_schemas[0].claim_schemas[0].claims[0].key
    );
    assert!(result.proof_input_schemas[0].claim_schemas[0].claims[0].required);
    assert_eq!(
        "foo",
        result.proof_input_schemas[0].claim_schemas[0].claims[1].key
    );
    assert!(!result.proof_input_schemas[0].claim_schemas[0].claims[1].required);
}

#[tokio::test]
async fn test_get_proof_schema_success_nested_claims_parent_not_mandatory() {
    let now = OffsetDateTime::now_utc();
    let bar_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "bar".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
    };
    let location_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
    };
    let location_x_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/X".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
    };

    let mut proof_schema = generic_proof_schema();
    proof_schema.input_schemas = Some(vec![ProofInputSchema {
        validity_constraint: None,
        claim_schemas: Some(vec![
            ProofInputClaimSchema {
                schema: bar_cs.to_owned(),
                required: true,
                order: 0,
            },
            ProofInputClaimSchema {
                schema: location_cs.to_owned(),
                required: false,
                order: 1,
            },
        ]),
        credential_schema: Some(credential_schema_with_claims(vec![
            CredentialSchemaClaim {
                schema: bar_cs,
                required: true,
            },
            CredentialSchemaClaim {
                schema: location_cs,
                required: false,
            },
            CredentialSchemaClaim {
                schema: location_x_cs,
                required: true,
            },
        ])),
    }]);

    let service = setup_service(Repositories {
        proof_schema_repository: proof_schema_repo_expecting_get(proof_schema.clone()),
        ..Default::default()
    });

    let result = service.get_proof_schema(&proof_schema.id).await.unwrap();
    assert_eq!(result.id, proof_schema.id);
    assert_eq!("bar", result.proof_input_schemas[0].claim_schemas[0].key);
    assert!(result.proof_input_schemas[0].claim_schemas[0].required);
    assert_eq!(
        "X",
        result.proof_input_schemas[0].claim_schemas[1].claims[0].key
    );
    // not required because parent object is optional
    assert!(!result.proof_input_schemas[0].claim_schemas[1].claims[0].required);
}

fn proof_schema_repo_expecting_get(proof_schema: ProofSchema) -> MockProofSchemaRepository {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .with(
            eq(proof_schema.id.to_owned()),
            eq(ProofSchemaRelations {
                organisation: Some(OrganisationRelations::default()),
                proof_inputs: Some(ProofInputSchemaRelations {
                    claim_schemas: Some(Default::default()),
                    credential_schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        ..Default::default()
                    }),
                }),
            }),
        )
        .returning(move |_id, _relations| Ok(Some(proof_schema.clone())));
    proof_schema_repository
}

fn credential_schema_with_claims(claims: Vec<CredentialSchemaClaim>) -> CredentialSchema {
    let now = OffsetDateTime::now_utc();
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        format: "".to_string(),
        imported_source_url: "CORE_URL".to_string(),
        revocation_method: "".to_string(),
        key_storage_security: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "".to_string(),
        claim_schemas: Some(claims),
        organisation: None,
        allow_suspension: true,
        requires_app_attestation: false,
    }
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_2nd_level_success() {
    let keys = ["root/nested", "root/nested2", "root/nested3"];
    assert!(
        test_create_proof_schema_verify_nested_generic(
            &keys,
            &[Features::SelectiveDisclosure],
            &[SelectiveDisclosure::SecondLevel]
        )
        .await
        .is_ok()
    )
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_2nd_level_fail_3rd_level() {
    let keys = [
        "root/nested",
        "root/nested2",
        "root/nested3/even more nested",
    ];
    assert!(
        test_create_proof_schema_verify_nested_generic(
            &keys,
            &[Features::SelectiveDisclosure],
            &[SelectiveDisclosure::SecondLevel]
        )
        .await
        .is_err_and(|e| e.error_code() == ErrorCode::BR_0130)
    );
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_2nd_level_success_root_level() {
    let keys = ["root/nested", "root", "root/nested3"];
    assert!(
        test_create_proof_schema_verify_nested_generic(
            &keys,
            &[Features::SelectiveDisclosure],
            &[SelectiveDisclosure::SecondLevel]
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_any_level_success() {
    let keys = [
        "root/nested",
        "root",
        "root/nested3",
        "root/nested4/even more nested/with nested claim",
    ];
    assert!(
        test_create_proof_schema_verify_nested_generic(
            &keys,
            &[Features::SelectiveDisclosure],
            &[SelectiveDisclosure::AnyLevel]
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_no_disclosure_fail() {
    let keys = ["root/nested", "root", "root/nested3"];
    assert!(
        test_create_proof_schema_verify_nested_generic(&keys, &[], &[])
            .await
            .is_err_and(|e| e.error_code() == ErrorCode::BR_0130)
    );
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_no_disclosure_success() {
    let keys = ["root1", "root2", "root3"];
    assert!(
        test_create_proof_schema_verify_nested_generic(&keys, &[], &[])
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_create_proof_schema_failure_session_org_mismatch() {
    let service = setup_service(Repositories {
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "".to_string(),
            organisation_id: Uuid::new_v4().into(),
            expire_duration: None,
            proof_input_schemas: vec![],
        })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));

    let result = service
        .import_proof_schema(ImportProofSchemaRequestDTO {
            schema: ImportProofSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "".to_string(),
                organisation_id: Uuid::new_v4().into(),
                expire_duration: 0,
                proof_input_schemas: vec![],
                imported_source_url: "".to_string(),
            },
            organisation_id: Uuid::new_v4().into(),
        })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_list_proof_schema_failure_session_org_mismatch() {
    let service = setup_service(Repositories {
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = service
        .get_proof_schema_list(
            &Uuid::new_v4().into(),
            GetProofSchemaQueryDTO {
                pagination: None,
                sorting: None,
                filtering: None,
                include: None,
            },
        )
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_proof_schema_ops_failure_session_org_mismatch() {
    let proof_schema = generic_proof_schema();
    let schema_id = proof_schema.id;
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .returning(move |_id, _relations| Ok(Some(proof_schema.clone())));

    let service = setup_service(Repositories {
        proof_schema_repository,
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = service.get_proof_schema(&schema_id).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));

    let result = service.delete_proof_schema(&schema_id).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));

    let result = service.share_proof_schema(schema_id).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

async fn test_create_proof_schema_verify_nested_generic(
    keys: &[&str],
    features: &[Features],
    disclosure_features: &[SelectiveDisclosure],
) -> Result<ProofSchemaId, ServiceError> {
    let claim_schemas: Vec<_> = keys
        .iter()
        .map(|key| ClaimSchema {
            id: Uuid::new_v4().into(),
            key: key.to_string(),
            data_type: "OBJECT".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
        })
        .collect();

    let mut formatter_capabilities = generic_formatter_capabilities();
    formatter_capabilities.features = features.to_vec();
    formatter_capabilities.selective_disclosure = disclosure_features.to_vec();

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .returning(move || formatter_capabilities.clone());

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let claim_schemas_cloned = claim_schemas.clone();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_, _| {
            let schema = CredentialSchema {
                id: credential_schema_id,
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "credential-schema".to_string(),
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                key_storage_security: None,
                claim_schemas: Some(
                    claim_schemas_cloned
                        .into_iter()
                        .map(|schema| CredentialSchemaClaim {
                            required: true,
                            schema,
                        })
                        .collect(),
                ),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: Some(0),
        organisation_id,
        proof_input_schemas: vec![ProofInputSchemaRequestDTO {
            claim_schemas: claim_schemas
                .into_iter()
                .map(|schema| CreateProofSchemaClaimRequestDTO {
                    id: schema.id,
                    required: true,
                })
                .collect(),
            credential_schema_id,
            validity_constraint: None,
        }],
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = generic_proof_schema();

    proof_schema_repository
        .expect_get_proof_schema_list()
        .times(1)
        .returning(move |_| {
            Ok(GetProofSchemaList {
                values: vec![proof_schema.clone()],
                total_pages: 0,
                total_items: 0,
            })
        });

    proof_schema_repository
        .expect_create_proof_schema()
        .returning(|request| Ok(request.id));

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
        ..Default::default()
    });

    service.create_proof_schema(create_request).await
}
