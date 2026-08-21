use std::sync::Arc;

use mockall::PredicateBooleanExt;
use mockall::predicate::*;
use serde_json::json;
use shared_types::{CredentialFormat, CredentialSchemaId, OrganisationId, ProofSchemaId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::ProofSchemaService;
use super::dto::{
    CreateProofSchemaClaimRequestDTO, CreateProofSchemaRequestDTO, ImportProofSchemaClaimSchemaDTO,
    ImportProofSchemaCredentialSchemaDTO, ImportProofSchemaDTO, ImportProofSchemaInputSchemaDTO,
    ImportProofSchemaRequestDTO, ProofInputSchemaRequestDTO, ProofSchemaFilterParamsDTO,
};
use super::error::ProofSchemaServiceError;
use crate::config::core_config::{
    ConfigEntryDisplay, CoreConfig, KeySecurityLevelFields, KeySecurityLevelType,
};
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::mapper::credential_schema_claim::backfill_default_translations;
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::GetListResponse;
use crate::model::credential_schema::{
    CredentialSchema, GetCredentialSchemaList, KeyStorageSecurity,
};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::proof_schema::{
    GetProofSchemaList, ProofInputClaimSchema, ProofInputSchema, ProofSchema,
};
use crate::proto::credential_schema::importer::{
    CredentialSchemaImporterProto, MockCredentialSchemaImporter,
};
use crate::proto::credential_schema::parser::{
    CredentialSchemaImportParserImpl, MockCredentialSchemaImportParser,
};
use crate::proto::credential_schema::url_importer::CredentialSchemaUrlImporterProto;
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::proof_schema::importer::ProofSchemaImporterProto;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, SessionProvider};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    Features, FormatterCapabilities, SelectiveDisclosure,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::error::{DataLayerError, EntityKind};
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::service::common_dto::ListQueryDTO;
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
    pub ecosystem_provider: MockEcosystemDirectory,
}

fn setup_service(repositories: Repositories) -> ProofSchemaService {
    let formatter_provider = Arc::new(repositories.formatter_provider);
    let credential_schema_repository = Arc::new(repositories.credential_schema_repository);
    let proof_schema_repository = Arc::new(repositories.proof_schema_repository);
    let revocation_method_provider = Arc::new(repositories.revocation_method_provider);
    let config = Arc::new(repositories.config.unwrap_or(generic_config().core));

    ProofSchemaService {
        proof_schema_repository: proof_schema_repository.clone(),
        credential_schema_repository: credential_schema_repository.clone(),
        organisation_repository: Arc::new(repositories.organisation_repository),
        formatter_provider: formatter_provider.clone(),
        config: config.clone(),
        base_url: Some("BASE_URL".to_string()),
        session_provider: repositories
            .session_provider
            .unwrap_or(Arc::new(NoSessionProvider)),
        proof_schema_importer: Arc::new(ProofSchemaImporterProto::new(
            proof_schema_repository,
            credential_schema_repository.clone(),
            Arc::new(CredentialSchemaUrlImporterProto::new(
                Arc::new(MockHttpClient::new()),
                Arc::new(CredentialSchemaImportParserImpl::new(
                    config.clone(),
                    None,
                    formatter_provider,
                    revocation_method_provider,
                )),
                Arc::new(CredentialSchemaImporterProto::new(
                    credential_schema_repository,
                    "en".to_string(),
                )),
            )),
            Arc::new(MockHttpClient::new()),
            config,
        )),
        ecosystem_provider: Arc::new(repositories.ecosystem_provider),
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
        deleted_at: Some(crate::clock::now_utc()),
        ..generic_proof_schema()
    };
    {
        let res_clone = proof_schema.clone();
        proof_schema_repository
            .expect_get_proof_schema()
            .returning(move |_id| Ok(res_clone.clone()));
    }

    let service = setup_service(Repositories {
        proof_schema_repository,
        ..Default::default()
    });

    let result = service.get_proof_schema(&proof_schema.id).await;

    assert!(result.is_err_and(|e| matches!(e, ProofSchemaServiceError::NotFound(_))));
}

#[tokio::test]
async fn test_get_proof_schema_missing() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .returning(|id| {
            Err(DataLayerError::EntityNotFound {
                kind: EntityKind::ProofSchema,
                id: (*id).into(),
            })
        });

    let service = setup_service(Repositories {
        proof_schema_repository,
        ..Default::default()
    });

    let result = service.get_proof_schema(&Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0014);
}

#[tokio::test]
async fn test_get_proof_schema_list_success() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = ProofSchema {
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        imported_source_url: Some("CORE_URL".to_string()),
        deleted_at: None,
        name: "name".to_string(),
        expire_duration: 0,
        organisation: dummy_organisation(None).into(),
        input_schemas: Default::default(),
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
    let result = service
        .get_proof_schema_list(ListQueryDTO {
            page: 0,
            page_size: 1,
            sort: None,
            sort_direction: None,
            filter: ProofSchemaFilterParamsDTO {
                name: None,
                exact: None,
                organisation_id,
                ids: None,
                formats: None,
                ecosystems: None,
                created_date_after: None,
                created_date_before: None,
                last_modified_after: None,
                last_modified_before: None,
            },
            include: None,
        })
        .await;

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
    let result = service
        .get_proof_schema_list(ListQueryDTO {
            page: 0,
            page_size: 1,
            sort: None,
            sort_direction: None,
            filter: ProofSchemaFilterParamsDTO {
                name: None,
                exact: None,
                organisation_id,
                ids: None,
                formats: None,
                ecosystems: None,
                created_date_after: None,
                created_date_before: None,
                last_modified_after: None,
                last_modified_before: None,
            },
            include: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0054);
}

#[tokio::test]
async fn test_delete_proof_schema_success() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    proof_schema_repository
        .expect_get_proof_schema()
        .returning(|_| {
            Ok(ProofSchema {
                ecosystem: None,
                id: Uuid::new_v4().into(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                deleted_at: None,
                name: "name".to_string(),
                expire_duration: 0,
                organisation: dummy_organisation(None).into(),
                input_schemas: Default::default(),
            })
        });

    let proof_schema_id: ProofSchemaId = Uuid::new_v4().into();
    proof_schema_repository
        .expect_delete_proof_schema()
        .times(1)
        .with(
            eq(proof_schema_id.to_owned()),
            // deletion will happen shortly after
            ge(crate::clock::now_utc()).and(lt(crate::clock::now_utc() + time::Duration::SECOND)),
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
        .returning(|_| {
            Ok(ProofSchema {
                ecosystem: None,
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                imported_source_url: Some("CORE_URL".to_string()),
                last_modified: crate::clock::now_utc(),
                deleted_at: None,
                name: "name".to_string(),
                expire_duration: 0,
                organisation: dummy_organisation(None).into(),
                input_schemas: Default::default(),
            })
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
    assert!(matches!(result, Err(ProofSchemaServiceError::NotFound(_))));
}

#[tokio::test]
async fn test_create_proof_schema_success() {
    let claim_schema_id = Uuid::new_v4().into();
    let claim_schema = ClaimSchema {
        id: claim_schema_id,
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
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
        .return_once(move |_| Ok(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id))
        .returning(|id| Ok(dummy_organisation(Some(*id))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_| {
            let schema = CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "credential-schema".to_string(),
                imported_source_url: "CORE_URL".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id,
                    format: "JWT".into(),
                    schema_id: "CredentialSchemaId".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: None,
                claim_schemas: vec![claim_schema.clone()].into(),
                organisation: dummy_organisation(None).into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
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
        }],
        ecosystem: None,
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
            proof_schema.organisation.id() == organisation_id
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
            enabled: true,
            capabilities: None,
            params: None,
        },
    );
    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id))
        .returning(|id| Ok(dummy_organisation(Some(*id))));

    let claim_schema_software_id = Uuid::new_v4().into();
    let claim_schema_software = ClaimSchema {
        id: claim_schema_software_id,
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
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
        .returning(move |_| {
            let schema_software = CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_software_id,
                deleted_at: None,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "software".to_string(),
                imported_source_url: "CORE_URL".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id: credential_schema_software_id,
                    format: "JWT".into(),
                    schema_id: "CredentialSchemaId".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: Some(KeyStorageSecurity::Basic),
                claim_schemas: vec![claim_schema_software.clone()].into(),
                organisation: dummy_organisation(None).into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            };

            let schema_hardware = CredentialSchema {
                id: credential_schema_hardware_id,
                name: "hardware".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                claim_schemas: vec![claim_schema_hardware.clone()].into(),
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
            },
            ProofInputSchemaRequestDTO {
                claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                    id: claim_schema_hardware_id,
                    required: true,
                }],
                credential_schema_id: credential_schema_hardware_id,
            },
        ],
        ecosystem: None,
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
        .returning(move |_| Ok(formatter.clone()));

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
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
    };

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id))
        .returning(|id| Ok(dummy_organisation(Some(*id))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_| {
            let schema = CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "credential-schema".to_string(),
                imported_source_url: "CORE_URL".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id,
                    format: "JWT".into(),
                    schema_id: "CredentialSchemaId".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: Some(KeyStorageSecurity::EnhancedBasic),
                claim_schemas: vec![claim_schema.clone()].into(),
                organisation: dummy_organisation(None).into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
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
        }],
        ecosystem: None,
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
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0309);
}

#[tokio::test]
async fn test_create_proof_schema_array_object_fail() {
    let claim_schema_root = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
    };

    let claim_schema_array = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: true,
        metadata: false,
        required: false,
        translations: Default::default(),
    };

    let claim_schema_array_object = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
    };

    let claim_schema_array_object_item = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0/item".to_string(),
        data_type: "STRING".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
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
        .return_once(move |_| Ok(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id))
        .returning(|id| Ok(dummy_organisation(Some(*id))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_| {
            let schema = CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                imported_source_url: "CORE_URL".to_string(),
                deleted_at: None,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "credential-schema".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id,
                    format: "SD_JWT".into(),
                    schema_id: "CredentialSchemaId".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: None,
                claim_schemas: vec![
                    claim_schema_root.clone(),
                    claim_schema_array.clone(),
                    claim_schema_array_object.clone(),
                    claim_schema_array_object_item.clone(),
                ]
                .into(),
                organisation: dummy_organisation(None).into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
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
        }],
        ecosystem: None,
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
    assert!(
        result.is_err_and(|e| matches!(e, ProofSchemaServiceError::NestedClaimInArrayRequested))
    );
}

#[tokio::test]
async fn test_create_proof_schema_array_success() {
    let claim_schema_root = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
    };

    let claim_schema_array = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: true,
        metadata: false,
        required: false,
        translations: Default::default(),
    };

    let claim_schema_array_object = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
    };

    let claim_schema_array_object_item = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0/item".to_string(),
        data_type: "STRING".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
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
        .return_once(move |_| Ok(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id))
        .returning(|id| Ok(dummy_organisation(Some(*id))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_| {
            let schema = CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                created_date: crate::clock::now_utc(),
                imported_source_url: "CORE_URL".to_string(),
                last_modified: crate::clock::now_utc(),
                name: "credential-schema".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id,
                    format: "SD_JWT".into(),
                    schema_id: "CredentialSchemaId".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: None,
                claim_schemas: vec![
                    claim_schema_root.clone(),
                    claim_schema_array.clone(),
                    claim_schema_array_object.clone(),
                    claim_schema_array_object_item.clone(),
                ]
                .into(),
                organisation: dummy_organisation(None).into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
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
        }],
        ecosystem: None,
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
            proof_schema.organisation.id() == organisation_id
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

            claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                id: claim_schema_id,
                required: true,
            }],
        }],
        ecosystem: None,
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
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0015);
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
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(1)
        .returning(move |_| {
            let schema = CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                imported_source_url: "CORE_URL".to_string(),
                deleted_at: None,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "credential-schema".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id,
                    format: "JWT".into(),
                    schema_id: "CredentialSchemaId".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: None,
                claim_schemas: vec![ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    array: false,
                    metadata: false,
                    required: false,
                    translations: Default::default(),
                }]
                .into(),
                organisation: dummy_organisation(None).into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
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
        .returning(move |_| Ok(dummy_organisation(None)));

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

                claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                    id: claim_schema_id,
                    required: true,
                }],
            }],
            ecosystem: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(ProofSchemaServiceError::MissingClaimSchema { .. })
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

                claim_schemas: vec![],
            }],
            ecosystem: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(ProofSchemaServiceError::MissingClaims)
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

                claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                    id: Uuid::new_v4().into(),
                    required: false,
                }],
            }],
            ecosystem: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(ProofSchemaServiceError::NoRequiredClaim)
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

                claim_schemas: vec![claim_schema.clone(), claim_schema],
            }],
            ecosystem: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(ProofSchemaServiceError::DuplicitClaim)
    ));
}

#[tokio::test]
async fn test_import_proof_schema_ok_for_new_credential_schema() {
    let now = crate::clock::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .return_once(move |_| Ok(dummy_organisation(Some(organisation_id))));

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
        .withf(move |schema_id, org| schema_id == "iso-org-test123" && org == &organisation_id)
        .once()
        .returning(|_, _| Ok(None));
    credential_schema_repository
        .expect_create_credential_schema()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(|_| {
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
                deleted_at: None,
                name: "test-credential-schema".to_string(),
                format: "JWT".into(),
                revocation_method: None,
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: None,
            },
        }],
    };

    let mut http_client = MockHttpClient::new();
    http_client
        .expect_get()
        .once()
        .with(eq(IMPORT_URL))
        .returning(|url| {
            let mut inner_client = MockHttpClient::new();
            inner_client
                .expect_send()
                .once()
                .returning(|_, _, _, _, _| {
                    Ok(Response {
                        body: json!({
                            "createdDate": "2023-06-09T14:19:57.000Z",
                            "lastModified": "2023-06-09T14:19:57.000Z",
                            "format": "JWT",
                            "id": Uuid::new_v4(),
                            "importedSourceUrl": "http://import.credential.schema",
                            "name": "test-credential-schema",
                            "organisationId": Uuid::new_v4(),
                            "revocationMethod": null,
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
                            timeout: None,
                        },
                    })
                });

            RequestBuilder::new(Arc::new(inner_client), Method::Get, url)
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter.clone()));

    let formatter_provider = Arc::new(formatter_provider);
    let credential_schema_repository = Arc::new(credential_schema_repository);
    let config = Arc::new(generic_config().core);

    let proof_schema_repository = Arc::new(proof_schema_repository);

    let service = ProofSchemaService {
        proof_schema_repository: proof_schema_repository.clone(),
        credential_schema_repository: credential_schema_repository.clone(),
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider: formatter_provider.clone(),
        config: Arc::new(generic_config().core),
        base_url: None,
        session_provider: Arc::new(NoSessionProvider),
        proof_schema_importer: Arc::new(ProofSchemaImporterProto::new(
            proof_schema_repository,
            credential_schema_repository.clone(),
            Arc::new(CredentialSchemaUrlImporterProto::new(
                Arc::new(http_client),
                Arc::new(CredentialSchemaImportParserImpl::new(
                    config.clone(),
                    None,
                    formatter_provider.clone(),
                    Arc::new(MockRevocationMethodProvider::default()),
                )),
                Arc::new(CredentialSchemaImporterProto::new(
                    credential_schema_repository,
                    "en".to_string(),
                )),
            )),
            Arc::new(MockHttpClient::new()),
            config,
        )),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::new()),
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
async fn test_import_proof_schema_ok_for_new_credential_schema_v2_url() {
    let now = crate::clock::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let credential_schema_id = Uuid::new_v4();
    let v2_url = format!("http://import.credential.schema/ssi/schema/v2/{credential_schema_id}");

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .return_once(move |_| Ok(dummy_organisation(Some(organisation_id))));

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
        .withf(move |schema_id, org| schema_id == "iso-org-test123" && org == &organisation_id)
        .once()
        .returning(|_, _| Ok(None));
    credential_schema_repository
        .expect_create_credential_schema()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(|_| {
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
                id: credential_schema_id.into(),
                created_date: now,
                imported_source_url: v2_url.clone(),
                last_modified: now,
                deleted_at: None,
                name: "test-credential-schema".to_string(),
                format: "JWT".into(),
                revocation_method: None,
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: None,
            },
        }],
    };

    let mut http_client = MockHttpClient::new();
    let v2_url_for_match = v2_url.clone();
    let v2_url_for_response = v2_url.clone();
    http_client
        .expect_get()
        .once()
        .withf(move |url| url == v2_url_for_match)
        .returning(move |url| {
            let url_for_response = v2_url_for_response.clone();
            let mut inner_client = MockHttpClient::new();
            inner_client
                .expect_send()
                .once()
                .returning(move |_, _, _, _, _| {
                    Ok(Response {
                        body: json!({
                            "id": Uuid::new_v4(),
                            "createdDate": "2023-06-09T14:19:57.000Z",
                            "lastModified": "2023-06-09T14:19:57.000Z",
                            "name": "test-credential-schema",
                            "formats": [{
                                "format": "JWT",
                                "schemaId": "iso-org-test123"
                            }],
                            "organisationId": Uuid::new_v4(),
                            "claims": [{
                                "id": Uuid::new_v4(),
                                "createdDate": "2023-06-09T14:19:57.000Z",
                                "lastModified": "2023-06-09T14:19:57.000Z",
                                "key": "field",
                                "datatype": "STRING",
                                "required": true,
                                "array": false,
                                "translations": {"name": {"en": "field"}}
                            }],
                            "importedSourceUrl": url_for_response,
                            "allowSuspension": false,
                            "requiresWalletInstanceAttestation": false,
                            "translations": {"name": {"en": "test-credential-schema"}}
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
                            url: url_for_response.clone(),
                            timeout: None,
                        },
                    })
                });

            RequestBuilder::new(Arc::new(inner_client), Method::Get, url)
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter.clone()));

    let formatter_provider = Arc::new(formatter_provider);
    let credential_schema_repository = Arc::new(credential_schema_repository);
    let config = Arc::new(generic_config().core);

    let proof_schema_repository = Arc::new(proof_schema_repository);

    let service = ProofSchemaService {
        proof_schema_repository: proof_schema_repository.clone(),
        credential_schema_repository: credential_schema_repository.clone(),
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider: formatter_provider.clone(),
        config: Arc::new(generic_config().core),
        base_url: None,
        session_provider: Arc::new(NoSessionProvider),
        proof_schema_importer: Arc::new(ProofSchemaImporterProto::new(
            proof_schema_repository,
            credential_schema_repository.clone(),
            Arc::new(CredentialSchemaUrlImporterProto::new(
                Arc::new(http_client),
                Arc::new(CredentialSchemaImportParserImpl::new(
                    config.clone(),
                    None,
                    formatter_provider.clone(),
                    Arc::new(MockRevocationMethodProvider::default()),
                )),
                Arc::new(CredentialSchemaImporterProto::new(
                    credential_schema_repository,
                    "en".to_string(),
                )),
            )),
            Arc::new(MockHttpClient::new()),
            config,
        )),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::new()),
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
    let now = crate::clock::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .return_once(move |_| Ok(dummy_organisation(Some(organisation_id))));

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
        .withf(move |schema_id, org| schema_id == "iso-org-test123" && org == &organisation_id)
        .once()
        .returning(|_, _| {
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
        .returning(|_| {
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
                deleted_at: None,
                name: "test-credential-schema".to_string(),
                format: "JWT".into(),
                revocation_method: None,
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: None,
            },
        }],
    };

    let mut http_client = MockHttpClient::new();
    http_client
        .expect_get()
        .once()
        .with(eq(IMPORT_URL))
        .returning(|url| {
            let mut inner_client = MockHttpClient::new();
            inner_client
                .expect_send()
                .once()
                .returning(|_, _, _, _, _| {
                    Ok(Response {
                        body: json!({
                            "createdDate": "2023-06-09T14:19:57.000Z",
                            "lastModified": "2023-06-09T14:19:57.000Z",
                            "format": "JWT",
                            "id": Uuid::new_v4(),
                            "importedSourceUrl": "http://import.credential.schema",
                            "name": "test-credential-schema",
                            "organisationId": Uuid::new_v4(),
                            "revocationMethod": null,
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
                            timeout: None,
                        },
                    })
                });

            RequestBuilder::new(Arc::new(inner_client), Method::Get, url)
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            datatypes: vec!["STRING".into(), "OBJECT".into()],
            ..Default::default()
        });
    formatter.expect_get_metadata_claims().returning(Vec::new);

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter.clone()));

    let formatter_provider = Arc::new(formatter_provider);
    let credential_schema_repository = Arc::new(credential_schema_repository);
    let config = Arc::new(generic_config().core);

    let proof_schema_repository = Arc::new(proof_schema_repository);

    let service = ProofSchemaService {
        proof_schema_repository: proof_schema_repository.clone(),
        credential_schema_repository: credential_schema_repository.clone(),
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider: formatter_provider.clone(),
        config: config.clone(),
        base_url: None,
        session_provider: Arc::new(NoSessionProvider),
        proof_schema_importer: Arc::new(ProofSchemaImporterProto::new(
            proof_schema_repository,
            credential_schema_repository.clone(),
            Arc::new(CredentialSchemaUrlImporterProto::new(
                Arc::new(http_client),
                Arc::new(CredentialSchemaImportParserImpl::new(
                    config.clone(),
                    None,
                    formatter_provider.clone(),
                    Arc::new(MockRevocationMethodProvider::default()),
                )),
                Arc::new(CredentialSchemaImporterProto::new(
                    credential_schema_repository,
                    "en".to_string(),
                )),
            )),
            Arc::new(MockHttpClient::new()),
            config,
        )),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::new()),
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
    let now = crate::clock::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .return_once(move |_| Ok(dummy_organisation(Some(organisation_id))));

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
        .withf(move |schema_id, org| schema_id == "iso-org-test123" && org == &organisation_id)
        .once()
        .returning(move |_, _| {
            Ok(Some(CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: existing_schema_id,
                deleted_at: None,
                created_date: get_dummy_date(),
                imported_source_url: "CORE_URL".to_string(),
                last_modified: get_dummy_date(),
                name: "test-credential-schema".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id: existing_schema_id,
                    format: "MDOC".into(),
                    schema_id: "iso-org-test123".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                layout_properties: None,
                claim_schemas: vec![ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "root/name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    array: false,
                    last_modified: get_dummy_date(),
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]
                .into(),
                organisation: dummy_organisation(None).into(),
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
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
                deleted_at: None,
                name: "test-credential-schema".to_string(),
                format: "MDOC".into(),
                revocation_method: None,
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: None,
            },
        }],
    };

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            features: vec![Features::SelectiveDisclosure],
            selective_disclosure: vec![SelectiveDisclosure::FirstLevel],
            ..Default::default()
        });

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("MDOC")))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let formatter_provider = Arc::new(formatter_provider);
    let credential_schema_repository = Arc::new(credential_schema_repository);
    let import_parser = CredentialSchemaImportParserImpl::new(
        Arc::new(generic_config().core),
        None,
        formatter_provider.clone(),
        Arc::new(MockRevocationMethodProvider::new()),
    );

    let importer =
        CredentialSchemaImporterProto::new(credential_schema_repository.clone(), "en".to_string());

    let proof_schema_repository = Arc::new(proof_schema_repository);

    let service = ProofSchemaService {
        proof_schema_repository: proof_schema_repository.clone(),
        credential_schema_repository: credential_schema_repository.clone(),
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider,
        config: Arc::new(generic_config().core),
        base_url: None,
        session_provider: Arc::new(NoSessionProvider),
        proof_schema_importer: Arc::new(ProofSchemaImporterProto::new(
            proof_schema_repository,
            credential_schema_repository,
            Arc::new(CredentialSchemaUrlImporterProto::new(
                Arc::new(MockHttpClient::new()),
                Arc::new(import_parser),
                Arc::new(importer),
            )),
            Arc::new(MockHttpClient::new()),
            Arc::new(generic_config().core),
        )),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::new()),
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
async fn test_import_proof_schema_rehosts_source_url_when_enabled() {
    let now = crate::clock::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .return_once(move |_| Ok(dummy_organisation(Some(organisation_id))));

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
        .returning(|proof_schema| {
            // source url is rewritten to point at this core instance
            assert_eq!(
                Some(format!("BASE_URL/ssi/proof-schema/v1/{}", proof_schema.id)),
                proof_schema.imported_source_url
            );
            Ok(proof_schema.id)
        });

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();

    let existing_schema_id = Uuid::new_v4().into();

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .withf(move |schema_id, org| schema_id == "iso-org-test123" && org == &organisation_id)
        .once()
        .returning(move |_, _| {
            Ok(Some(CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: existing_schema_id,
                deleted_at: None,
                created_date: get_dummy_date(),
                imported_source_url: "CORE_URL".to_string(),
                last_modified: get_dummy_date(),
                name: "test-credential-schema".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id: existing_schema_id,
                    format: "MDOC".into(),
                    schema_id: "iso-org-test123".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                layout_properties: None,
                claim_schemas: vec![ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "root/name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    array: false,
                    last_modified: get_dummy_date(),
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]
                .into(),
                organisation: dummy_organisation(None).into(),
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            }))
        });

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        imported_source_url: "https://other-core/ssi/proof-schema/v1/external".to_string(),
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
                deleted_at: None,
                name: "test-credential-schema".to_string(),
                format: "MDOC".into(),
                revocation_method: None,
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: None,
            },
        }],
    };

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            revocation_methods: vec![],
            features: vec![Features::SelectiveDisclosure],
            selective_disclosure: vec![SelectiveDisclosure::FirstLevel],
            ..Default::default()
        });

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("MDOC")))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let formatter_provider = Arc::new(formatter_provider);
    let credential_schema_repository = Arc::new(credential_schema_repository);

    let mut config = generic_config().core;
    config.global_settings.rehost_imported_schemas = true;
    let config = Arc::new(config);

    let import_parser = CredentialSchemaImportParserImpl::new(
        config.clone(),
        Some("BASE_URL".to_string()),
        formatter_provider.clone(),
        Arc::new(MockRevocationMethodProvider::new()),
    );

    let importer =
        CredentialSchemaImporterProto::new(credential_schema_repository.clone(), "en".to_string());

    let proof_schema_repository = Arc::new(proof_schema_repository);

    let service = ProofSchemaService {
        proof_schema_repository: proof_schema_repository.clone(),
        credential_schema_repository: credential_schema_repository.clone(),
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider,
        config: config.clone(),
        base_url: Some("BASE_URL".to_string()),
        session_provider: Arc::new(NoSessionProvider),
        proof_schema_importer: Arc::new(ProofSchemaImporterProto::new(
            proof_schema_repository,
            credential_schema_repository,
            Arc::new(CredentialSchemaUrlImporterProto::new(
                Arc::new(MockHttpClient::new()),
                Arc::new(import_parser),
                Arc::new(importer),
            )),
            Arc::new(MockHttpClient::new()),
            config,
        )),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::new()),
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
    let now = crate::clock::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .return_once(move |_| Ok(dummy_organisation(Some(organisation_id))));

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
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                name: "test-credential-schema".to_string(),
                format: "MDOC".into(),
                revocation_method: None,
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: None,
            },
        }],
    };

    let proof_schema_repository = Arc::new(proof_schema_repository);

    let service = ProofSchemaService {
        proof_schema_repository: proof_schema_repository.clone(),
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::new()),
        organisation_repository: Arc::new(organisation_repository),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        config: Arc::new(generic_config().core),
        base_url: None,
        session_provider: Arc::new(NoSessionProvider),
        proof_schema_importer: Arc::new(ProofSchemaImporterProto::new(
            proof_schema_repository,
            Arc::new(MockCredentialSchemaRepository::new()),
            Arc::new(CredentialSchemaUrlImporterProto::new(
                Arc::new(MockHttpClient::new()),
                Arc::new(MockCredentialSchemaImportParser::default()),
                Arc::new(MockCredentialSchemaImporter::default()),
            )),
            Arc::new(MockHttpClient::new()),
            Arc::new(generic_config().core),
        )),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::new()),
    };

    let result = service
        .import_proof_schema(ImportProofSchemaRequestDTO {
            schema,
            organisation_id,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0015);
}

#[tokio::test]
async fn test_import_proof_schema_fails_validation_for_unsupported_datatype() {
    let now = crate::clock::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .return_once(move |_| Ok(dummy_organisation(Some(organisation_id))));

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
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                name: "test-credential-schema".to_string(),
                format: "MDOC".into(),
                revocation_method: None,
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: None,
            },
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

    assert_eq!(err.error_code(), ErrorCode::BR_0135)
}

#[tokio::test]
async fn test_import_proof_schema_fails_validation_for_unsupported_format() {
    let now = crate::clock::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .return_once(move |_| Ok(dummy_organisation(Some(organisation_id))));

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
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                name: "test-credential-schema".to_string(),
                format: "OTHER_FORMAT".into(),
                revocation_method: None,
                key_storage_security: Some(KeyStorageSecurity::Moderate),
                schema_id: "iso-org-test123".to_string(),
                layout_properties: None,
                allow_suspension: None,
                requires_wallet_instance_attestation: None,
            },
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

    assert_eq!(err.error_code(), ErrorCode::BR_0135)
}

fn generic_proof_schema() -> ProofSchema {
    ProofSchema {
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        imported_source_url: Some("CORE_URL".to_string()),
        last_modified: crate::clock::now_utc(),
        deleted_at: None,
        name: "name".to_string(),
        expire_duration: 0,
        organisation: dummy_organisation(None).into(),
        input_schemas: Default::default(),
    }
}

#[tokio::test]
async fn test_get_proof_schema_success_nested_claims() {
    let now = crate::clock::now_utc();
    let location_claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    };
    let location_x_claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/X".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    };

    let mut proof_schema = generic_proof_schema();
    proof_schema.input_schemas = vec![ProofInputSchema {
        claim_schemas: vec![ProofInputClaimSchema {
            schema: location_x_claim_schema.to_owned(),
            required: true,
            order: 0,
        }]
        .into(),
        credential_schema: credential_schema_with_claims(vec![
            location_claim_schema,
            location_x_claim_schema.to_owned(),
        ])
        .await
        .into(),
    }]
    .into();

    let service = setup_service(Repositories {
        proof_schema_repository: proof_schema_repo_expecting_get(proof_schema.clone()),
        formatter_provider: mock_formatter_provider(),
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
    let now = crate::clock::now_utc();
    let location_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    };
    let location_x_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/X".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    };
    let location_foo_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/foo".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
    };

    let mut proof_schema = generic_proof_schema();
    proof_schema.input_schemas = vec![ProofInputSchema {
        claim_schemas: vec![ProofInputClaimSchema {
            schema: location_cs.to_owned(),
            required: true,
            order: 0,
        }]
        .into(),
        credential_schema: credential_schema_with_claims(vec![
            location_cs,
            location_x_cs,
            location_foo_cs.to_owned(),
        ])
        .await
        .into(),
    }]
    .into();

    let service = setup_service(Repositories {
        proof_schema_repository: proof_schema_repo_expecting_get(proof_schema.clone()),
        formatter_provider: mock_formatter_provider(),
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
    let now = crate::clock::now_utc();
    let bar_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "bar".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    };
    let location_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: false,
        translations: Default::default(),
    };
    let location_x_cs = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/X".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    };

    let mut proof_schema = generic_proof_schema();
    proof_schema.input_schemas = vec![ProofInputSchema {
        claim_schemas: vec![
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
        ]
        .into(),
        credential_schema: credential_schema_with_claims(vec![bar_cs, location_cs, location_x_cs])
            .await
            .into(),
    }]
    .into();

    let service = setup_service(Repositories {
        proof_schema_repository: proof_schema_repo_expecting_get(proof_schema.clone()),
        formatter_provider: mock_formatter_provider(),
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

fn mock_formatter_provider() -> MockCredentialFormatterProvider {
    let mut credential_formatter_provider = MockCredentialFormatterProvider::new();
    credential_formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().returning(|| None);
            Ok(Arc::new(formatter))
        });
    credential_formatter_provider
}

fn proof_schema_repo_expecting_get(proof_schema: ProofSchema) -> MockProofSchemaRepository {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .with(eq(proof_schema.id.to_owned()))
        .returning(move |_id| Ok(proof_schema.clone()));
    proof_schema_repository
}

async fn credential_schema_with_claims(claims: Vec<ClaimSchema>) -> CredentialSchema {
    let now = crate::clock::now_utc();
    let credential_schema_id = Uuid::new_v4().into();
    backfill_default_translations(
        CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: "".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                credential_schema_id,
                format: "".into(),
                schema_id: "".to_owned(),
                claim_mappings: Default::default(),
            }]
            .into(),
            imported_source_url: "CORE_URL".to_string(),
            key_storage_security: None,
            layout_properties: None,
            claim_schemas: claims.into(),
            organisation: dummy_organisation(None).into(),
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        },
        "en",
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_1st_level_fail_nested() {
    let keys = ["root", "root/nested"];
    assert!(
        test_create_proof_schema_verify_nested_generic(
            &keys,
            &[Features::SelectiveDisclosure],
            &[SelectiveDisclosure::FirstLevel]
        )
        .await
        .is_err_and(|e| e.error_code() == ErrorCode::BR_0130)
    );
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_1st_level_success_root_level() {
    let keys = ["root"];
    assert!(
        test_create_proof_schema_verify_nested_generic(
            &keys,
            &[Features::SelectiveDisclosure],
            &[SelectiveDisclosure::FirstLevel]
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
            ecosystem: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

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
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_list_proof_schema_failure_session_org_mismatch() {
    let service = setup_service(Repositories {
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = service
        .get_proof_schema_list(ListQueryDTO {
            page: 0,
            page_size: 0,
            sort: None,
            sort_direction: None,
            filter: ProofSchemaFilterParamsDTO {
                name: None,
                exact: None,
                organisation_id: Uuid::new_v4().into(),
                ids: None,
                formats: None,
                ecosystems: None,
                created_date_after: None,
                created_date_before: None,
                last_modified_after: None,
                last_modified_before: None,
            },
            include: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_proof_schema_ops_failure_session_org_mismatch() {
    let proof_schema = generic_proof_schema();
    let schema_id = proof_schema.id;
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .returning(move |_id| Ok(proof_schema.clone()));

    let service = setup_service(Repositories {
        proof_schema_repository,
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = service.get_proof_schema(&schema_id).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service.delete_proof_schema(&schema_id).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service.share_proof_schema(schema_id).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

async fn test_create_proof_schema_verify_nested_generic(
    keys: &[&str],
    features: &[Features],
    disclosure_features: &[SelectiveDisclosure],
) -> Result<ProofSchemaId, ProofSchemaServiceError> {
    let claim_schemas: Vec<_> = keys
        .iter()
        .map(|key| ClaimSchema {
            id: Uuid::new_v4().into(),
            key: key.to_string(),
            data_type: "OBJECT".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
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
        .return_once(move |_| Ok(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id))
        .returning(|id| Ok(dummy_organisation(Some(*id))));

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let claim_schemas_cloned = claim_schemas.clone();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| {
            let schema = CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "credential-schema".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id,
                    format: "JWT".into(),
                    schema_id: "CredentialSchemaId".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: None,
                claim_schemas: claim_schemas_cloned.into(),
                organisation: dummy_organisation(None).into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
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
        }],
        ecosystem: None,
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
