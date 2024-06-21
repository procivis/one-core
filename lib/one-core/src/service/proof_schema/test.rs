use std::sync::Arc;

use mockall::predicate::*;
use mockall::PredicateBooleanExt;
use shared_types::CredentialSchemaId;
use shared_types::OrganisationId;
use shared_types::ProofSchemaId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofSchemaService;
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::common::GetListResponse;
use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, CredentialSchemaType,
    LayoutType,
};
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::proof_schema::{
    GetProofSchemaList, ProofInputClaimSchema, ProofInputSchema, ProofInputSchemaRelations,
    ProofSchema, ProofSchemaRelations,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::credential_formatter::{MockCredentialFormatter, SelectiveDisclosureOption};
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ErrorCode, ServiceError, ValidationError,
};
use crate::service::proof_schema::dto::ImportProofSchemaClaimSchemaDTO;
use crate::service::proof_schema::dto::ImportProofSchemaCredentialSchemaDTO;
use crate::service::proof_schema::dto::ImportProofSchemaDTO;
use crate::service::proof_schema::dto::ImportProofSchemaInputSchemaDTO;
use crate::service::proof_schema::dto::ImportProofSchemaRequestDTO;
use crate::service::proof_schema::dto::{
    CreateProofSchemaClaimRequestDTO, CreateProofSchemaRequestDTO, GetProofSchemaQueryDTO,
    ProofInputSchemaRequestDTO,
};
use crate::service::proof_schema::ProofSchemaImportError;
use crate::service::test_utilities::{generic_config, generic_formatter_capabilities};

fn setup_service(
    proof_schema_repository: MockProofSchemaRepository,
    credential_schema_repository: MockCredentialSchemaRepository,
    organisation_repository: MockOrganisationRepository,
    formatter_provider: MockCredentialFormatterProvider,
) -> ProofSchemaService {
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    ProofSchemaService {
        proof_schema_repository: Arc::new(proof_schema_repository),
        credential_schema_repository: Arc::new(credential_schema_repository),
        organisation_repository: Arc::new(organisation_repository),
        history_repository: Arc::new(history_repository),
        formatter_provider: Arc::new(formatter_provider),
        config: Arc::new(generic_config().core),
        base_url: Default::default(),
    }
}

#[tokio::test]
async fn test_get_proof_schema_exists() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = generic_proof_schema();
    {
        let res_clone = proof_schema.clone();
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
            .returning(move |_id, _relations| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(
        proof_schema_repository,
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

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

    let service = setup_service(
        proof_schema_repository,
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

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

    let service = setup_service(
        proof_schema_repository,
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

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

    let service = setup_service(
        proof_schema_repository,
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

    let query = GetProofSchemaQueryDTO {
        page: 0,
        page_size: 1,
        sort: None,
        sort_direction: None,
        exact: None,
        name: None,
        organisation_id: Uuid::new_v4().into(),
        ids: None,
    };
    let result = service.get_proof_schema_list(query).await;

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

    let service = setup_service(
        proof_schema_repository,
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

    let query = GetProofSchemaQueryDTO {
        page: 0,
        page_size: 1,
        sort: None,
        sort_direction: None,
        exact: None,
        name: None,
        organisation_id: Uuid::new_v4().into(),
        ids: None,
    };
    let result = service.get_proof_schema_list(query).await;

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
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "name".to_string(),
                expire_duration: 0,
                organisation: None,
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

    let service = setup_service(
        proof_schema_repository,
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

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
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "name".to_string(),
                expire_duration: 0,
                organisation: None,
                input_schemas: None,
            }))
        });

    proof_schema_repository
        .expect_delete_proof_schema()
        .times(1)
        .returning(|_, _| Err(DataLayerError::RecordNotUpdated));

    let service = setup_service(
        proof_schema_repository,
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

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
    };

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| {
            Ok(Some(Organisation {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }))
        });

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
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                wallet_storage_type: None,
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: claim_schema.clone(),
                    required: false,
                }]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                schema_id: "CredentialSchemaId".to_owned(),
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: 0,
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
                && proof_schema.expire_duration == create_request_clone.expire_duration
        })
        .returning(|request| Ok(request.id));

    let service = setup_service(
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
    );

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_ok());
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
    };

    let claim_schema_array = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: true,
    };

    let claim_schema_array_object = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
    };

    let claim_schema_array_object_item = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0/item".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
    };

    let claim_id = claim_schema_array_object_item.id;
    let mut capabilities = generic_formatter_capabilities();
    capabilities.features = vec!["SELECTIVE_DISCLOSURE".to_string()];
    capabilities.selective_disclosure = vec![SelectiveDisclosureOption::AnyLevel];

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(move || capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| {
            Ok(Some(Organisation {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }))
        });

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
                format: "SD-JWT".to_string(),
                revocation_method: "NONE".to_string(),
                wallet_storage_type: None,
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
                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                schema_id: "CredentialSchemaId".to_owned(),
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: 0,
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

    let service = setup_service(
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
    );

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
    };

    let claim_schema_array = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: true,
    };

    let claim_schema_array_object = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
    };

    let claim_schema_array_object_item = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "root/nested_array/0/item".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
    };

    let claim_id = claim_schema_array.id;

    let mut capabilities = generic_formatter_capabilities();
    capabilities.features = vec!["SELECTIVE_DISCLOSURE".to_string()];
    capabilities.selective_disclosure = vec![SelectiveDisclosureOption::AnyLevel];

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(move || capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| {
            Ok(Some(Organisation {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }))
        });

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
                format: "SD-JWT".to_string(),
                revocation_method: "NONE".to_string(),
                wallet_storage_type: None,
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
                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                schema_id: "CredentialSchemaId".to_owned(),
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: 0,
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
                && proof_schema.expire_duration == create_request_clone.expire_duration
        })
        .returning(|request| Ok(request.id));

    let service = setup_service(
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
    );

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_proof_schema_unique_name_error() {
    let claim_schema_id = Uuid::new_v4().into();
    let organisation_id = Uuid::new_v4().into();

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: 0,
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

    let service = setup_service(
        proof_schema_repository,
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

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
        .expect_get_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

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
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                wallet_storage_type: None,
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "key".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
                    },
                    required: false,
                }]),
                organisation: None,
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                schema_id: "CredentialSchemaId".to_owned(),
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
        .returning(move |_, _| {
            Ok(Some(Organisation {
                id: organisation_id,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }))
        });

    let service = setup_service(
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
    );

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: 0,
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
    let service = setup_service(
        MockProofSchemaRepository::default(),
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: 0,
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
    let service = setup_service(
        MockProofSchemaRepository::default(),
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: 0,
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
    let service = setup_service(
        MockProofSchemaRepository::default(),
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

    let claim_schema = CreateProofSchemaClaimRequestDTO {
        id: Uuid::new_v4().into(),
        required: true,
    };
    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: 0,
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
        .return_once(move |_, _| {
            Ok(Some(Organisation {
                id: organisation_id,
                created_date: now,
                last_modified: now,
            }))
        });

    let mut proof_schema_repository = MockProofSchemaRepository::new();
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

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .withf(|h| {
            h.entity_type == HistoryEntityType::CredentialSchema
                && h.action == HistoryAction::Created
        })
        .returning(|_| Ok(Uuid::new_v4().into()));
    history_repository
        .expect_create_history()
        .once()
        .withf(|h| {
            h.entity_type == HistoryEntityType::ProofSchema && h.action == HistoryAction::Imported
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "test-proof-schema".to_string(),
        organisation_id,
        expire_duration: 1000,
        proof_input_schemas: vec![ImportProofSchemaInputSchemaDTO {
            claim_schemas: vec![ImportProofSchemaClaimSchemaDTO {
                id: Uuid::new_v4().into(),
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
                name: "test-credential-schema".to_string(),
                format: "MDOC".to_string(),
                revocation_method: "NONE".to_string(),
                wallet_storage_type: Some(WalletStorageTypeEnum::Hardware),
                schema_id: "iso-org-test123".to_string(),
                schema_type: CredentialSchemaType::Mdoc,
                layout_type: None,
                layout_properties: None,
            },
            validity_constraint: None,
        }],
    };

    let service = ProofSchemaService {
        proof_schema_repository: Arc::new(proof_schema_repository),
        credential_schema_repository: Arc::new(credential_schema_repository),
        organisation_repository: Arc::new(organisation_repository),
        history_repository: Arc::new(history_repository),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        config: Arc::new(generic_config().core),
        base_url: None,
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
async fn test_import_proof_schema_fails_validation_for_unsupported_datatype() {
    let now = OffsetDateTime::now_utc();
    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let mut organisation_repo = MockOrganisationRepository::new();
    organisation_repo
        .expect_get_organisation()
        .with(eq(organisation_id), always())
        .return_once(move |_, _| {
            Ok(Some(Organisation {
                id: organisation_id,
                created_date: now,
                last_modified: now,
            }))
        });

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "test-proof-schema".to_string(),
        organisation_id,
        expire_duration: 1000,
        proof_input_schemas: vec![ImportProofSchemaInputSchemaDTO {
            claim_schemas: vec![ImportProofSchemaClaimSchemaDTO {
                id: Uuid::new_v4().into(),
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
                name: "test-credential-schema".to_string(),
                format: "MDOC".to_string(),
                revocation_method: "NONE".to_string(),
                wallet_storage_type: Some(WalletStorageTypeEnum::Hardware),
                schema_id: "iso-org-test123".to_string(),
                schema_type: CredentialSchemaType::Mdoc,
                layout_type: None,
                layout_properties: None,
            },
            validity_constraint: None,
        }],
    };

    let service = setup_service(
        MockProofSchemaRepository::default(),
        MockCredentialSchemaRepository::default(),
        organisation_repo,
        MockCredentialFormatterProvider::default(),
    );

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
    let mut organisation_repo = MockOrganisationRepository::new();
    organisation_repo
        .expect_get_organisation()
        .with(eq(organisation_id), always())
        .return_once(move |_, _| {
            Ok(Some(Organisation {
                id: organisation_id,
                created_date: now,
                last_modified: now,
            }))
        });

    let schema = ImportProofSchemaDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "test-proof-schema".to_string(),
        organisation_id,
        expire_duration: 1000,
        proof_input_schemas: vec![ImportProofSchemaInputSchemaDTO {
            claim_schemas: vec![ImportProofSchemaClaimSchemaDTO {
                id: Uuid::new_v4().into(),
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
                name: "test-credential-schema".to_string(),
                format: "OTHER_FORMAT".to_string(),
                revocation_method: "NONE".to_string(),
                wallet_storage_type: Some(WalletStorageTypeEnum::Hardware),
                schema_id: "iso-org-test123".to_string(),
                schema_type: CredentialSchemaType::Mdoc,
                layout_type: None,
                layout_properties: None,
            },
            validity_constraint: None,
        }],
    };

    let service = setup_service(
        MockProofSchemaRepository::default(),
        MockCredentialSchemaRepository::default(),
        organisation_repo,
        MockCredentialFormatterProvider::default(),
    );

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
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        name: "name".to_string(),
        expire_duration: 0,
        organisation: Some(Organisation {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
        input_schemas: Some(vec![]),
    }
}

#[tokio::test]
async fn test_get_proof_schema_success_nested_claims() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let now = OffsetDateTime::now_utc();
    let location_claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
    };
    let location_x_claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/X".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
    };

    let mut proof_schema = generic_proof_schema();
    proof_schema.input_schemas = Some(vec![ProofInputSchema {
        validity_constraint: None,
        claim_schemas: Some(vec![ProofInputClaimSchema {
            schema: location_x_claim_schema.to_owned(),
            required: true,
            order: 0,
        }]),
        credential_schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: "".to_string(),
            format: "".to_string(),
            revocation_method: "".to_string(),
            wallet_storage_type: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "".to_string(),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            claim_schemas: Some(vec![
                CredentialSchemaClaim {
                    schema: location_claim_schema,
                    required: true,
                },
                CredentialSchemaClaim {
                    schema: location_x_claim_schema.to_owned(),
                    required: true,
                },
            ]),
            organisation: None,
        }),
    }]);

    {
        let res_clone = proof_schema.clone();
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
            .returning(move |_id, _relations| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(
        proof_schema_repository,
        MockCredentialSchemaRepository::default(),
        MockOrganisationRepository::default(),
        MockCredentialFormatterProvider::default(),
    );

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
async fn test_create_proof_schema_verify_nested_2nd_level_success() {
    let keys = ["root/nested", "root/nested2", "root/nested3"];
    assert!(test_create_proof_schema_verify_nested_generic(
        &keys,
        &["SELECTIVE_DISCLOSURE".to_owned()],
        &[SelectiveDisclosureOption::SecondLevel]
    )
    .await
    .is_ok())
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_2nd_level_fail_3rd_level() {
    let keys = [
        "root/nested",
        "root/nested2",
        "root/nested3/even more nested",
    ];
    assert!(test_create_proof_schema_verify_nested_generic(
        &keys,
        &["SELECTIVE_DISCLOSURE".to_owned()],
        &[SelectiveDisclosureOption::SecondLevel]
    )
    .await
    .is_err_and(|e| e.error_code() == ErrorCode::BR_0130));
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_2nd_level_success_root_level() {
    let keys = ["root/nested", "root", "root/nested3"];
    assert!(test_create_proof_schema_verify_nested_generic(
        &keys,
        &["SELECTIVE_DISCLOSURE".to_owned()],
        &[SelectiveDisclosureOption::SecondLevel]
    )
    .await
    .is_ok());
}

#[tokio::test]
async fn test_create_proof_schema_verify_nested_any_level_success() {
    let keys = [
        "root/nested",
        "root",
        "root/nested3",
        "root/nested4/even more nested/with nested claim",
    ];
    assert!(test_create_proof_schema_verify_nested_generic(
        &keys,
        &["SELECTIVE_DISCLOSURE".to_owned()],
        &[SelectiveDisclosureOption::AnyLevel]
    )
    .await
    .is_ok());
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

async fn test_create_proof_schema_verify_nested_generic(
    keys: &[&str],
    features: &[String],
    disclosure_features: &[SelectiveDisclosureOption],
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
        .expect_get_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(|id, _| {
            Ok(Some(Organisation {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }))
        });

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
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "credential-schema".to_string(),
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                wallet_storage_type: None,
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
                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                schema_id: "CredentialSchemaId".to_owned(),
            };

            Ok(GetListResponse {
                values: vec![schema],
                total_pages: 1,
                total_items: 1,
            })
        });

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: 0,
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

    let service = setup_service(
        proof_schema_repository,
        credential_schema_repository,
        organisation_repository,
        formatter_provider,
    );

    service.create_proof_schema(create_request).await
}
