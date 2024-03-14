use super::ProofSchemaService;
use crate::{
    model::{
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential_schema::CredentialSchemaRelations,
        organisation::{Organisation, OrganisationRelations},
        proof_schema::{
            GetProofSchemaList, ProofSchema, ProofSchemaClaimRelations, ProofSchemaRelations,
        },
    },
    repository::{
        error::DataLayerError,
        history_repository::MockHistoryRepository,
        mock::{
            claim_schema_repository::MockClaimSchemaRepository,
            organisation_repository::MockOrganisationRepository,
            proof_schema_repository::MockProofSchemaRepository,
        },
    },
    service::{
        error::{BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError},
        proof_schema::dto::{
            CreateProofSchemaClaimRequestDTO, CreateProofSchemaRequestDTO, GetProofSchemaQueryDTO,
        },
    },
};
use mockall::{predicate::*, PredicateBooleanExt};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

fn setup_service(
    proof_schema_repository: MockProofSchemaRepository,
    claim_schema_repository: MockClaimSchemaRepository,
    organisation_repository: MockOrganisationRepository,
) -> ProofSchemaService {
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    ProofSchemaService {
        proof_schema_repository: Arc::new(proof_schema_repository),
        claim_schema_repository: Arc::new(claim_schema_repository),
        organisation_repository: Arc::new(organisation_repository),
        history_repository: Arc::new(history_repository),
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
                    claim_schemas: Some(ProofSchemaClaimRelations {
                        credential_schema: Some(CredentialSchemaRelations {
                            claim_schemas: None,
                            organisation: None,
                        }),
                    }),
                    organisation: Some(OrganisationRelations::default()),
                    proof_inputs: None,
                }),
            )
            .returning(move |_id, _relations| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(
        proof_schema_repository,
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
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
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
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
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
    );

    let result = service.get_proof_schema(&Uuid::new_v4()).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::EntityNotFound(EntityNotFoundError::ProofSchema(_))
    )));
}

#[tokio::test]
async fn test_get_proof_schema_list_success() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();

    let proof_schema = ProofSchema {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        name: "name".to_string(),
        expire_duration: 0,
        claim_schemas: None,
        organisation: None,
        validity_constraint: None,
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
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
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
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
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
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "name".to_string(),
                expire_duration: 0,
                claim_schemas: None,
                organisation: None,
                validity_constraint: None,
                input_schemas: None,
            }))
        });

    let proof_schema_id = Uuid::new_v4();
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
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
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
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "name".to_string(),
                expire_duration: 0,
                claim_schemas: None,
                organisation: None,
                validity_constraint: None,
                input_schemas: None,
            }))
        });

    proof_schema_repository
        .expect_delete_proof_schema()
        .times(1)
        .returning(|_, _| Err(DataLayerError::RecordNotUpdated));

    let service = setup_service(
        proof_schema_repository,
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
    );

    let result = service.delete_proof_schema(&Uuid::new_v4()).await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::MissingProofSchema { .. }
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_schema_success() {
    let claim_schema_id = Uuid::new_v4();
    let claim_schema = ClaimSchema {
        id: claim_schema_id,
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    };
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .times(1)
        .with(
            eq(vec![claim_schema_id]),
            eq(ClaimSchemaRelations::default()),
        )
        .returning(move |_, _| Ok(vec![claim_schema.clone()]));

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

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: 0,
        organisation_id,
        claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
            id: claim_schema_id,
            required: true,
        }],
        validity_constraint: None,
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
            let claim_schemas = proof_schema.claim_schemas.as_ref().unwrap();
            claim_schemas.len() == 1
                && claim_schemas[0].schema.id == claim_schema_id
                && proof_schema.organisation.as_ref().unwrap().id == organisation_id
                && proof_schema.name == create_request_clone.name
                && proof_schema.expire_duration == create_request_clone.expire_duration
        })
        .returning(|request| Ok(request.id));

    let service = setup_service(
        proof_schema_repository,
        claim_schema_repository,
        organisation_repository,
    );

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_proof_schema_unique_name_error() {
    let claim_schema_id = Uuid::new_v4();
    let organisation_id = Uuid::new_v4().into();

    let create_request = CreateProofSchemaRequestDTO {
        name: "name".to_string(),
        expire_duration: 0,
        organisation_id,
        claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
            id: claim_schema_id,
            required: true,
        }],
        validity_constraint: None,
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
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
    );

    let result = service.create_proof_schema(create_request).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::ProofSchemaAlreadyExists)
    )));
}

#[tokio::test]
async fn test_create_proof_schema_claims_dont_exist() {
    let claim_schema_id = Uuid::new_v4();
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .times(1)
        .returning(|_, _| {
            Err(DataLayerError::IncompleteClaimsSchemaList {
                expected: 1,
                got: 0,
            })
        });

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
        claim_schema_repository,
        MockOrganisationRepository::default(),
    );

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: 0,
            organisation_id: Uuid::new_v4().into(),
            claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                id: claim_schema_id,
                required: true,
            }],
            validity_constraint: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::MissingClaimSchemas
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_schema_no_claims() {
    let service = setup_service(
        MockProofSchemaRepository::default(),
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
    );

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: 0,
            organisation_id: Uuid::new_v4().into(),
            claim_schemas: vec![],
            validity_constraint: None,
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
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
    );

    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: 0,
            organisation_id: Uuid::new_v4().into(),
            claim_schemas: vec![CreateProofSchemaClaimRequestDTO {
                id: Uuid::new_v4(),
                required: false,
            }],
            validity_constraint: None,
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
        MockClaimSchemaRepository::default(),
        MockOrganisationRepository::default(),
    );

    let claim_schema = CreateProofSchemaClaimRequestDTO {
        id: Uuid::new_v4(),
        required: true,
    };
    let result = service
        .create_proof_schema(CreateProofSchemaRequestDTO {
            name: "name".to_string(),
            expire_duration: 0,
            organisation_id: Uuid::new_v4().into(),
            claim_schemas: vec![claim_schema.clone(), claim_schema],
            validity_constraint: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::ProofSchemaDuplicitClaim
        ))
    ));
}

fn generic_proof_schema() -> ProofSchema {
    ProofSchema {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        name: "name".to_string(),
        expire_duration: 0,
        claim_schemas: Some(vec![]),
        organisation: Some(Organisation {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
        validity_constraint: None,
        input_schemas: None,
    }
}
