use super::CredentialService;
use crate::{
    config::data_structure::CoreConfig,
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::{Credential, CredentialState, CredentialStateEnum, GetCredentialList},
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::{Did, DidType},
        organisation::Organisation,
    },
    repository::mock::{
        credential_repository::MockCredentialRepository,
        credential_schema_repository::MockCredentialSchemaRepository,
        did_repository::MockDidRepository,
    },
    revocation::mock::revocation_method_provider::MockRevocationMethodProvider,
    service::{
        credential::dto::{
            CreateCredentialRequestDTO, CredentialRequestClaimDTO, GetCredentialQueryDTO,
        },
        error::ServiceError,
        test_utilities::generic_config,
    },
};
use mockall::predicate::*;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

fn setup_service(
    repository: MockCredentialRepository,
    credential_schema_repository: MockCredentialSchemaRepository,
    did_repository: MockDidRepository,
    revocation_method_provider: MockRevocationMethodProvider,
    config: CoreConfig,
) -> CredentialService {
    CredentialService::new(
        Arc::new(repository),
        Arc::new(credential_schema_repository),
        Arc::new(did_repository),
        Arc::new(revocation_method_provider),
        Arc::new(config),
    )
}

fn generic_credential() -> Credential {
    let now = OffsetDateTime::now_utc();

    let claim_schema = ClaimSchema {
        id: Uuid::new_v4(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
    };
    let organisation = Organisation {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
    };

    Credential {
        id: Uuid::new_v4(),
        created_date: now,
        issuance_date: now,
        last_modified: now,
        credential: vec![],
        transport: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
        }]),
        claims: Some(vec![Claim {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            value: "123".to_string(),
            schema: Some(claim_schema.clone()),
        }]),
        issuer_did: Some(Did {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            name: "did1".to_string(),
            organisation: Some(organisation.clone()),
            did: "did1".to_string(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: None,
        }),
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: claim_schema,
                required: true,
            }]),
            organisation: Some(organisation),
        }),
        interaction: None,
        revocation_list: None,
    }
}

#[tokio::test]
async fn test_get_credential_list_success() {
    let mut repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();
    let now = OffsetDateTime::now_utc();
    let mut c = generic_credential().clone();
    c.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Revoked,
    }]);

    let credentials = GetCredentialList {
        values: vec![generic_credential(), c],
        total_pages: 1,
        total_items: 2,
    };
    {
        let clone = credentials.clone();
        repository
            .expect_get_credential_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(
        repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        generic_config(),
    );

    let result = service
        .get_credential_list(GetCredentialQueryDTO {
            page: 0,
            page_size: 5,
            sort: None,
            sort_direction: None,
            name: None,
            exact: None,
            organisation_id: credentials.values[0]
                .schema
                .clone()
                .unwrap()
                .organisation
                .unwrap()
                .id
                .to_string(),
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(2, result.total_items);
    assert_eq!(1, result.total_pages);
    assert_eq!(2, result.values.len());
    assert_eq!(credentials.values[0].id, result.values[0].id);
    assert_eq!(None, result.values[0].revocation_date);
    assert_ne!(None, result.values[1].revocation_date);
}

#[tokio::test]
async fn test_get_credential_success() {
    let mut repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let credential = generic_credential();
    {
        let clone = credential.clone();
        repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(clone.clone()));
    }

    let service = setup_service(
        repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        generic_config(),
    );

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.id, result.id);
    assert_eq!(None, result.revocation_date);
}

#[tokio::test]
async fn test_get_revoked_credential_success() {
    let mut repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();
    let now = OffsetDateTime::now_utc();

    let mut credential = generic_credential();
    credential.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Revoked,
    }]);

    {
        let clone = credential.clone();
        repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(clone.clone()));
    }

    let service = setup_service(
        repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        generic_config(),
    );

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.id, result.id);
    assert_ne!(None, result.revocation_date);
}

#[tokio::test]
async fn test_get_credential_fail_credential_schema_is_none() {
    let mut repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut credential = generic_credential();
    credential.schema = None;
    {
        let clone = credential.clone();
        repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(clone.clone()));
    }

    let service = setup_service(
        repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        generic_config(),
    );

    let result = service.get_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(e, ServiceError::MappingError(_))));
}

#[tokio::test]
async fn test_share_credential_success() {
    let mut repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let credential = generic_credential();
    {
        let clone = credential.clone();
        repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(clone.clone()));
        repository
            .expect_update_credential()
            .times(1)
            .returning(move |_| Ok(()));
    }

    let service = setup_service(
        repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        generic_config(),
    );

    let result = service.share_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.id, result.id);
    assert_eq!("PROCIVIS_TEMPORARY", result.transport);
}

#[tokio::test]
async fn test_share_credential_failed_invalid_state() {
    let mut repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut credential = generic_credential();
    credential.state.as_mut().unwrap()[0].state = CredentialStateEnum::Accepted;
    {
        let clone = credential.clone();
        repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(clone.clone()));
    }

    let service = setup_service(
        repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        generic_config(),
    );

    let result = service.share_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(e, ServiceError::AlreadyExists)));
}

#[tokio::test]
async fn test_create_credential_success() {
    let mut repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let credential = generic_credential();
    {
        let clone = credential.clone();
        let issuer_did = credential.issuer_did.clone().unwrap();
        let credential_schema = credential.schema.clone().unwrap();

        did_repository
            .expect_get_did()
            .times(1)
            .returning(move |_, _| Ok(issuer_did.clone()));

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_, _| Ok(credential_schema.clone()));

        repository
            .expect_create_credential()
            .times(1)
            .returning(move |_| Ok(clone.id));
    }

    let service = setup_service(
        repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        generic_config(),
    );

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
            transport: "PROCIVIS_TEMPORARY".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
            }],
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_one_required_claim_missing() {
    let mut repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let credential = generic_credential();
    let credential_schema = CredentialSchema {
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4(),
                    key: "required".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4(),
                    key: "optional".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                },
                required: false,
            },
        ]),
        ..credential.schema.clone().unwrap()
    };

    {
        let clone = credential.clone();
        let issuer_did = credential.issuer_did.clone().unwrap();
        let credential_schema_clone = credential_schema.clone();
        did_repository
            .expect_get_did()
            .returning(move |_, _| Ok(issuer_did.clone()));

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_, _| Ok(credential_schema_clone.clone()));

        repository
            .expect_create_credential()
            .times(1)
            .returning(move |_| Ok(clone.id));
    }

    let service = setup_service(
        repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        generic_config(),
    );

    let required_claim_schema_id = credential_schema.claim_schemas.as_ref().unwrap()[0]
        .schema
        .id
        .to_owned();
    let optional_claim_schema_id = credential_schema.claim_schemas.as_ref().unwrap()[1]
        .schema
        .id
        .to_owned();
    let create_request_template = CreateCredentialRequestDTO {
        credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
        issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
        transport: "PROCIVIS_TEMPORARY".to_string(),
        claim_values: vec![],
    };

    // create a credential with only an optional claim fails
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: optional_claim_schema_id,
                value: "value".to_string(),
            }],
            ..create_request_template.clone()
        })
        .await;
    assert!(matches!(result, Err(ServiceError::IncorrectParameters)));

    // create a credential with required claims only succeeds
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: required_claim_schema_id,
                value: "value".to_string(),
            }],
            ..create_request_template
        })
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_schema_deleted() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let credential = generic_credential();
    let credential_schema = CredentialSchema {
        deleted_at: Some(OffsetDateTime::now_utc()),
        ..credential.schema.clone().unwrap()
    };

    {
        let issuer_did = credential.issuer_did.clone().unwrap();
        let credential_schema_clone = credential_schema.clone();
        did_repository
            .expect_get_did()
            .returning(move |_, _| Ok(issuer_did.clone()));

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_, _| Ok(credential_schema_clone.clone()));
    }

    let service = setup_service(
        MockCredentialRepository::default(),
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        generic_config(),
    );

    let claim_schema_id = credential_schema.claim_schemas.as_ref().unwrap()[0]
        .schema
        .id
        .to_owned();

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
            transport: "PROCIVIS_TEMPORARY".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id,
                value: "value".to_string(),
            }],
        })
        .await;
    assert!(matches!(result, Err(ServiceError::NotFound)));
}
