use super::CredentialService;
use crate::repository::lvvc_repository::MockLvvcRepository;
use crate::{
    config::core_config::CoreConfig,
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::{
            Credential, CredentialRole, CredentialState, CredentialStateEnum, GetCredentialList,
            UpdateCredentialRequest,
        },
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::{Did, DidType, KeyRole, RelatedKey},
        key::Key,
        list_filter::ListFilterValue as _,
        list_query::ListPagination,
        organisation::Organisation,
    },
    provider::{
        credential_formatter::{
            model::{CredentialStatus, CredentialSubject, DetailCredential},
            provider::MockCredentialFormatterProvider,
            MockCredentialFormatter,
        },
        revocation::{provider::MockRevocationMethodProvider, MockRevocationMethod},
        transport_protocol::{provider::MockTransportProtocolProvider, MockTransportProtocol},
    },
    repository::{
        credential_repository::MockCredentialRepository,
        credential_schema_repository::MockCredentialSchemaRepository,
        did_repository::MockDidRepository, history_repository::MockHistoryRepository,
    },
    service::{
        credential::{
            self,
            dto::{
                CreateCredentialRequestDTO, CredentialFilterValue, CredentialRequestClaimDTO,
                GetCredentialQueryDTO,
            },
        },
        error::{BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError},
        test_utilities::generic_config,
    },
};
use mockall::predicate::*;
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
struct Repositories {
    pub credential_repository: MockCredentialRepository,
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub did_repository: MockDidRepository,
    pub history_repository: MockHistoryRepository,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub protocol_provider: MockTransportProtocolProvider,
    pub config: CoreConfig,
    pub lvvc_repository: MockLvvcRepository,
}

fn setup_service(repositories: Repositories) -> CredentialService {
    CredentialService::new(
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.credential_schema_repository),
        Arc::new(repositories.did_repository),
        Arc::new(repositories.history_repository),
        Arc::new(repositories.revocation_method_provider),
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.protocol_provider),
        Arc::new(repositories.config),
        Arc::new(repositories.lvvc_repository),
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

    let credential_id = Uuid::new_v4().into();
    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        transport: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
        }]),
        claims: Some(vec![Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: "123".to_string(),
            schema: Some(claim_schema.clone()),
        }]),
        issuer_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "did1".to_string(),
            organisation: Some(organisation.clone()),
            did: "did1".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            keys: Some(vec![RelatedKey {
                role: KeyRole::AssertionMethod,
                key: Key {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    public_key: vec![],
                    name: "key_name".to_string(),
                    key_reference: vec![],
                    storage_type: "INTERNAL".to_string(),
                    key_type: "EDDSA".to_string(),
                    organisation: None,
                },
            }]),
            deactivated: false,
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
        key: None,
    }
}

fn generic_credential_list_entity() -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: Uuid::new_v4().into(),
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        transport: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
        }]),
        claims: None,
        issuer_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "did1".to_string(),
            organisation: None,
            did: "did1".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            keys: None,
            deactivated: false,
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
            claim_schemas: None,
            organisation: None,
        }),
        interaction: None,
        revocation_list: None,
        key: None,
    }
}

#[tokio::test]
async fn test_delete_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    credential_repository
        .expect_get_credential()
        .returning(|_, _| Ok(Some(generic_credential())));
    credential_repository
        .expect_delete_credential()
        .returning(|_| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    service
        .delete_credential(&generic_credential().id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_delete_credential_failed_credential_missing() {
    let mut credential_repository = MockCredentialRepository::default();

    credential_repository
        .expect_get_credential()
        .returning(|_, _| Ok(None));

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.delete_credential(&generic_credential().id).await;
    assert!(matches!(
        result,
        Err(ServiceError::EntityNotFound(
            EntityNotFoundError::Credential(_)
        ))
    ));
}

#[tokio::test]
async fn test_delete_credential_incorrect_state() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut credential = generic_credential();
    credential.schema.as_mut().unwrap().revocation_method = "BITSTRINGSTATUSLIST".to_string();
    credential.state = Some(vec![CredentialState {
        created_date: OffsetDateTime::now_utc(),
        state: CredentialStateEnum::Accepted,
    }]);

    let copy = credential.clone();
    credential_repository
        .expect_get_credential()
        .returning(move |_, _| Ok(Some(copy.clone())));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.delete_credential(&credential.id).await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::InvalidCredentialState { .. }
        ))
    ));
}

#[tokio::test]
async fn test_get_credential_list_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();
    let now = OffsetDateTime::now_utc();
    let mut c = generic_credential_list_entity();
    c.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Revoked,
    }]);

    let credentials = GetCredentialList {
        values: vec![generic_credential_list_entity(), c],
        total_pages: 1,
        total_items: 2,
    };
    {
        let clone = credentials.clone();
        credential_repository
            .expect_get_credential_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .get_credential_list(GetCredentialQueryDTO {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            sorting: None,
            filtering: Some(CredentialFilterValue::OrganisationId(Uuid::new_v4()).condition()),
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
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let credential = generic_credential();
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.id, result.id);
    assert_eq!(None, result.revocation_date);
}

#[tokio::test]
async fn test_get_credential_deleted() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let credential = Credential {
        deleted_at: Some(OffsetDateTime::now_utc()),
        ..generic_credential()
    };
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::EntityNotFound(EntityNotFoundError::Credential(_))
    )));
}

#[tokio::test]
async fn test_get_revoked_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();
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
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.id, result.id);
    assert_ne!(None, result.revocation_date);
}

#[tokio::test]
async fn test_get_credential_fail_credential_schema_is_none() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut credential = generic_credential();
    credential.schema = None;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(e, ServiceError::ResponseMapping(_))));
}

#[tokio::test]
async fn test_share_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut protocol = MockTransportProtocol::default();
    let mut protocol_provider = MockTransportProtocolProvider::default();

    let expected_url = "test_url";
    protocol
        .expect_share_credential()
        .times(1)
        .returning(|_| Ok(expected_url.to_owned()));

    let protocol = Arc::new(protocol);

    protocol_provider
        .expect_get_protocol()
        .times(1)
        .returning(move |_| Some(protocol.clone()));

    let credential = generic_credential();
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
        credential_repository
            .expect_update_credential()
            .times(1)
            .returning(move |_| Ok(()));
    }

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        history_repository,
        config: generic_config().core,
        protocol_provider,
        ..Default::default()
    });

    let result: Result<crate::model::common::EntityShareResponseDTO, ServiceError> =
        service.share_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.url, expected_url);
}

#[tokio::test]
async fn test_share_credential_failed_invalid_state() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut credential = generic_credential();
    credential.state.as_mut().unwrap()[0].state = CredentialStateEnum::Accepted;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::InvalidCredentialState { .. })
    )));
}

#[tokio::test]
async fn test_create_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .times(1)
        .returning(|history| Ok(history.id));

    let credential = generic_credential();
    {
        let clone = credential.clone();
        let issuer_did = credential.issuer_did.clone().unwrap();
        let credential_schema = credential.schema.clone().unwrap();

        did_repository
            .expect_get_did()
            .times(1)
            .returning(move |_, _| Ok(Some(issuer_did.clone())));

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_, _| Ok(Some(credential_schema.clone())));

        credential_repository
            .expect_create_credential()
            .times(1)
            .returning(move |_| Ok(clone.id));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
            issuer_key: None,
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
            redirect_uri: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_fails_if_did_is_deactivated() {
    let mut did_repository = MockDidRepository::default();
    let did_id = Uuid::new_v4();

    did_repository
        .expect_get_did()
        .once()
        .returning(move |_, _| {
            Ok(Some(Did {
                id: did_id.into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did1".to_string(),
                organisation: None,
                did: "did1".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                keys: None,
                deactivated: true,
            }))
        });

    let service = setup_service(Repositories {
        did_repository,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: Uuid::new_v4(),
            issuer_did: did_id.into(),
            issuer_key: None,
            transport: "PROCIVIS_TEMPORARY".to_string(),
            claim_values: vec![],
            redirect_uri: None,
        })
        .await;

    assert2::assert!(
        let ServiceError::BusinessLogic(BusinessLogicError::DidIsDeactivated(_)) = result.err().unwrap()
    );
}

#[tokio::test]
async fn test_create_credential_one_required_claim_missing() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .times(1)
        .returning(|history| Ok(history.id));

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
            .returning(move |_, _| Ok(Some(issuer_did.clone())));

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_, _| Ok(Some(credential_schema_clone.clone())));

        credential_repository
            .expect_create_credential()
            .times(1)
            .returning(move |_| Ok(clone.id));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

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
        issuer_key: None,
        transport: "PROCIVIS_TEMPORARY".to_string(),
        claim_values: vec![],
        redirect_uri: None,
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
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::CredentialMissingClaim { .. }
        ))
    ));

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
            .returning(move |_, _| Ok(Some(issuer_did.clone())));

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_, _| Ok(Some(credential_schema_clone.clone())));
    }

    let service = setup_service(Repositories {
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let claim_schema_id = credential_schema.claim_schemas.as_ref().unwrap()[0]
        .schema
        .id
        .to_owned();

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
            issuer_key: None,
            transport: "PROCIVIS_TEMPORARY".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id,
                value: "value".to_string(),
            }],
            redirect_uri: None,
        })
        .await;

    assert2::assert!(
        let Err(ServiceError::BusinessLogic(
            BusinessLogicError::MissingCredentialSchema
        )) = result
    );
}

#[tokio::test]
async fn test_check_revocation_invalid_state() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let credential = generic_credential();
    {
        let credential_clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .returning(move |_, _| Ok(Some(credential_clone.clone())));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.check_revocation(vec![credential.id]).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].credential_id, credential.id);
    assert!(!result[0].success);
    assert_eq!(
        result[0].status,
        credential::dto::CredentialStateEnum::Created
    );
}

#[tokio::test]
async fn test_check_revocation_non_revocable() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    formatter.expect_peek().returning(|_| {
        Ok(DetailCredential {
            id: None,
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer_did: None,
            subject: None,
            claims: CredentialSubject {
                values: HashMap::default(),
            },
            status: None,
        })
    });

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter()
        .returning(move |_| Some(formatter.clone()));

    revocation_method_provider
        .expect_get_revocation_method()
        .returning(|_| Some(Arc::new(MockRevocationMethod::default())));

    let credential = Credential {
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
        }]),
        ..generic_credential()
    };

    {
        let credential_clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .returning(move |_, _| Ok(Some(credential_clone.clone())));
    }

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .check_revocation(vec![credential.id, Uuid::new_v4().into()])
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].credential_id, credential.id);
    assert!(result[0].success);
    assert_eq!(
        result[0].status,
        credential::dto::CredentialStateEnum::Accepted
    );

    assert!(result[1].success);
    assert_eq!(
        result[1].status,
        credential::dto::CredentialStateEnum::Accepted
    );
}

#[tokio::test]
async fn test_check_revocation_already_revoked() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();
    let formatter_provider = MockCredentialFormatterProvider::default();

    let credential = Credential {
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Revoked,
        }]),
        ..generic_credential()
    };

    {
        let credential_clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .returning(move |_, _| Ok(Some(credential_clone.clone())));
    }
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        formatter_provider,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .check_revocation(vec![credential.id, Uuid::new_v4().into()])
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].credential_id, credential.id);
    assert!(result[0].success);
    assert_eq!(
        result[0].status,
        credential::dto::CredentialStateEnum::Revoked
    );

    assert!(result[1].success);
    assert_eq!(
        result[1].status,
        credential::dto::CredentialStateEnum::Revoked
    );
}

#[tokio::test]
async fn test_check_revocation_being_revoked() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    let mut revocation_method = MockRevocationMethod::default();

    formatter.expect_peek().returning(|_| {
        Ok(DetailCredential {
            id: None,
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer_did: None,
            subject: None,
            claims: CredentialSubject {
                values: HashMap::default(),
            },
            status: Some(CredentialStatus {
                id: "id".to_string(),
                r#type: "type".to_string(),
                status_purpose: "purpose".to_string(),
                additional_fields: HashMap::default(),
            }),
        })
    });

    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _| Ok(true));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter()
        .returning(move |_| Some(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .returning(move |_| Some(revocation_method.clone()));

    let credential = Credential {
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
        }]),
        ..generic_credential()
    };

    {
        let credential_clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .returning(move |_, _| Ok(Some(credential_clone.clone())));
    }

    credential_repository
        .expect_update_credential()
        .withf(|request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialState {
                        state: CredentialStateEnum::Revoked,
                        ..
                    }),
                    ..
                }
            )
        })
        .returning(|_| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        revocation_method_provider,
        history_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.check_revocation(vec![credential.id]).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].credential_id, credential.id);
    assert!(result[0].success);
    assert_eq!(
        result[0].status,
        credential::dto::CredentialStateEnum::Revoked
    );
}

#[tokio::test]
async fn test_create_credentials_key_with_issuer_key() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let credential = generic_credential();
    let issuer_did = credential.issuer_did.clone().unwrap();
    let credential_schema = credential.schema.clone().unwrap();

    did_repository.expect_get_did().times(1).returning({
        let issuer_did = issuer_did.clone();
        move |_, _| Ok(Some(issuer_did.clone()))
    });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    credential_repository
        .expect_create_credential()
        .times(1)
        .returning({
            let credential = credential.clone();
            move |_| Ok(credential.id)
        });

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
            issuer_key: Some(issuer_did.keys.unwrap()[0].key.id),
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
            redirect_uri: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credentials_key_with_issuer_key_and_repeating_key() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let credential = generic_credential();
    let key_id = Uuid::new_v4();
    let issuer_did = Did {
        keys: Some(vec![
            RelatedKey {
                role: KeyRole::KeyAgreement,
                key: Key {
                    id: key_id.into(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    public_key: vec![],
                    name: "key_name".to_string(),
                    key_reference: vec![],
                    storage_type: "INTERNAL".to_string(),
                    key_type: "EDDSA".to_string(),
                    organisation: None,
                },
            },
            RelatedKey {
                role: KeyRole::AssertionMethod,
                key: Key {
                    id: key_id.into(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    public_key: vec![],
                    name: "key_name".to_string(),
                    key_reference: vec![],
                    storage_type: "INTERNAL".to_string(),
                    key_type: "EDDSA".to_string(),
                    organisation: None,
                },
            },
        ]),
        ..credential.issuer_did.clone().unwrap()
    };
    let credential_schema = credential.schema.clone().unwrap();

    did_repository.expect_get_did().times(1).returning({
        let issuer_did = issuer_did.clone();
        move |_, _| Ok(Some(issuer_did.clone()))
    });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    credential_repository
        .expect_create_credential()
        .times(1)
        .returning({
            let credential = credential.clone();
            move |_| Ok(credential.id)
        });

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
            issuer_key: Some(key_id.into()),
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
            redirect_uri: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_fail_to_create_credentials_no_assertion_key() {
    let credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let history_repository = MockHistoryRepository::default();

    let credential = generic_credential();
    let issuer_did = Did {
        keys: Some(vec![RelatedKey {
            role: KeyRole::KeyAgreement,
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: vec![],
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
        }]),
        ..credential.issuer_did.clone().unwrap()
    };

    let credential_schema = credential.schema.clone().unwrap();

    did_repository
        .expect_get_did()
        .times(1)
        .returning(move |_, _| Ok(Some(issuer_did.clone())));

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
            issuer_key: None,
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
            redirect_uri: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::InvalidKey(_)))
    ));
}

#[tokio::test]
async fn test_fail_to_create_credentials_unknown_key_id() {
    let credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let history_repository = MockHistoryRepository::default();

    let credential = generic_credential();
    let issuer_did = credential.issuer_did.clone().unwrap();
    let credential_schema = credential.schema.clone().unwrap();

    did_repository
        .expect_get_did()
        .times(1)
        .returning(move |_, _| Ok(Some(issuer_did.clone())));

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
            issuer_key: Some(Uuid::new_v4().into()),
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
            redirect_uri: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::InvalidKey(_)))
    ));
}

#[tokio::test]
async fn test_fail_to_create_credentials_key_id_points_to_wrong_key_type() {
    let credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let history_repository = MockHistoryRepository::default();

    let credential = generic_credential();
    let key_id = Uuid::new_v4();
    let issuer_did = Did {
        keys: Some(vec![RelatedKey {
            role: KeyRole::KeyAgreement,
            key: Key {
                id: key_id.into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: vec![],
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
        }]),
        ..credential.issuer_did.clone().unwrap()
    };
    let credential_schema = credential.schema.clone().unwrap();

    did_repository
        .expect_get_did()
        .times(1)
        .returning(move |_, _| Ok(Some(issuer_did.clone())));

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer_did: credential.issuer_did.as_ref().unwrap().id.to_owned(),
            issuer_key: Some(key_id.into()),
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
            redirect_uri: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::InvalidKey(_)))
    ));
}
