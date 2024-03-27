use super::CredentialService;
use crate::model::credential_schema::{CredentialSchemaType, LayoutType, WalletStorageTypeEnum};
use crate::provider::revocation::{CredentialRevocationState, RevocationMethodCapabilities};
use crate::repository::lvvc_repository::MockLvvcRepository;
use crate::service::credential::dto::{
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
    SuspendCredentialRequestDTO,
};
use crate::service::credential::mapper::renest_claims;
use crate::service::credential::validator::validate_create_request;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
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
            FormatterCapabilities, MockCredentialFormatter,
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
use std::ops::Add;
use std::{collections::HashMap, sync::Arc};
use time::{Duration, OffsetDateTime};
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
        id: Uuid::new_v4().into(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
    };
    let organisation = Organisation {
        id: Uuid::new_v4().into(),
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
            suspend_end_date: None,
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
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: claim_schema,
                required: true,
            }]),
            organisation: Some(organisation),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
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
            suspend_end_date: None,
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
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: None,
            organisation: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
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
        suspend_end_date: None,
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
        suspend_end_date: None,
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
            filtering: Some(
                CredentialFilterValue::OrganisationId(Uuid::new_v4().into()).condition(),
            ),
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
async fn test_get_credential_success_suspended_credential_with_end_date() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let mut credential = generic_credential();
    let now = OffsetDateTime::now_utc();
    let suspend_end_date = now.add(Duration::hours(1));
    credential.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Suspended,
        suspend_end_date: Some(suspend_end_date),
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
    assert_eq!(None, result.revocation_date);
    assert_eq!(
        credential::dto::CredentialStateEnum::Suspended,
        result.state
    );
    assert_eq!(Some(suspend_end_date), result.suspend_end_date);
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
        suspend_end_date: None,
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

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_string()],
            features: vec![],
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        formatter_provider,
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
                    id: Uuid::new_v4().into(),
                    key: "required".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
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

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_string()],
            features: vec![],
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .with(eq(credential_schema.format))
        .return_once(move |_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        formatter_provider,
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

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_| {
            Ok(DetailCredential {
                id: None,
                issued_at: None,
                expires_at: None,
                invalid_before: None,
                issuer_did: None,
                subject: None,
                claims: CredentialSubject {
                    values: Default::default(),
                },
                status: vec![],
                credential_schema: None,
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
            suspend_end_date: None,
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
            suspend_end_date: None,
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

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_| {
            Ok(DetailCredential {
                id: None,
                issued_at: None,
                expires_at: None,
                invalid_before: None,
                issuer_did: None,
                subject: None,
                claims: CredentialSubject {
                    values: Default::default(),
                },
                status: vec![CredentialStatus {
                    id: "id".to_string(),
                    r#type: "type".to_string(),
                    status_purpose: Some("purpose".to_string()),
                    additional_fields: HashMap::default(),
                }],
                credential_schema: None,
            })
        });

    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _, _| Ok(CredentialRevocationState::Revoked));

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
            suspend_end_date: None,
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
async fn test_create_credential_key_with_issuer_key() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();

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

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_string()],
            features: vec![],
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        formatter_provider,
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
async fn test_create_credential_key_with_issuer_key_and_repeating_key() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();

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

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_string()],
            features: vec![],
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        did_repository,
        history_repository,
        formatter_provider,
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
async fn test_fail_to_create_credential_no_assertion_key() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();

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

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_string()],
            features: vec![],
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        did_repository,
        formatter_provider,
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
async fn test_fail_to_create_credential_unknown_key_id() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();

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

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_string()],
            features: vec![],
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        did_repository,
        formatter_provider,
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
async fn test_fail_to_create_credential_key_id_points_to_wrong_key_role() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();

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

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_string()],
            features: vec![],
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        did_repository,
        formatter_provider,
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

#[tokio::test]
async fn test_fail_to_create_credential_key_id_points_to_unsupported_key_algorithm() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut did_repository = MockDidRepository::default();

    let credential = generic_credential();
    let key_id = Uuid::new_v4();
    let issuer_did = Did {
        keys: Some(vec![RelatedKey {
            role: KeyRole::AssertionMethod,
            key: Key {
                id: key_id.into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: vec![],
                storage_type: "INTERNAL".to_string(),
                key_type: "unsupported".to_string(),
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

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_string()],
            features: vec![],
        });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        did_repository,
        formatter_provider,
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

#[tokio::test]
async fn test_revoke_credential_success_with_accepted_credential() {
    let now = OffsetDateTime::now_utc();

    let mut credential = generic_credential();
    credential.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
    }]);

    let mut credential_repository = MockCredentialRepository::default();
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .once()
        .return_once(move || RevocationMethodCapabilities {
            operations: vec!["REVOKE".to_string()],
        });
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(CredentialRevocationState::Revoked))
        .return_once(move |_, _| Ok(()));

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |request| {
            assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap().state);
            Ok(())
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    service.revoke_credential(&credential.id).await.unwrap();
}

#[tokio::test]
async fn test_revoke_credential_success_with_suspended_credential() {
    let now = OffsetDateTime::now_utc();

    let mut credential = generic_credential();
    credential.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Suspended,
        suspend_end_date: None,
    }]);

    let mut credential_repository = MockCredentialRepository::default();
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .once()
        .return_once(move || RevocationMethodCapabilities {
            operations: vec!["REVOKE".to_string()],
        });
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(CredentialRevocationState::Revoked))
        .return_once(move |_, _| Ok(()));

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |request| {
            assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap().state);
            Ok(())
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    service.revoke_credential(&credential.id).await.unwrap();
}

#[tokio::test]
async fn test_suspend_credential_success() {
    let now = OffsetDateTime::now_utc();

    let mut credential = generic_credential();
    credential.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
    }]);

    let suspend_end_date = now.add(Duration::days(1));

    let mut credential_repository = MockCredentialRepository::default();
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .once()
        .return_once(move || RevocationMethodCapabilities {
            operations: vec!["SUSPEND".to_string()],
        });
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(
            always(),
            eq(CredentialRevocationState::Suspended {
                suspend_end_date: Some(suspend_end_date),
            }),
        )
        .return_once(move |_, _| Ok(()));

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |request| {
            assert_eq!(CredentialStateEnum::Suspended, request.state.unwrap().state);
            Ok(())
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    service
        .suspend_credential(
            &credential.id,
            SuspendCredentialRequestDTO {
                suspend_end_date: Some(suspend_end_date),
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_suspend_credential_failed_cannot_suspend_revoked_credential() {
    let now = OffsetDateTime::now_utc();

    let mut credential = generic_credential();
    credential.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Revoked,
        suspend_end_date: None,
    }]);

    let mut credential_repository = MockCredentialRepository::default();
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
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .suspend_credential(
            &credential.id,
            SuspendCredentialRequestDTO {
                suspend_end_date: None,
            },
        )
        .await
        .unwrap_err();

    assert!(matches!(
        result,
        ServiceError::BusinessLogic(BusinessLogicError::InvalidCredentialState { .. })
    ));
}

#[tokio::test]
async fn test_reactivate_credential_success() {
    let now = OffsetDateTime::now_utc();

    let mut credential = generic_credential();
    credential.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Suspended,
        suspend_end_date: None,
    }]);

    let mut credential_repository = MockCredentialRepository::default();
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));
    }

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .once()
        .return_once(move || RevocationMethodCapabilities {
            operations: vec!["SUSPEND".to_string()],
        });
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(CredentialRevocationState::Valid))
        .return_once(move |_, _| Ok(()));

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |request| {
            assert_eq!(CredentialStateEnum::Accepted, request.state.unwrap().state);
            Ok(())
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        history_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    service.reactivate_credential(&credential.id).await.unwrap();
}

#[tokio::test]
async fn test_reactivate_credential_failed_cannot_reactivate_revoked_credential() {
    let now = OffsetDateTime::now_utc();

    let mut credential = generic_credential();
    credential.state = Some(vec![CredentialState {
        created_date: now,
        state: CredentialStateEnum::Revoked,
        suspend_end_date: None,
    }]);

    let mut credential_repository = MockCredentialRepository::default();
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
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .reactivate_credential(&credential.id)
        .await
        .unwrap_err();

    assert!(matches!(
        result,
        ServiceError::BusinessLogic(BusinessLogicError::InvalidCredentialState { .. })
    ));
}

fn generate_credential_schema_with_claim_schemas(
    claim_schemas: Vec<CredentialSchemaClaim>,
) -> CredentialSchema {
    let now = OffsetDateTime::now_utc();
    CredentialSchema {
        id: Uuid::new_v4(),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: "nested".to_string(),
        format: "".to_string(),
        revocation_method: "".to_string(),
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "".to_string(),
        claim_schemas: Some(claim_schemas),
        organisation: None,
    }
}

#[test]
fn test_validate_create_request_all_nested_claims_are_required() {
    let address_claim_id = Uuid::new_v4().into();
    let location_claim_id = Uuid::new_v4().into();
    let location_x_claim_id = Uuid::new_v4().into();
    let location_y_claim_id = Uuid::new_v4().into();

    let now = OffsetDateTime::now_utc();
    let schema = generate_credential_schema_with_claim_schemas(vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: address_claim_id,
                key: "address".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: location_claim_id,
                key: "location".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: location_x_claim_id,
                key: "location/x".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: location_y_claim_id,
                key: "location/y".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
    ]);

    validate_create_request(
        "PROCIVIS_TEMPORARY",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_y_claim_id,
                value: "456".to_string(),
            },
        ],
        &schema,
        &generic_config().core,
    )
    .unwrap();
}

#[test]
fn test_validate_create_request_all_optional_nested_object_with_required_claims() {
    let address_claim_id = Uuid::new_v4().into();
    let location_claim_id = Uuid::new_v4().into();
    let location_x_claim_id = Uuid::new_v4().into();
    let location_y_claim_id = Uuid::new_v4().into();

    let now = OffsetDateTime::now_utc();
    let schema = generate_credential_schema_with_claim_schemas(vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: address_claim_id,
                key: "address".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: location_claim_id,
                key: "location".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: false,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: location_x_claim_id,
                key: "location/x".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: location_y_claim_id,
                key: "location/y".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
    ]);

    validate_create_request(
        "PROCIVIS_TEMPORARY",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_y_claim_id,
                value: "456".to_string(),
            },
        ],
        &schema,
        &generic_config().core,
    )
    .unwrap();

    validate_create_request(
        "PROCIVIS_TEMPORARY",
        &[CredentialRequestClaimDTO {
            claim_schema_id: address_claim_id,
            value: "Somewhere".to_string(),
        }],
        &schema,
        &generic_config().core,
    )
    .unwrap();

    let result = validate_create_request(
        "PROCIVIS_TEMPORARY",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
            },
        ],
        &schema,
        &generic_config().core,
    );
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::CredentialMissingClaim { .. }
        ))
    ));
}

#[test]
fn test_validate_create_request_all_required_nested_object_with_optional_claims() {
    let address_claim_id = Uuid::new_v4().into();
    let location_claim_id = Uuid::new_v4().into();
    let location_x_claim_id = Uuid::new_v4().into();
    let location_y_claim_id = Uuid::new_v4().into();

    let now = OffsetDateTime::now_utc();
    let schema = generate_credential_schema_with_claim_schemas(vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: address_claim_id,
                key: "address".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: location_claim_id,
                key: "location".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: location_x_claim_id,
                key: "location/x".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: location_y_claim_id,
                key: "location/y".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: false,
        },
    ]);

    validate_create_request(
        "PROCIVIS_TEMPORARY",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_y_claim_id,
                value: "456".to_string(),
            },
        ],
        &schema,
        &generic_config().core,
    )
    .unwrap();

    let result = validate_create_request(
        "PROCIVIS_TEMPORARY",
        &[CredentialRequestClaimDTO {
            claim_schema_id: address_claim_id,
            value: "Somewhere".to_string(),
        }],
        &schema,
        &generic_config().core,
    );
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::CredentialMissingClaim { .. }
        ))
    ));

    validate_create_request(
        "PROCIVIS_TEMPORARY",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
            },
        ],
        &schema,
        &generic_config().core,
    )
    .unwrap();
}

#[test]
fn test_renest_claims_success_single_claim_and_layer() {
    let now = OffsetDateTime::now_utc();

    let uuid_location = Uuid::new_v4().into();
    let uuid_location_x = Uuid::new_v4().into();

    let request = vec![
        DetailCredentialClaimResponseDTO {
            schema: CredentialClaimSchemaDTO {
                id: uuid_location,
                created_date: now,
                last_modified: now,
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![],
            },
            value: DetailCredentialClaimValueResponseDTO::Nested(vec![]),
        },
        DetailCredentialClaimResponseDTO {
            schema: CredentialClaimSchemaDTO {
                id: uuid_location_x,
                created_date: now,
                last_modified: now,
                key: "location/x".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            },
            value: DetailCredentialClaimValueResponseDTO::String("123".to_string()),
        },
    ];

    let expected = vec![DetailCredentialClaimResponseDTO {
        schema: CredentialClaimSchemaDTO {
            id: uuid_location,
            created_date: now,
            last_modified: now,
            key: "location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        value: DetailCredentialClaimValueResponseDTO::Nested(vec![
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id: uuid_location_x,
                    created_date: now,
                    last_modified: now,
                    key: "x".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    claims: vec![],
                },
                value: DetailCredentialClaimValueResponseDTO::String("123".to_string()),
            },
        ]),
    }];

    assert_eq!(expected, renest_claims(request).unwrap());
}

#[test]
fn test_renest_claims_success_multiple_claims_and_layers() {
    let now = OffsetDateTime::now_utc();

    let uuid_location = Uuid::new_v4().into();
    let uuid_location_x = Uuid::new_v4().into();

    let request = vec![
        DetailCredentialClaimResponseDTO {
            schema: CredentialClaimSchemaDTO {
                id: uuid_location,
                created_date: now,
                last_modified: now,
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: true,
                claims: vec![],
            },
            value: DetailCredentialClaimValueResponseDTO::Nested(vec![]),
        },
        DetailCredentialClaimResponseDTO {
            schema: CredentialClaimSchemaDTO {
                id: uuid_location_x,
                created_date: now,
                last_modified: now,
                key: "location/x".to_string(),
                datatype: "STRING".to_string(),
                required: true,
                claims: vec![],
            },
            value: DetailCredentialClaimValueResponseDTO::String("123".to_string()),
        },
    ];

    let expected = vec![DetailCredentialClaimResponseDTO {
        schema: CredentialClaimSchemaDTO {
            id: uuid_location,
            created_date: now,
            last_modified: now,
            key: "location".to_string(),
            datatype: "OBJECT".to_string(),
            required: true,
            claims: vec![],
        },
        value: DetailCredentialClaimValueResponseDTO::Nested(vec![
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id: uuid_location_x,
                    created_date: now,
                    last_modified: now,
                    key: "x".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    claims: vec![],
                },
                value: DetailCredentialClaimValueResponseDTO::String("123".to_string()),
            },
        ]),
    }];

    assert_eq!(expected, renest_claims(request).unwrap());
}

#[tokio::test]
async fn test_get_credential_success_with_non_required_nested_object() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();
    let did_repository = MockDidRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();

    let now = OffsetDateTime::now_utc();

    let location_claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
    };
    let location_x_claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "location/X".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
    };

    let mut credential = generic_credential();

    *credential
        .schema
        .as_mut()
        .unwrap()
        .claim_schemas
        .as_mut()
        .unwrap() = vec![
        CredentialSchemaClaim {
            schema: location_claim_schema,
            required: false,
        },
        CredentialSchemaClaim {
            schema: location_x_claim_schema.to_owned(),
            required: false,
        },
    ];

    *credential.claims.as_mut().unwrap() = vec![Claim {
        id: Uuid::new_v4(),
        credential_id: credential.id,
        created_date: now,
        last_modified: now,
        value: "123".to_string(),
        schema: Some(location_x_claim_schema.clone()),
    }];

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

    let result = service.get_credential(&credential.id).await.unwrap();
    assert_eq!(credential.id, result.id);
    assert_eq!(None, result.revocation_date);
    assert_eq!(1, result.claims.len());
    assert_eq!("location", result.claims[0].schema.key);
    assert!(matches!(
        result.claims[0].value,
        DetailCredentialClaimValueResponseDTO::Nested(_)
    ));
}
