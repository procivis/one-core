use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;

use mockall::predicate::*;
use serde_json::json;
use shared_types::CredentialId;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::CredentialService;
use crate::config::core_config::{CoreConfig, KeyAlgorithmType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialRole, CredentialStateEnum, GetCredentialList, UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
    WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::Key;
use crate::model::list_filter::ListFilterValue as _;
use crate::model::list_query::ListPagination;
use crate::model::validity_credential::{ValidityCredential, ValidityCredentialType};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, IssuerDetails,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::issuance_protocol::MockIssuanceProtocol;
use crate::provider::issuance_protocol::dto::IssuanceProtocolCapabilities;
use crate::provider::issuance_protocol::openid4vci_draft13::model::ShareResponse;
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::{
    CredentialRevocationState, Operation, RevocationMethodCapabilities, RevocationUpdate,
};
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::revocation_list_repository::MockRevocationListRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::certificate::validator::MockCertificateValidator;
use crate::service::credential;
use crate::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialFilterValue, CredentialRequestClaimDTO,
    DetailCredentialClaimValueResponseDTO, GetCredentialQueryDTO, SuspendCredentialRequestDTO,
};
use crate::service::credential::validator::validate_create_request;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::test_utilities::{
    dummy_did, dummy_did_document, dummy_identifier, dummy_key, dummy_organisation, generic_config,
    generic_formatter_capabilities, get_dummy_date,
};

#[derive(Default)]
struct Repositories {
    pub credential_repository: MockCredentialRepository,
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub identifier_repository: MockIdentifierRepository,
    pub history_repository: MockHistoryRepository,
    pub interaction_repository: MockInteractionRepository,
    pub revocation_list_repository: MockRevocationListRepository,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub protocol_provider: MockIssuanceProtocolProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub key_provider: MockKeyProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub config: CoreConfig,
    pub lvvc_repository: MockValidityCredentialRepository,
    pub certificate_validator: MockCertificateValidator,
}

fn setup_service(repositories: Repositories) -> CredentialService {
    CredentialService::new(
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.credential_schema_repository),
        Arc::new(repositories.identifier_repository),
        Arc::new(repositories.history_repository),
        Arc::new(repositories.interaction_repository),
        Arc::new(repositories.revocation_list_repository),
        Arc::new(repositories.revocation_method_provider),
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.protocol_provider),
        Arc::new(repositories.did_method_provider),
        Arc::new(repositories.key_provider),
        Arc::new(repositories.key_algorithm_provider),
        Arc::new(repositories.config),
        Arc::new(repositories.lvvc_repository),
        None,
        Arc::new(ReqwestClient::default()),
        Arc::new(repositories.certificate_validator),
    )
}

fn generic_credential() -> Credential {
    let now = OffsetDateTime::now_utc();

    let claim_schema = ClaimSchema {
        array: false,
        id: Uuid::new_v4().into(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
    };
    let organisation = dummy_organisation(None);

    let credential_id = Uuid::new_v4().into();
    let issuer_did = Did {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "did1".to_string(),
        organisation: Some(organisation.clone()),
        did: "did:example:1".parse().unwrap(),
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
        log: None,
    };

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(vec![Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: "123".to_string(),
            path: claim_schema.key.clone(),
            schema: Some(claim_schema.clone()),
        }]),
        issuer_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "identifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(issuer_did),
            key: None,
            certificates: None,
        }),
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            external_schema: false,
            imported_source_url: "CORE_URL".to_string(),
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
            allow_suspension: true,
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
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: None,
        issuer_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "identifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "did1".to_string(),
                organisation: None,
                did: "did:example:1".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                keys: None,
                deactivated: false,
                log: None,
            }),
            key: None,
            certificates: None,
        }),
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            external_schema: false,
            revocation_method: "NONE".to_string(),
            claim_schemas: None,
            organisation: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
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

    let mut credential = generic_credential();
    credential.schema.as_mut().unwrap().revocation_method = "BITSTRINGSTATUSLIST".to_string();
    credential.state = CredentialStateEnum::Accepted;
    credential.role = CredentialRole::Issuer;

    let copy = credential.clone();
    credential_repository
        .expect_get_credential()
        .returning(move |_, _| Ok(Some(copy.clone())));

    let service = setup_service(Repositories {
        credential_repository,
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
    let mut c = generic_credential_list_entity();
    c.state = CredentialStateEnum::Revoked;

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
            include: None,
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

    let mut credential = generic_credential();
    let now = OffsetDateTime::now_utc();
    let suspend_end_date = now.add(Duration::hours(1));
    credential.state = CredentialStateEnum::Suspended;
    credential.suspend_end_date = Some(suspend_end_date);

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

    let mut credential = generic_credential();
    credential.state = CredentialStateEnum::Revoked;
    credential.suspend_end_date = None;

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

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.id, result.id);
    assert_ne!(None, result.revocation_date);
}

#[tokio::test]
async fn test_get_credential_fail_credential_schema_is_none() {
    let mut credential_repository = MockCredentialRepository::default();

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
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(e, ServiceError::ResponseMapping(_))));
}

#[tokio::test]
async fn test_share_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut protocol = MockIssuanceProtocol::default();
    let mut protocol_provider = MockIssuanceProtocolProvider::default();

    let expected_url = "test_url";
    let interaction_id = Uuid::new_v4();
    protocol
        .expect_issuer_share_credential()
        .times(1)
        .returning(move |_| {
            Ok(ShareResponse {
                url: expected_url.to_owned(),
                interaction_id,
                context: Default::default(),
            })
        });

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
            .returning(move |_, _| Ok(()));
    }

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_create_interaction()
        .withf(move |interaction| interaction.id == interaction_id)
        .once()
        .returning(|interaction| Ok(interaction.id));

    credential_repository
        .expect_update_credential()
        .once()
        .withf(move |id, _| *id == credential.id)
        .returning(|_, _| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        history_repository,
        config: generic_config().core,
        protocol_provider,
        interaction_repository,
        ..Default::default()
    });

    let result = service.share_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.url, expected_url);
}

#[tokio::test]
async fn test_share_credential_failed_invalid_state() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential();
    credential.state = CredentialStateEnum::Accepted;
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

    let result = service.share_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::InvalidCredentialState { .. })
    )));
}

#[tokio::test]
async fn test_share_credential_failed_inactive_identifier() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential();
    credential.issuer_identifier.as_mut().unwrap().state = IdentifierState::Deactivated;
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

    let result = service.share_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::IdentifierIsDeactivated(_))
    )));
}

#[tokio::test]
async fn test_create_credential_based_on_issuer_did_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential();
    {
        let clone = credential.clone();
        let issuer_did = credential.issuer_identifier.clone().unwrap().did.unwrap();
        let credential_schema = credential.schema.clone().unwrap();

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_, _| {
                Ok(Some(Identifier {
                    did: Some(issuer_did),
                    ..dummy_identifier()
                }))
            });

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
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_based_on_issuer_identifier_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential();
    {
        let clone = credential.clone();
        let issuer_identifier = credential.issuer_identifier.clone().unwrap();
        let credential_schema = credential.schema.clone().unwrap();

        identifier_repository
            .expect_get()
            .return_once(|_, _| Ok(Some(issuer_identifier)));

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
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: Some(credential.issuer_identifier.as_ref().unwrap().id),
            issuer_did: None,
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_failed_unsupported_wallet_storage_type() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let Credential {
        schema,
        claims,
        issuer_identifier,
        ..
    } = generic_credential();

    let mut schema = schema.unwrap();
    let claims = claims.unwrap();
    let issuer_identifier = issuer_identifier.unwrap();

    schema.wallet_storage_type = Some(WalletStorageTypeEnum::Hardware);
    {
        let issuer_identifier = issuer_identifier.clone();
        let credential_schema = schema.clone();

        identifier_repository
            .expect_get()
            .return_once(|_, _| Ok(Some(issuer_identifier)));

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_, _| Ok(Some(credential_schema.clone())));
    }

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let mut config = generic_config().core;
    config
        .holder_key_storage
        .get_mut(&WalletStorageTypeEnum::Hardware)
        .unwrap()
        .enabled = Some(false);

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        key_algorithm_provider,
        config,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: schema.id,
            issuer: Some(issuer_identifier.id),
            issuer_did: None,
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: claims[0].schema.as_ref().unwrap().id.to_owned(),
                value: claims[0].value.to_owned(),
                path: claims[0].path.to_owned(),
            }],
            redirect_uri: None,
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
async fn test_create_credential_failed_formatter_doesnt_support_did_identifiers() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential();
    {
        let issuer_did = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .did
            .as_ref()
            .unwrap()
            .clone();
        let credential_schema = credential.schema.clone().unwrap();

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_, _| Ok(Some(credential_schema.clone())));

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_, _| {
                Ok(Some(Identifier {
                    did: Some(issuer_did),
                    ..dummy_identifier()
                }))
            });
    }

    let mut formatter_capabilities = generic_formatter_capabilities();
    formatter_capabilities.issuance_identifier_types.clear();

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::IncompatibleIssuanceIdentifier
        ))
    ));
}

#[tokio::test]
async fn test_create_credential_failed_issuance_did_method_incompatible() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential();
    {
        let issuer_did = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .did
            .as_ref()
            .unwrap()
            .clone();
        let credential_schema = credential.schema.clone().unwrap();

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_, _| Ok(Some(credential_schema.clone())));

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_, _| {
                Ok(Some(Identifier {
                    did: Some(issuer_did),
                    ..dummy_identifier()
                }))
            });
    }

    let mut formatter_capabilities = generic_formatter_capabilities();
    formatter_capabilities.issuance_did_methods.clear();

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::IncompatibleIssuanceDidMethod
        ))
    ));
}

#[tokio::test]
async fn test_create_credential_fails_if_did_is_deactivated() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let did_id = Uuid::new_v4();
    let issuer_did = Did {
        id: did_id.into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "did1".to_string(),
        organisation: None,
        did: "did:example:1".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: None,
        deactivated: true,
        log: None,
    };

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(issuer_did),
                ..dummy_identifier()
            }))
        });

    let credential = generic_credential();
    let credential_schema = credential.schema.clone().unwrap();
    credential_schema_repository
        .expect_get_credential_schema()
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        identifier_repository,
        credential_schema_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: Uuid::new_v4().into(),
            issuer: None,
            issuer_did: Some(did_id.into()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![],
            redirect_uri: None,
        })
        .await;

    assert2::assert!(
        let ServiceError::BusinessLogic(BusinessLogicError::DidIsDeactivated(_)) = result.err().unwrap()
    );
}

#[tokio::test]
async fn test_create_credential_one_required_claim_missing_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential();
    let credential_schema = CredentialSchema {
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    array: false,
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
                    array: false,
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
        let issuer_did = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .did
            .as_ref()
            .unwrap()
            .clone();
        let credential_schema_clone = credential_schema.clone();

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_, _| Ok(Some(credential_schema_clone.clone())));

        credential_repository
            .expect_create_credential()
            .times(1)
            .returning(move |_| Ok(clone.id));

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_, _| {
                Ok(Some(Identifier {
                    did: Some(issuer_did),
                    ..dummy_identifier()
                }))
            });
    }

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(credential_schema.format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let required_claim_schema_id = credential_schema.claim_schemas.as_ref().unwrap()[0]
        .schema
        .id
        .to_owned();
    let create_request_template = CreateCredentialRequestDTO {
        credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
        issuer: None,
        issuer_did: Some(
            credential
                .issuer_identifier
                .as_ref()
                .unwrap()
                .did
                .as_ref()
                .unwrap()
                .id,
        ),
        issuer_key: None,
        issuer_certificate: None,
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        claim_values: vec![],
        redirect_uri: None,
    };

    // create a credential with required claims only succeeds
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: required_claim_schema_id,
                value: "value".to_string(),
                path: credential_schema.claim_schemas.as_ref().unwrap()[0]
                    .schema
                    .key
                    .to_owned(),
            }],
            ..create_request_template
        })
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_one_required_claim_missing_fail_required_claim_not_provided() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential();
    let credential_schema = CredentialSchema {
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    array: false,
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
                    array: false,
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
        let issuer_did = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .did
            .as_ref()
            .unwrap()
            .clone();
        let credential_schema_clone = credential_schema.clone();

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_, _| {
                Ok(Some(Identifier {
                    did: Some(issuer_did),
                    ..dummy_identifier()
                }))
            });

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_, _| Ok(Some(credential_schema_clone.clone())));
    }

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(credential_schema.format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let optional_claim_schema_id = credential_schema.claim_schemas.as_ref().unwrap()[1]
        .schema
        .id
        .to_owned();
    let create_request_template = CreateCredentialRequestDTO {
        credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
        issuer: None,
        issuer_did: Some(
            credential
                .issuer_identifier
                .as_ref()
                .unwrap()
                .did
                .as_ref()
                .unwrap()
                .id,
        ),
        issuer_key: None,
        issuer_certificate: None,
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        claim_values: vec![],
        redirect_uri: None,
    };

    // create a credential with only an optional claim fails
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: optional_claim_schema_id,
                value: "value".to_string(),
                path: credential_schema.claim_schemas.as_ref().unwrap()[1]
                    .schema
                    .key
                    .to_owned(),
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
}

#[tokio::test]
async fn test_create_credential_schema_deleted() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let revocation_method_provider = MockRevocationMethodProvider::default();

    let credential = generic_credential();
    let credential_schema = CredentialSchema {
        deleted_at: Some(OffsetDateTime::now_utc()),
        ..credential.schema.clone().unwrap()
    };

    {
        let issuer_did = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .did
            .as_ref()
            .unwrap()
            .clone();
        let credential_schema_clone = credential_schema.clone();

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_, _| Ok(Some(credential_schema_clone.clone())));

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_, _| {
                Ok(Some(Identifier {
                    did: Some(issuer_did),
                    ..dummy_identifier()
                }))
            });
    }

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(credential_schema.format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        revocation_method_provider,
        protocol_provider,
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
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id,
                value: "value".to_string(),
                path: credential_schema.claim_schemas.as_ref().unwrap()[0]
                    .schema
                    .key
                    .to_owned(),
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
async fn test_check_revocation_invalid_role() {
    let credential_issuer_role = Credential {
        role: CredentialRole::Issuer,
        ..generic_credential()
    };

    let credential_verifier_role = Credential {
        role: CredentialRole::Verifier,
        ..generic_credential()
    };

    let issuer_credential_id = credential_issuer_role.id;
    let verifier_credential_id = credential_verifier_role.id;

    let mut credential_repository = MockCredentialRepository::default();

    credential_repository
        .expect_get_credential()
        .with(eq(credential_issuer_role.id), always())
        .returning(move |_, _| Ok(Some(credential_issuer_role.clone())));

    credential_repository
        .expect_get_credential()
        .with(eq(credential_verifier_role.id), always())
        .returning(move |_, _| Ok(Some(credential_verifier_role.clone())));

    let service = setup_service(Repositories {
        credential_repository,
        ..Default::default()
    });

    let issuer_revocation_check_resp = service
        .check_revocation(vec![issuer_credential_id], false)
        .await;

    let verifier_revocation_check_resp = service
        .check_revocation(vec![verifier_credential_id], false)
        .await;

    assert!(issuer_revocation_check_resp.is_err());
    assert!(matches!(
        issuer_revocation_check_resp.unwrap_err(),
        ServiceError::BusinessLogic(BusinessLogicError::RevocationCheckNotAllowedForRole { .. })
    ));

    assert!(verifier_revocation_check_resp.is_err());
    assert!(matches!(
        verifier_revocation_check_resp.unwrap_err(),
        ServiceError::BusinessLogic(BusinessLogicError::RevocationCheckNotAllowedForRole { .. })
    ));
}

#[tokio::test]
async fn test_check_revocation_invalid_state() {
    let mut credential_repository = MockCredentialRepository::default();

    let credential = generic_credential();
    {
        let credential_clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .returning(move |_, _| Ok(Some(credential_clone.clone())));
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.check_revocation(vec![credential.id], false).await;
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
    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_, _| {
            Ok(DetailCredential {
                id: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IssuerDetails::Did("did:example:123".parse().unwrap()),
                subject: None,
                claims: CredentialSubject {
                    claims: Default::default(),
                    id: None,
                },
                status: vec![],
                credential_schema: None,
            })
        });

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(formatter.clone()));

    revocation_method_provider
        .expect_get_revocation_method()
        .returning(|_| Some(Arc::new(MockRevocationMethod::default())));

    let credential = Credential {
        state: CredentialStateEnum::Accepted,
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
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .check_revocation(vec![credential.id, Uuid::new_v4().into()], false)
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

    let credential = Credential {
        state: CredentialStateEnum::Revoked,
        suspend_end_date: None,
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
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .check_revocation(vec![credential.id, Uuid::new_v4().into()], false)
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
    let mut revocation_method_provider: MockRevocationMethodProvider =
        MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    let mut revocation_method = MockRevocationMethod::default();

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_, _| {
            Ok(DetailCredential {
                id: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IssuerDetails::Did("did:example:123".parse().unwrap()),
                subject: None,
                claims: CredentialSubject {
                    claims: Default::default(),
                    id: None,
                },
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
                    r#type: "type".to_string(),
                    status_purpose: Some("purpose".to_string()),
                    additional_fields: HashMap::default(),
                }],
                credential_schema: None,
            })
        });

    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _, _, _| Ok(CredentialRevocationState::Revoked));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .returning(move |_| Some(revocation_method.clone()));

    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
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
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Revoked),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        credential_repository,
        revocation_method_provider,
        history_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.check_revocation(vec![credential.id], false).await;
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
    let mut identifier_repository = MockIdentifierRepository::default();

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let credential = generic_credential();
    let issuer_did = credential
        .issuer_identifier
        .as_ref()
        .unwrap()
        .did
        .as_ref()
        .unwrap()
        .clone();
    let credential_schema = credential.schema.clone().unwrap();

    identifier_repository.expect_get_from_did_id().return_once({
        let issuer_did = issuer_did.clone();
        |_, _| {
            Ok(Some(Identifier {
                did: Some(issuer_did),
                ..dummy_identifier()
            }))
        }
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
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        history_repository,
        formatter_provider,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: Some(issuer_did.keys.unwrap()[0].key.id),
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
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
    let mut identifier_repository = MockIdentifierRepository::default();

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
        ..credential.issuer_identifier.clone().unwrap().did.unwrap()
    };
    let credential_schema = credential.schema.clone().unwrap();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(issuer_did),
                ..dummy_identifier()
            }))
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
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        history_repository,
        formatter_provider,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: Some(key_id.into()),
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_fail_to_create_credential_no_assertion_key() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

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
        ..credential.issuer_identifier.clone().unwrap().did.unwrap()
    };

    let credential_schema = credential.schema.clone().unwrap();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(issuer_did),
                ..dummy_identifier()
            }))
        });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
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
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential();
    let issuer_did = credential
        .issuer_identifier
        .as_ref()
        .unwrap()
        .did
        .as_ref()
        .unwrap()
        .clone();
    let credential_schema = credential.schema.clone().unwrap();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(issuer_did),
                ..dummy_identifier()
            }))
        });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: Some(Uuid::new_v4().into()),
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::KeyNotFound))
    ));
}

#[tokio::test]
async fn test_fail_to_create_credential_key_id_points_to_wrong_key_role() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

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
        ..credential.issuer_identifier.clone().unwrap().did.unwrap()
    };
    let credential_schema = credential.schema.clone().unwrap();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(issuer_did),
                ..dummy_identifier()
            }))
        });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: Some(key_id.into()),
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
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
    let mut identifier_repository = MockIdentifierRepository::default();

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
        ..credential.issuer_identifier.clone().unwrap().did.unwrap()
    };
    let credential_schema = credential.schema.clone().unwrap();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(issuer_did),
                ..dummy_identifier()
            }))
        });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Ecdsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: Some(key_id.into()),
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
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
async fn test_create_credential_fail_incompatible_format_and_tranposrt_protocol() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential();
    {
        let credential_schema = credential.schema.clone().unwrap();
        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_, _| Ok(Some(credential_schema.clone())));
    }

    let issuer_did = credential.issuer_identifier.clone().unwrap().did.unwrap();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(issuer_did),
                ..dummy_identifier()
            }))
        });

    let mut formatter_capabilities = generic_formatter_capabilities();
    formatter_capabilities.issuance_exchange_protocols = vec![];

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::IncompatibleIssuanceExchangeProtocol
        ))
    ));
}

#[tokio::test]
async fn test_create_credential_fail_invalid_redirect_uri() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let credential = generic_credential();
    let issuer_did = credential.issuer_identifier.clone().unwrap().did.unwrap();
    let credential_schema = credential.schema.clone().unwrap();

    identifier_repository.expect_get_from_did_id().return_once({
        let issuer_did = issuer_did.clone();
        |_, _| {
            Ok(Some(Identifier {
                did: Some(issuer_did),
                ..dummy_identifier()
            }))
        }
    });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema.clone())));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential.schema.as_ref().unwrap().format.to_owned()))
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        history_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .unwrap()
                    .did
                    .as_ref()
                    .unwrap()
                    .id,
            ),
            issuer_key: Some(issuer_did.keys.unwrap()[0].key.id),
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().unwrap()[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().unwrap()[0].value.to_owned(),
                path: credential.claims.as_ref().unwrap()[0].path.to_owned(),
            }],
            redirect_uri: Some("invalid://domain.com".to_string()),
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::InvalidRedirectUri
        ))
    ));
}

#[tokio::test]
async fn test_revoke_credential_success_with_accepted_credential() {
    let mut credential = generic_credential();
    credential.state = CredentialStateEnum::Accepted;

    let mut history_repository = MockHistoryRepository::default();
    let mut credential_repository = MockCredentialRepository::default();
    let clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .times(1)
        .with(eq(clone.id), always())
        .returning(move |_, _| Ok(Some(clone.clone())));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .once()
        .return_once(move || RevocationMethodCapabilities {
            operations: vec![Operation::Revoke],
        });
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(CredentialRevocationState::Revoked), always())
        .return_once(move |_, _, _| {
            Ok(RevocationUpdate {
                status_type: "NONE".to_string(),
                data: vec![],
            })
        });
    revocation_method
        .expect_get_status_type()
        .return_once(|| "NONE".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap());
            Ok(())
        });

    history_repository
        .expect_create_history()
        .return_once(move |_| Ok(Uuid::new_v4().into()));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .times(1)
        .returning(move |_| Some(revocation_method.clone()));

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
    let mut credential = generic_credential();

    credential.state = CredentialStateEnum::Suspended;

    let mut credential_repository = MockCredentialRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_get_capabilities()
        .once()
        .return_once(move || RevocationMethodCapabilities {
            operations: vec![Operation::Revoke],
        });
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(CredentialRevocationState::Revoked), always())
        .return_once(move |_, _, _| {
            Ok(RevocationUpdate {
                status_type: "NONE".to_string(),
                data: vec![],
            })
        });
    revocation_method
        .expect_get_status_type()
        .return_once(|| "NONE".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap());
            Ok(())
        });

    let clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .times(1)
        .with(eq(clone.id), always())
        .returning(move |_, _| Ok(Some(clone.clone())));

    history_repository
        .expect_create_history()
        .return_once(move |_| Ok(Uuid::new_v4().into()));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .times(1)
        .returning(move |_| Some(revocation_method.clone()));

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

    credential.state = CredentialStateEnum::Accepted;

    let suspend_end_date = now.add(Duration::days(1));

    let mut credential_repository = MockCredentialRepository::default();
    let mut history_repository = MockHistoryRepository::default();
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
            operations: vec![Operation::Suspend],
        });
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(
            always(),
            eq(CredentialRevocationState::Suspended {
                suspend_end_date: Some(suspend_end_date),
            }),
            always(),
        )
        .return_once(move |_, _, _| {
            Ok(RevocationUpdate {
                status_type: "NONE".to_string(),
                data: vec![],
            })
        });
    revocation_method
        .expect_get_status_type()
        .return_once(|| "NONE".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Suspended, request.state.unwrap());
            Ok(())
        });

    history_repository
        .expect_create_history()
        .return_once(move |_| Ok(Uuid::new_v4().into()));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .times(1)
        .returning(move |_| Some(revocation_method.clone()));

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
    let mut credential = generic_credential();

    credential.state = CredentialStateEnum::Revoked;

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
    let mut credential = generic_credential();

    credential.state = CredentialStateEnum::Suspended;

    let mut credential_repository = MockCredentialRepository::default();
    let mut did_method_provider = MockDidMethodProvider::default();
    let mut history_repository = MockHistoryRepository::default();

    did_method_provider
        .expect_resolve()
        .returning(|did| Ok(dummy_did_document(did)));
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
            operations: vec![Operation::Suspend],
        });
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(CredentialRevocationState::Valid), always())
        .return_once(move |_, _, _| {
            Ok(RevocationUpdate {
                status_type: "NONE".to_string(),
                data: vec![],
            })
        });
    revocation_method
        .expect_get_status_type()
        .return_once(|| "NONE".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Accepted, request.state.unwrap());
            Ok(())
        });

    history_repository
        .expect_create_history()
        .return_once(move |_| Ok(Uuid::new_v4().into()));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .times(1)
        .returning(move |_| Some(revocation_method.clone()));

    let service = setup_service(Repositories {
        credential_repository,
        history_repository,
        did_method_provider,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    service.reactivate_credential(&credential.id).await.unwrap();
}

#[tokio::test]
async fn test_reactivate_credential_failed_cannot_reactivate_revoked_credential() {
    let mut credential = generic_credential();

    credential.state = CredentialStateEnum::Revoked;

    let mut credential_repository = MockCredentialRepository::default();
    let clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .times(1)
        .with(eq(clone.id), always())
        .returning(move |_, _| Ok(Some(clone.clone())));

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
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: now,
        external_schema: false,
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
        allow_suspension: true,
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
                array: false,
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
                array: false,
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
                array: false,
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
                array: false,
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
        "OPENID4VCI_DRAFT13",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_y_claim_id,
                value: "456".to_string(),
                path: "location/y".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .unwrap();
}

fn generic_capabilities() -> IssuanceProtocolCapabilities {
    IssuanceProtocolCapabilities {
        features: vec![crate::provider::issuance_protocol::dto::Features::SupportsRejection],
        did_methods: vec![crate::config::core_config::DidType::Key],
    }
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
                array: false,
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
                array: false,
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
                array: false,
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
                array: false,
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
        "OPENID4VCI_DRAFT13",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_y_claim_id,
                value: "456".to_string(),
                path: "location/y".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .unwrap();

    validate_create_request(
        "OPENID4VCI_DRAFT13",
        &[CredentialRequestClaimDTO {
            claim_schema_id: address_claim_id,
            value: "Somewhere".to_string(),
            path: "address".to_string(),
        }],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .unwrap();

    let result = validate_create_request(
        "OPENID4VCI_DRAFT13",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
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
                array: false,
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
                array: false,
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
                array: false,
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
                array: false,
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
        "OPENID4VCI_DRAFT13",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_y_claim_id,
                value: "456".to_string(),
                path: "location/y".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .unwrap();

    let result = validate_create_request(
        "OPENID4VCI_DRAFT13",
        &[CredentialRequestClaimDTO {
            claim_schema_id: address_claim_id,
            value: "Somewhere".to_string(),
            path: "address".to_string(),
        }],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    );
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::CredentialMissingClaim { .. }
        ))
    ));

    validate_create_request(
        "OPENID4VCI_DRAFT13",
        &[
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .unwrap();
}

#[tokio::test]
async fn test_get_credential_success_with_non_required_nested_object() {
    let mut credential_repository = MockCredentialRepository::default();

    let now = OffsetDateTime::now_utc();

    let location_claim_schema = ClaimSchema {
        array: false,
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
    };
    let location_x_claim_schema = ClaimSchema {
        array: false,
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
        path: location_x_claim_schema.key.clone(),
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

fn generate_claim_schema(key: &str, datatype: &str, array: bool) -> ClaimSchema {
    let now = get_dummy_date();
    ClaimSchema {
        array,
        id: Uuid::new_v4().into(),
        key: key.to_string(),
        data_type: datatype.to_string(),
        created_date: now,
        last_modified: now,
    }
}

fn generate_claim(
    credential_id: CredentialId,
    claim_schema: &ClaimSchema,
    value: &str,
    path: &str,
) -> Claim {
    let now = get_dummy_date();

    Claim {
        id: Uuid::new_v4(),
        credential_id,
        created_date: now,
        last_modified: now,
        value: value.to_string(),
        path: path.to_string(),
        schema: Some(claim_schema.to_owned()),
    }
}

#[tokio::test]
async fn test_get_credential_success_array_complex_nested_all() {
    let mut credential_repository = MockCredentialRepository::default();

    let now = get_dummy_date();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);
    let schema_root_name = generate_claim_schema("root/name", "STRING", false);
    let schema_root_cap = generate_claim_schema("root/cap", "STRING", true);

    let schema_other = generate_claim_schema("other", "OBJECT", false);
    let schema_other_0 = generate_claim_schema("other/0", "OBJECT", true);
    let schema_other_0_name = generate_claim_schema("other/0/name", "STRING", false);
    let schema_other_1 = generate_claim_schema("other/1", "STRING", true);

    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![
        schema_root.to_owned(),
        schema_root_index_list.to_owned(),
        schema_root_name.to_owned(),
        schema_root_cap.to_owned(),
        schema_other.to_owned(),
        schema_other_0.to_owned(),
        schema_other_0_name.to_owned(),
        schema_other_1.to_owned(),
        schema_str.to_owned(),
    ];
    let organisation = dummy_organisation(None);

    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
        generate_claim(id, &schema_root_name, "123", "root/0/name"),
        generate_claim(id, &schema_root_cap, "invoke", "root/0/cap/0"),
        generate_claim(id, &schema_root_cap, "revoke", "root/0/cap/1"),
        generate_claim(id, &schema_root_cap, "delete", "root/0/cap/2"),
        generate_claim(id, &schema_root_index_list, "456", "root/1/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "456", "root/1/indexlist/1"),
        generate_claim(id, &schema_root_name, "456", "root/1/name"),
        generate_claim(id, &schema_root_cap, "invoke", "root/1/cap/0"),
        generate_claim(id, &schema_root_cap, "revoke", "root/1/cap/1"),
        generate_claim(id, &schema_root_cap, "delete", "root/1/cap/2"),
        generate_claim(id, &schema_other_0_name, "name1", "other/0/0/name"),
        generate_claim(id, &schema_other_0_name, "name2", "other/0/1/name"),
        generate_claim(id, &schema_other_1, "other1", "other/1/0"),
        generate_claim(id, &schema_other_1, "other2", "other/1/1"),
        generate_claim(id, &schema_other_1, "other3", "other/1/2"),
        generate_claim(id, &schema_str, "str1", "str/0"),
        generate_claim(id, &schema_str, "str1", "str/1"),
        generate_claim(id, &schema_str, "str1", "str/2"),
    ];

    let credential = Credential {
        id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(claims.to_owned()),
        issuer_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "identifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "did1".to_string(),
                organisation: Some(organisation.clone()),
                did: "did:example:1".parse().unwrap(),
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
                log: None,
            }),
            key: None,
            certificates: None,
        }),
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            imported_source_url: "CORE_URL".to_string(),
            last_modified: now,
            name: "schema".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            external_schema: false,
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(
                claim_schemas
                    .into_iter()
                    .map(|schema| CredentialSchemaClaim {
                        required: true,
                        schema,
                    })
                    .collect(),
            ),
            organisation: Some(organisation),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
        }),
        interaction: None,
        revocation_list: None,
        key: None,
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
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await.unwrap();

    let expected_claims = json!([{
        "path": "root",
        "schema": {
          "id": schema_root.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "root",
          "datatype": "OBJECT",
          "required": true,
          "array": true
        },
        "value": [{
            "path": "root/0",
            "schema": {
              "id": schema_root.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "root",
              "datatype": "OBJECT",
              "required": true,
              "array": false
            },
            "value": [{
                "path": "root/0/indexlist",
                "schema": {
                  "id": schema_root_index_list.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/indexlist",
                  "datatype": "NUMBER",
                  "required": true,
                  "array": true
                },
                "value": [{
                    "path": "root/0/indexlist/0",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false
                    },
                    "value": 123
                  },
                  {
                    "path": "root/0/indexlist/1",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false
                    },
                    "value": 123
                  }
                ]
              },
              {
                "path": "root/0/name",
                "schema": {
                  "id": schema_root_name.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/name",
                  "datatype": "STRING",
                  "required": true,
                  "array": false
                },
                "value": "123"
              },
              {
                "path": "root/0/cap",
                "schema": {
                  "id": schema_root_cap.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/cap",
                  "datatype": "STRING",
                  "required": true,
                  "array": true
                },
                "value": [{
                    "path": "root/0/cap/0",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false
                    },
                    "value": "invoke"
                  },
                  {
                    "path": "root/0/cap/1",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false
                    },
                    "value": "revoke"
                  },
                  {
                    "path": "root/0/cap/2",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false
                    },
                    "value": "delete"
                  }
                ]
              },
            ]
          },
          {
            "path": "root/1",
            "schema": {
              "id": schema_root.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "root",
              "datatype": "OBJECT",
              "required": true,
              "array": false
            },
            "value": [{
                "path": "root/1/indexlist",
                "schema": {
                  "id": schema_root_index_list.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/indexlist",
                  "datatype": "NUMBER",
                  "required": true,
                  "array": true
                },
                "value": [{
                    "path": "root/1/indexlist/0",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false
                    },
                    "value": 456
                  },
                  {
                    "path": "root/1/indexlist/1",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false
                    },
                    "value": 456
                  }
                ]
              },
              {
                "path": "root/1/name",
                "schema": {
                  "id": schema_root_name.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/name",
                  "datatype": "STRING",
                  "required": true,
                  "array": false
                },
                "value": "456"
              },
              {
                "path": "root/1/cap",
                "schema": {
                  "id": schema_root_cap.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/cap",
                  "datatype": "STRING",
                  "required": true,
                  "array": true
                },
                "value": [{
                    "path": "root/1/cap/0",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false
                    },
                    "value": "invoke"
                  },
                  {
                    "path": "root/1/cap/1",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false
                    },
                    "value": "revoke"
                  },
                  {
                    "path": "root/1/cap/2",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false
                    },
                    "value": "delete"
                  }
                ]
              },
            ]
          }
        ]
      },
      {
        "path": "other",
        "schema": {
          "id": schema_other.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "other",
          "datatype": "OBJECT",
          "required": true,
          "array": false
        },
        "value": [{
            "path": "other/0",
            "schema": {
              "id": schema_other_0.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "other/0",
              "datatype": "OBJECT",
              "required": true,
              "array": true
            },
            "value": [{
                "path": "other/0/0",
                "schema": {
                  "id": schema_other_0.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/0",
                  "datatype": "OBJECT",
                  "required": true,
                  "array": false
                },
                "value": [{
                  "path": "other/0/0/name",
                  "schema": {
                    "id": schema_other_0_name.id,
                    "createdDate": "2005-04-02T21:37:00+01:00",
                    "lastModified": "2005-04-02T21:37:00+01:00",
                    "key": "other/0/name",
                    "datatype": "STRING",
                    "required": true,
                    "array": false
                  },
                  "value": "name1"
                }]
              },
              {
                "path": "other/0/1",
                "schema": {
                  "id": schema_other_0.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/0",
                  "datatype": "OBJECT",
                  "required": true,
                  "array": false
                },
                "value": [{
                  "path": "other/0/1/name",
                  "schema": {
                    "id": schema_other_0_name.id,
                    "createdDate": "2005-04-02T21:37:00+01:00",
                    "lastModified": "2005-04-02T21:37:00+01:00",
                    "key": "other/0/name",
                    "datatype": "STRING",
                    "required": true,
                    "array": false
                  },
                  "value": "name2"
                }]
              }
            ]
          },
          {
            "path": "other/1",
            "schema": {
              "id": schema_other_1.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "other/1",
              "datatype": "STRING",
              "required": true,
              "array": true
            },
            "value": [{
                "path": "other/1/0",
                "schema": {
                  "id": schema_other_1.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/1",
                  "datatype": "STRING",
                  "required": true,
                  "array": false
                },
                "value": "other1"
              },
              {
                "path": "other/1/1",
                "schema": {
                  "id": schema_other_1.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/1",
                  "datatype": "STRING",
                  "required": true,
                  "array": false
                },
                "value": "other2"
              },
              {
                "path": "other/1/2",
                "schema": {
                  "id": schema_other_1.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/1",
                  "datatype": "STRING",
                  "required": true,
                  "array": false
                },
                "value": "other3"
              }
            ]
          }
        ]
      },
      {
        "path": "str",
        "schema": {
          "id": schema_str.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "str",
          "datatype": "STRING",
          "required": true,
          "array": true
        },
        "value": [{
            "path": "str/0",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/1",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/2",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          }
        ]
      }
    ]);

    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

#[tokio::test]
async fn test_get_credential_success_array_index_sorting() {
    let mut credential_repository = MockCredentialRepository::default();

    let now = get_dummy_date();
    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![schema_str.to_owned()];
    let organisation = dummy_organisation(None);

    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_str, "str1", "str/2"),
        generate_claim(id, &schema_str, "str1", "str/0"),
        generate_claim(id, &schema_str, "str1", "str/1"),
        generate_claim(id, &schema_str, "str1", "str/6"),
        generate_claim(id, &schema_str, "str1", "str/7"),
        generate_claim(id, &schema_str, "str1", "str/3"),
        generate_claim(id, &schema_str, "str1", "str/4"),
        generate_claim(id, &schema_str, "str1", "str/10"),
        generate_claim(id, &schema_str, "str1", "str/11"),
        generate_claim(id, &schema_str, "str1", "str/5"),
        generate_claim(id, &schema_str, "str1", "str/9"),
        generate_claim(id, &schema_str, "str1", "str/8"),
        generate_claim(id, &schema_str, "str1", "str/12"),
    ];

    let credential = Credential {
        id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(claims.to_owned()),
        issuer_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "identifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "did1".to_string(),
                organisation: Some(organisation.clone()),
                did: "did:example:1".parse().unwrap(),
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
                log: None,
            }),
            key: None,
            certificates: None,
        }),
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            imported_source_url: "CORE_URL".to_string(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            external_schema: false,
            name: "schema".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(
                claim_schemas
                    .into_iter()
                    .map(|schema| CredentialSchemaClaim {
                        required: true,
                        schema,
                    })
                    .collect(),
            ),
            organisation: Some(organisation),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
        }),
        interaction: None,
        revocation_list: None,
        key: None,
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
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await.unwrap();

    let expected_claims = json!([
      {
        "path": "str",
        "schema": {
          "id": schema_str.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "str",
          "datatype": "STRING",
          "required": true,
          "array": true
        },
        "value": [
          {
            "path": "str/0",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/1",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/2",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/3",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/4",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/5",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/6",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/7",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/8",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/9",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/10",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/11",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
          {
            "path": "str/12",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false
            },
            "value": "str1"
          },
        ]
      }
    ]);

    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

#[tokio::test]
async fn test_get_credential_success_array_complex_nested_first_case() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut validity_credential_repository = MockValidityCredentialRepository::default();

    let now = get_dummy_date();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];
    let organisation = dummy_organisation(None);

    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
    ];

    let credential = Credential {
        id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(claims.to_owned()),
        issuer_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "identifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "did1".to_string(),
                organisation: Some(organisation.clone()),
                did: "did:example:1".parse().unwrap(),
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
                log: None,
            }),
            key: None,
            certificates: None,
        }),
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            external_schema: false,
            format: "MDOC".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(
                claim_schemas
                    .into_iter()
                    .map(|schema| CredentialSchemaClaim {
                        required: true,
                        schema,
                    })
                    .collect(),
            ),
            organisation: Some(organisation),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
        }),
        interaction: None,
        revocation_list: None,
        key: None,
    };

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id), always())
            .returning(move |_, _| Ok(Some(clone.clone())));

        validity_credential_repository
            .expect_get_latest_by_credential_id()
            .once()
            .with(eq(credential.id), eq(ValidityCredentialType::Mdoc))
            .return_once(move |_, _| {
                Ok(Some(ValidityCredential {
                    id: Uuid::new_v4(),
                    created_date: now,
                    credential: vec![1, 2, 3],
                    linked_credential_id: credential.id,
                    r#type: ValidityCredentialType::Mdoc,
                }))
            });
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        lvvc_repository: validity_credential_repository,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await.unwrap();

    let expected_claims = json!([
      {
        "path": "root",
        "schema": {
          "id": schema_root.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "root",
          "datatype": "OBJECT",
          "required": true,
          "array": true
        },
        "value": [
          {
            "path": "root/0",
            "schema": {
              "id": schema_root.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "root",
              "datatype": "OBJECT",
              "required": true,
              "array": false
            },
            "value": [
              {
                "path": "root/0/indexlist",
                "schema": {
                  "id": schema_root_index_list.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/indexlist",
                  "datatype": "NUMBER",
                  "required": true,
                  "array": true
                },
                "value": [
                  {
                    "path": "root/0/indexlist/0",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false
                    },
                    "value": 123
                  },
                  {
                    "path": "root/0/indexlist/1",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false
                    },
                    "value": 123
                  }
                ]
              }
            ]
          }
        ]
      }
    ]);

    assert!(result.mdoc_mso_validity.is_some());
    assert_eq!(now, result.mdoc_mso_validity.unwrap().last_update);
    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

#[tokio::test]
async fn test_get_credential_success_array_single_element() {
    let mut credential_repository = MockCredentialRepository::default();

    let now = get_dummy_date();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];
    let organisation = dummy_organisation(None);

    let id = Uuid::new_v4().into();

    let claims = vec![generate_claim(
        id,
        &schema_root_index_list,
        "123",
        "root/0/indexlist/0",
    )];

    let credential = Credential {
        id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(claims.to_owned()),
        issuer_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "identifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "did1".to_string(),
                organisation: Some(organisation.clone()),
                did: "did:example:1".parse().unwrap(),
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
                log: None,
            }),
            key: None,
            certificates: None,
        }),
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            imported_source_url: "CORE_URL".to_string(),
            name: "schema".to_string(),
            external_schema: false,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(
                claim_schemas
                    .into_iter()
                    .map(|schema| CredentialSchemaClaim {
                        required: true,
                        schema,
                    })
                    .collect(),
            ),
            organisation: Some(organisation),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
        }),
        interaction: None,
        revocation_list: None,
        key: None,
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
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await.unwrap();

    let expected_claims = json!([
      {
        "path": "root",
        "schema": {
          "id": schema_root.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "root",
          "datatype": "OBJECT",
          "required": true,
          "array": true
        },
        "value": [
          {
            "path": "root/0",
            "schema": {
              "id": schema_root.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "root",
              "datatype": "OBJECT",
              "required": true,
              "array": false
            },
            "value": [
              {
                "path": "root/0/indexlist",
                "schema": {
                  "id": schema_root_index_list.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/indexlist",
                  "datatype": "NUMBER",
                  "required": true,
                  "array": true
                },
                "value": [
                  {
                    "path": "root/0/indexlist/0",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false
                    },
                    "value": 123
                  }
                ]
              }
            ]
          }
        ]
      }
    ]);

    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

async fn test_create_credential_array(
    claim_schemas: Vec<ClaimSchema>,
    claims: Vec<Claim>,
) -> Result<CredentialId, ServiceError> {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let organisation = dummy_organisation(None);

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        imported_source_url: "CORE_URL".to_string(),
        name: "str array".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        external_schema: false,
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "".to_string(),
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        claim_schemas: Some(
            claim_schemas
                .iter()
                .map(|schema| CredentialSchemaClaim {
                    schema: schema.to_owned(),
                    required: true,
                })
                .collect(),
        ),
        organisation: Some(organisation.to_owned()),
        allow_suspension: true,
    };

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();

    {
        let credential_schema = credential_schema.clone();
        credential_schema_repository
            .expect_get_credential_schema()
            .return_once(move |_, _| Ok(Some(credential_schema)));
        formatter_provider
            .expect_get_credential_formatter()
            .once()
            .return_once(move |_| Some(Arc::new(formatter)));
        credential_repository
            .expect_create_credential()
            .return_once(move |_| Ok(Uuid::new_v4().into()));
        history_repository
            .expect_create_history()
            .return_once(move |_| Ok(Uuid::new_v4().into()));
    }

    let did = Did {
        did_method: "KEY".to_string(),
        keys: Some(vec![RelatedKey {
            role: KeyRole::AssertionMethod,
            key: dummy_key(),
        }]),
        ..dummy_did()
    };
    let did_clone = did.clone();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(did_clone),
                ..dummy_identifier()
            }))
        });

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(dummy_protocol)));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        history_repository,
        key_algorithm_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: Uuid::new_v4().into(),
            issuer: None,
            issuer_did: Some(did.id),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            claim_values: claims
                .iter()
                .map(|claim| CredentialRequestClaimDTO {
                    claim_schema_id: claim.schema.to_owned().unwrap().id,
                    value: claim.value.to_owned(),
                    path: claim.path.to_owned(),
                })
                .collect(),
            redirect_uri: None,
        })
        .await
}

#[tokio::test]
async fn test_create_credential_array_simple_string() {
    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![schema_str.to_owned()];
    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_str, "str1", "str/0"),
        generate_claim(id, &schema_str, "str1", "str/1"),
        generate_claim(id, &schema_str, "str1", "str/2"),
    ];

    test_create_credential_array(claim_schemas, claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_credential_array_simple_object() {
    let id = Uuid::new_v4().into();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
    ];

    test_create_credential_array(claim_schemas, claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_credential_array_complex_structure() {
    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);
    let schema_root_name = generate_claim_schema("root/name", "STRING", false);
    let schema_root_cap = generate_claim_schema("root/cap", "STRING", true);

    let schema_other = generate_claim_schema("other", "OBJECT", false);
    let schema_other_0 = generate_claim_schema("other/0", "OBJECT", true);
    let schema_other_0_name = generate_claim_schema("other/0/name", "STRING", false);
    let schema_other_1 = generate_claim_schema("other/1", "STRING", true);

    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![
        schema_root.to_owned(),
        schema_root_index_list.to_owned(),
        schema_root_name.to_owned(),
        schema_root_cap.to_owned(),
        schema_other.to_owned(),
        schema_other_0.to_owned(),
        schema_other_0_name.to_owned(),
        schema_other_1.to_owned(),
        schema_str.to_owned(),
    ];

    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
        generate_claim(id, &schema_root_name, "123", "root/0/name"),
        generate_claim(id, &schema_root_cap, "invoke", "root/0/cap/0"),
        generate_claim(id, &schema_root_cap, "revoke", "root/0/cap/1"),
        generate_claim(id, &schema_root_cap, "delete", "root/0/cap/2"),
        generate_claim(id, &schema_root_index_list, "456", "root/1/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "456", "root/1/indexlist/1"),
        generate_claim(id, &schema_root_name, "456", "root/1/name"),
        generate_claim(id, &schema_root_cap, "invoke", "root/1/cap/0"),
        generate_claim(id, &schema_root_cap, "revoke", "root/1/cap/1"),
        generate_claim(id, &schema_root_cap, "delete", "root/1/cap/2"),
        generate_claim(id, &schema_other_0_name, "name1", "other/0/0/name"),
        generate_claim(id, &schema_other_0_name, "name2", "other/0/1/name"),
        generate_claim(id, &schema_other_1, "other1", "other/1/0"),
        generate_claim(id, &schema_other_1, "other2", "other/1/1"),
        generate_claim(id, &schema_other_1, "other3", "other/1/2"),
        generate_claim(id, &schema_str, "str1", "str/0"),
        generate_claim(id, &schema_str, "str1", "str/1"),
        generate_claim(id, &schema_str, "str1", "str/2"),
    ];

    test_create_credential_array(claim_schemas, claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_credential_array_fail_incorrect_index() {
    let id = Uuid::new_v4().into();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let unparsable_index = generate_claim(
        id,
        &schema_root_index_list,
        "123",
        "root/0/indexlist/not_an_index",
    );
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![unparsable_index])
            .await
            .is_err()
    );

    let unparsable_index_parent = generate_claim(
        id,
        &schema_root_index_list,
        "123",
        "root/not_an_index/indexlist/0",
    );
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![unparsable_index_parent])
            .await
            .is_err()
    );

    let missing_component = generate_claim(id, &schema_root_index_list, "123", "root/indexlist/0");
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![missing_component])
            .await
            .is_err()
    );

    let malformed_path = generate_claim(id, &schema_root_index_list, "123", "not_even_a_path");
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![malformed_path])
            .await
            .is_err()
    );

    let malformed_path = generate_claim(id, &schema_root_index_list, "123", "///////");
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![malformed_path])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_create_credential_array_fail_index_incorrect_order() {
    let id = Uuid::new_v4().into();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/2"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/2/indexlist/0"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/1/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_create_credential_number_named_claims() {
    let id = Uuid::new_v4().into();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_00 = generate_claim_schema("root/00", "STRING", false);
    let schema_1 = generate_claim_schema("root/1", "STRING", false);
    let schema_2array = generate_claim_schema("root/2-array", "STRING", true);

    let claim_schemas = vec![
        schema_root.to_owned(),
        schema_1.to_owned(),
        schema_00.to_owned(),
        schema_2array.to_owned(),
    ];

    let claims = vec![
        generate_claim(id, &schema_00, "zero", "root/0/00"),
        generate_claim(id, &schema_1, "1first", "root/0/1"),
        generate_claim(id, &schema_1, "1second", "root/1/1"),
        generate_claim(id, &schema_2array, "2first", "root/0/2-array/0"),
    ];
    test_create_credential_array(claim_schemas.to_owned(), claims)
        .await
        .unwrap();
}
