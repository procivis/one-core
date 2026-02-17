use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;

use mockall::predicate::{always, eq};
use shared_types::RevocationMethodId;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialRole, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::Key;
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::credential_validity_manager::{
    CredentialValidityManager, CredentialValidityManagerImpl, Error,
};
use crate::proto::http_client::MockHttpClient;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, SessionProvider};
use crate::provider::blob_storage_provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::service::test_utilities::{dummy_did_document, dummy_organisation, generic_config};

#[derive(Default)]
struct Repositories {
    pub credential_repository: MockCredentialRepository,
    pub interaction_repository: MockInteractionRepository,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub key_provider: MockKeyProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub certificate_validator: MockCertificateValidator,
    pub config: CoreConfig,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub client: MockHttpClient,
    pub session_provider: Option<Arc<dyn SessionProvider>>,
}

fn setup_validity_manager(repositories: Repositories) -> CredentialValidityManagerImpl {
    CredentialValidityManagerImpl::new(
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.interaction_repository),
        Arc::new(repositories.client),
        Arc::new(repositories.key_provider),
        Arc::new(repositories.key_algorithm_provider),
        Arc::new(repositories.certificate_validator),
        Arc::new(repositories.did_method_provider),
        Arc::new(repositories.revocation_method_provider),
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.blob_storage_provider),
        repositories
            .session_provider
            .unwrap_or(Arc::new(NoSessionProvider)),
        Arc::new(repositories.config),
    )
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
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
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

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(credential.id, false)
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.credential_id, credential.id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Accepted);
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

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(credential.id, false)
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.credential_id, credential.id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Revoked);
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
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
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
        .returning(|_, _, _, _| Ok(RevocationState::Revoked));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq::<RevocationMethodId>("mock".into()))
        .returning(move |_| Some(revocation_method.clone()));

    let credential = {
        let mut cred = Credential {
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
            ..generic_credential()
        };
        cred.schema.as_mut().unwrap().revocation_method = Some("mock".into());
        cred
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

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(credential.id, false)
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.credential_id, credential.id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Revoked);
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

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let issuer_revocation_check_resp = validity_manager
        .check_holder_credential_validity(issuer_credential_id, false)
        .await;

    let verifier_revocation_check_resp = validity_manager
        .check_holder_credential_validity(verifier_credential_id, false)
        .await;

    assert!(issuer_revocation_check_resp.is_err());
    assert!(matches!(
        issuer_revocation_check_resp.unwrap_err(),
        Error::RevocationCheckNotAllowedForRole { .. }
    ));

    assert!(verifier_revocation_check_resp.is_err());
    assert!(matches!(
        verifier_revocation_check_resp.unwrap_err(),
        Error::RevocationCheckNotAllowedForRole { .. }
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

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(credential.id, false)
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.credential_id, credential.id);
    assert!(!result.success);
    assert_eq!(result.status, CredentialStateEnum::Created);
}

#[tokio::test]
async fn test_revoke_credential_success_with_accepted_credential() {
    let mut credential = generic_credential();
    credential.state = CredentialStateEnum::Accepted;
    credential.schema.as_mut().unwrap().revocation_method = Some("mock".into());

    let mut credential_repository = MockCredentialRepository::default();
    let clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .times(1)
        .with(eq(clone.id), always())
        .returning(move |_, _| Ok(Some(clone.clone())));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(RevocationState::Revoked))
        .return_once(|_, _| Ok(()));
    revocation_method
        .expect_get_status_type()
        .return_once(|| "mock".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap());
            Ok(())
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq::<RevocationMethodId>("mock".into()))
        .times(1)
        .returning(move |_| Some(revocation_method.clone()));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_validity_state(&credential.id, RevocationState::Revoked)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_revoke_credential_success_with_suspended_credential() {
    let mut credential = generic_credential();

    credential.state = CredentialStateEnum::Suspended;
    credential.schema.as_mut().unwrap().revocation_method = Some("mock".into());

    let mut credential_repository = MockCredentialRepository::default();

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(RevocationState::Revoked))
        .return_once(|_, _| Ok(()));
    revocation_method
        .expect_get_status_type()
        .return_once(|| "mock".to_string());

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

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq::<RevocationMethodId>("mock".into()))
        .times(1)
        .returning(move |_| Some(revocation_method.clone()));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_validity_state(&credential.id, RevocationState::Revoked)
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
    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .change_credential_validity_state(
            &credential.id,
            RevocationState::Suspended {
                suspend_end_date: None,
            },
        )
        .await
        .unwrap_err();

    assert!(matches!(
        result,
        Error::InvalidCredentialStateTransition { .. }
    ));
}

#[tokio::test]
async fn test_suspend_credential_success() {
    let now = OffsetDateTime::now_utc();

    let mut credential = generic_credential();

    credential.state = CredentialStateEnum::Accepted;
    credential.schema.as_mut().unwrap().revocation_method = Some("mock".into());

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
        .expect_mark_credential_as()
        .once()
        .with(
            always(),
            eq(RevocationState::Suspended {
                suspend_end_date: Some(suspend_end_date),
            }),
        )
        .return_once(|_, _| Ok(()));
    revocation_method
        .expect_get_status_type()
        .return_once(|| "mock".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Suspended, request.state.unwrap());
            Ok(())
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq::<RevocationMethodId>("mock".into()))
        .times(1)
        .returning(move |_| Some(revocation_method.clone()));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_validity_state(
            &credential.id,
            RevocationState::Suspended {
                suspend_end_date: Some(suspend_end_date),
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_reactivate_credential_success() {
    let mut credential = generic_credential();

    credential.state = CredentialStateEnum::Suspended;
    credential.schema.as_mut().unwrap().revocation_method = Some("mock".into());

    let mut credential_repository = MockCredentialRepository::default();
    let mut did_method_provider = MockDidMethodProvider::default();

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
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(RevocationState::Valid))
        .return_once(|_, _| Ok(()));
    revocation_method
        .expect_get_status_type()
        .return_once(|| "mock".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Accepted, request.state.unwrap());
            Ok(())
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq::<RevocationMethodId>("mock".into()))
        .times(1)
        .returning(move |_| Some(revocation_method.clone()));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_validity_state(&credential.id, RevocationState::Valid)
        .await
        .unwrap();
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

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .change_credential_validity_state(&credential.id, RevocationState::Valid)
        .await
        .unwrap_err();

    assert!(matches!(
        result,
        Error::InvalidCredentialStateTransition { .. }
    ));
}

#[tokio::test]
async fn test_credential_ops_session_org_mismatch() {
    let mut credential_repository = MockCredentialRepository::default();
    credential_repository
        .expect_get_credential()
        .returning(|_, _| Ok(Some(generic_credential())));
    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = validity_manager
        .change_credential_validity_state(&Uuid::new_v4().into(), RevocationState::Valid)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
    let result = validity_manager
        .check_holder_credential_validity(Uuid::new_v4().into(), false)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
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
        metadata: false,
        required: true,
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
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            reference: "1".to_string(),
        }]),
        deactivated: false,
        log: None,
    };

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(vec![Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: Some("123".to_string()),
            path: claim_schema.key.clone(),
            selectively_disclosable: false,
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
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            key_storage_security: None,
            format: "JWT".into(),
            revocation_method: Some("REVOCATION_METHOD".to_string().into()),
            claim_schemas: Some(vec![claim_schema]),
            organisation: Some(organisation),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
        }),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
    }
}
