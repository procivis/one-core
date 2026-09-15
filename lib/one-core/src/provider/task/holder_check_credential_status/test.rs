use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use mockall::predicate::eq;
use shared_types::RevocationMethodId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::model::blob::{Blob, BlobType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialRole, CredentialStateEnum, CredentialType, GetCredentialList,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::{CredentialSchema, KeyStorageSecurity, WalletAttestation};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::key::Key;
use crate::proto::credential_validity_manager::{
    CredentialValidityManager, CredentialValidityManagerImpl,
};
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage::MockBlobStorage;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::task::Task;
use crate::provider::task::holder_check_credential_status::HolderCheckCredentialStatus;
use crate::provider::task::holder_check_credential_status::dto::HolderCheckCredentialStatusResultDTO;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::service::test_utilities::{dummy_organisation, generic_config, get_dummy_date};

#[tokio::test]
async fn test_task_holder_check_credential_status_being_revoked() {
    // given
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

    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _, _, _| Ok(RevocationState::Revoked));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .returning(move |_| Ok(revocation_method.clone()));

    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        ..generic_credential()
    };

    let credential_clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .returning(move |_| Ok(credential_clone.clone()));

    credential_repository
        .expect_get_credential_list()
        .returning(move |_| {
            Ok(GetCredentialList {
                values: vec![credential.clone()],
                total_pages: 0,
                total_items: 1,
            })
        });

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

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_get().once().return_once(|id| {
        Ok(Some(Blob {
            id: id.to_owned(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: vec![1, 2, 3, 4, 5],
            r#type: BlobType::Credential,
        }))
    });

    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let credential_repository = Arc::new(credential_repository);
    let validity_manager = setup_validity_manager(Repositories {
        credential_repository: credential_repository.clone(),
        revocation_method_provider: Arc::new(revocation_method_provider),
        formatter_provider: Arc::new(formatter_provider),
        config: Arc::new(generic_config().core),
        blob_storage_provider: Arc::new(blob_storage_provider),
        ..Default::default()
    });

    let holder_check_credential_status =
        HolderCheckCredentialStatus::new(credential_repository, validity_manager);

    // when
    let result = holder_check_credential_status.run(None).await;

    // then
    assert!(result.is_ok());
    let result = result.unwrap();
    let response: HolderCheckCredentialStatusResultDTO = serde_json::from_value(result).unwrap();
    assert_eq!(response.total_checks, 1);
}

#[derive(Default)]
struct Repositories {
    pub credential_repository: Arc<MockCredentialRepository>,
    pub revocation_method_provider: Arc<MockRevocationMethodProvider>,
    pub formatter_provider: Arc<MockCredentialFormatterProvider>,
    pub issuance_protocol_provider: Arc<MockIssuanceProtocolProvider>,
    pub config: Arc<CoreConfig>,
    pub blob_storage_provider: Arc<MockBlobStorageProvider>,
}

fn setup_validity_manager(repositories: Repositories) -> Arc<dyn CredentialValidityManager> {
    Arc::new(CredentialValidityManagerImpl::new(
        repositories.credential_repository,
        repositories.issuance_protocol_provider,
        repositories.revocation_method_provider,
        repositories.formatter_provider,
        repositories.blob_storage_provider,
        Arc::new(NoSessionProvider),
        Arc::new(NoTransactionManager),
        repositories.config,
    ))
}

fn generic_credential() -> Credential {
    let now = crate::clock::now_utc();

    let claim_schema = ClaimSchema {
        array: false,
        id: Uuid::new_v4().into(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
        metadata: false,
        translations: Default::default(),
        required: true,
    };
    let organisation = dummy_organisation(None);

    let credential_id = Uuid::new_v4().into();
    let issuer_did = Did {
        deleted_at: None,
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "did1".to_string(),
        organisation: organisation.clone().into(),
        did: "did:example:1".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".into(),
        keys: vec![RelatedKey {
            role: KeyRole::AssertionMethod,
            key: Key {
                autogenerated: false,
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: dummy_organisation(None).into(),
            },
            reference: "1".to_string(),
        }]
        .into(),
        deactivated: false,
        log: None,
    };

    let credential_schema_id = Uuid::new_v4().into();
    let format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "JWT".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: Default::default(),
    };
    Credential {
        expires_at: None,
        ecosystem: None,
        id: credential_id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: vec![Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: Some("123".to_string()),
            path: claim_schema.key.clone(),
            selectively_disclosable: false,
            schema: claim_schema.clone().into(),
        }]
        .into(),
        issuer_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "identifier".to_string(),
                data: IdentifierData::Did((issuer_did).into()),
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                autogenerated: false,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
                logo: None,
                translations: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        schema: CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            deleted_at: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            wallet_attestation: WalletAttestation {
                require_instance_attestation: false,
                key_storage_security_level: Some(KeyStorageSecurity::Basic),
                preferred_key_storage_attestation_lifetime: None,
                preferred_instance_attestation_lifetime: None,
            },
            formats: vec![format.clone()].into(),
            claim_schemas: vec![claim_schema].into(),
            organisation: organisation.into(),
            layout_properties: None,
            allow_suspension: true,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        }
        .into(),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: Some(Uuid::new_v4().into()),
        wallet_key_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    }
}
