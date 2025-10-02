use std::collections::HashMap;
use std::sync::Arc;

use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::model::blob::{Blob, BlobType};
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
use crate::proto::session_provider::{NoSessionProvider, SessionProvider};
use crate::provider::blob_storage_provider::{MockBlobStorage, MockBlobStorageProvider};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::CredentialRevocationState;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::task::Task;
use crate::provider::task::holder_check_credential_status::dto::HolderCheckCredentialStatusResultDTO;
use crate::provider::task::holder_check_credential_status::{HolderCheckCredentialStatus, Params};
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::revocation_list_repository::MockRevocationListRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::certificate::validator::MockCertificateValidator;
use crate::service::credential::CredentialService;
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

    let credential_clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .returning(move |_, _| Ok(Some(credential_clone.clone())));

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

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

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
        .returning(move |_| Some(blob_storage.clone()));

    let credential_repository = Arc::new(credential_repository);
    let service = setup_service(Repositories {
        credential_repository: credential_repository.clone(),
        revocation_method_provider: Arc::new(revocation_method_provider),
        history_repository: Arc::new(history_repository),
        formatter_provider: Arc::new(formatter_provider),
        config: Arc::new(generic_config().core),
        blob_storage_provider: Arc::new(blob_storage_provider),
        ..Default::default()
    });

    let params = Params {
        organisation_id: None,
        force_refresh: None,
    };

    let holder_check_credential_status =
        HolderCheckCredentialStatus::new(Some(params), credential_repository, service);

    // when
    let result = holder_check_credential_status.run().await;

    // then
    assert!(result.is_ok());
    let result = result.unwrap();
    let response: HolderCheckCredentialStatusResultDTO = serde_json::from_value(result).unwrap();
    assert_eq!(response.total_checks, 1);
}

#[derive(Default)]
struct Repositories {
    pub credential_repository: Arc<MockCredentialRepository>,
    pub credential_schema_repository: Arc<MockCredentialSchemaRepository>,
    pub identifier_repository: Arc<MockIdentifierRepository>,
    pub history_repository: Arc<MockHistoryRepository>,
    pub interaction_repository: Arc<MockInteractionRepository>,
    pub revocation_list_repository: Arc<MockRevocationListRepository>,
    pub revocation_method_provider: Arc<MockRevocationMethodProvider>,
    pub formatter_provider: Arc<MockCredentialFormatterProvider>,
    pub protocol_provider: Arc<MockIssuanceProtocolProvider>,
    pub did_method_provider: Arc<MockDidMethodProvider>,
    pub key_provider: Arc<MockKeyProvider>,
    pub key_algorithm_provider: Arc<MockKeyAlgorithmProvider>,
    pub certificate_validator: Arc<MockCertificateValidator>,
    pub config: Arc<CoreConfig>,
    pub lvvc_repository: Arc<MockValidityCredentialRepository>,
    pub blob_storage_provider: Arc<MockBlobStorageProvider>,
    pub session_provider: Option<Arc<dyn SessionProvider>>,
}

fn setup_service(repositories: Repositories) -> CredentialService {
    CredentialService::new(
        repositories.credential_repository,
        repositories.credential_schema_repository,
        repositories.identifier_repository,
        repositories.history_repository,
        repositories.interaction_repository,
        repositories.revocation_list_repository,
        repositories.revocation_method_provider,
        repositories.formatter_provider,
        repositories.protocol_provider,
        repositories.did_method_provider,
        repositories.key_provider,
        repositories.key_algorithm_provider,
        repositories.config,
        repositories.lvvc_repository,
        None,
        Arc::new(ReqwestClient::default()),
        repositories.certificate_validator,
        repositories.blob_storage_provider,
        repositories
            .session_provider
            .unwrap_or(Arc::new(NoSessionProvider)),
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
        metadata: false,
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
            id: Uuid::new_v4(),
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
        profile: None,
        credential_blob_id: Some(Uuid::new_v4().into()),
        wallet_unit_attestation_blob_id: None,
    }
}
