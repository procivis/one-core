use std::sync::Arc;

use mockall::predicate::eq;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::revocation_list::{
    RevocationList, RevocationListPurpose, RevocationListRelations, StatusListCredentialFormat,
    StatusListType,
};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::revocation_list_repository::MockRevocationListRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::revocation_list::RevocationListService;
use crate::service::revocation_list::dto::RevocationListResponseDTO;
use crate::service::test_utilities::generic_config;

#[derive(Default)]
struct Repositories {
    pub credential_repository: MockCredentialRepository,
    pub lvvc_repository: MockValidityCredentialRepository,
    pub revocation_list_repository: MockRevocationListRepository,
    pub did_method_provider: MockDidMethodProvider,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub key_provider: MockKeyProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub certificate_validator: MockCertificateValidator,
}

fn setup_service(repositories: Repositories) -> RevocationListService {
    RevocationListService::new(
        None,
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.lvvc_repository),
        Arc::new(repositories.revocation_list_repository),
        Arc::new(repositories.did_method_provider),
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.key_provider),
        Arc::new(repositories.key_algorithm_provider),
        Arc::new(repositories.revocation_method_provider),
        Arc::new(generic_config().core),
        Arc::new(repositories.certificate_validator),
    )
}

#[tokio::test]
async fn test_get_revocation_list() {
    let mut revocation_list_repository = MockRevocationListRepository::default();

    let revocation_id = Uuid::new_v4();
    {
        let revocation = RevocationList {
            id: revocation_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            credentials: b"revocation-list-credential".to_vec(),
            purpose: RevocationListPurpose::Revocation,
            issuer_identifier: None,
            format: StatusListCredentialFormat::Jwt,
            r#type: StatusListType::BitstringStatusList,
        };

        revocation_list_repository
            .expect_get_revocation_list()
            .times(1)
            .with(
                eq(revocation_id.to_owned()),
                eq(RevocationListRelations::default()),
            )
            .returning(move |_, _| Ok(Some(revocation.clone())));
    }

    let service = setup_service(Repositories {
        revocation_list_repository,
        ..Default::default()
    });

    let result = service
        .get_revocation_list_by_id(&revocation_id.to_owned())
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();

    assert_eq!(
        result,
        RevocationListResponseDTO {
            revocation_list: "revocation-list-credential".to_owned(),
            format: StatusListCredentialFormat::Jwt,
            r#type: StatusListType::BitstringStatusList
        }
    );
}
