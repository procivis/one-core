use std::sync::Arc;

use mockall::predicate::eq;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::config::core_config::RevocationType;
use crate::model::revocation_list::{
    RevocationList, RevocationListPurpose, RevocationListRelations, StatusListCredentialFormat,
};
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::revocation_list_repository::MockRevocationListRepository;
use crate::service::revocation_list::RevocationListService;
use crate::service::revocation_list::dto::RevocationListResponseDTO;
use crate::service::test_utilities::generic_config;

#[derive(Default)]
struct Repositories {
    pub revocation_list_repository: MockRevocationListRepository,
    pub revocation_method_provider: MockRevocationMethodProvider,
}

fn setup_service(repositories: Repositories) -> RevocationListService {
    RevocationListService::new(
        Arc::new(repositories.revocation_list_repository),
        Arc::new(repositories.revocation_method_provider),
        Arc::new(generic_config().core),
    )
}

#[tokio::test]
async fn test_get_revocation_list() {
    let mut revocation_list_repository = MockRevocationListRepository::default();

    let revocation_id = Uuid::new_v4().into();
    {
        let revocation = RevocationList {
            id: revocation_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            formatted_list: b"revocation-list-credential".to_vec(),
            purpose: RevocationListPurpose::Revocation,
            issuer_identifier: None,
            format: StatusListCredentialFormat::Jwt,
            r#type: "BITSTRINGSTATUSLIST".into(),
            issuer_certificate: None,
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
            r#type: RevocationType::BitstringStatusList
        }
    );
}
