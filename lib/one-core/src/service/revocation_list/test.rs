use crate::model::revocation_list::{RevocationList, RevocationListRelations};
use crate::repository::mock::revocation_list_repository::MockRevocationListRepository;
use crate::service::revocation_list::RevocationListService;
use mockall::predicate::eq;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
struct Repositories {
    pub revocation_list_repository: MockRevocationListRepository,
}

fn setup_service(repositories: Repositories) -> RevocationListService {
    RevocationListService::new(Arc::new(repositories.revocation_list_repository))
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
            issuer_did: None,
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
    });

    let result = service
        .get_revocation_list_by_id(&revocation_id.to_owned())
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result, "revocation-list-credential");
}
