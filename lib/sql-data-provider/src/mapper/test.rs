use std::error::Error;

use one_core::error::{ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use rstest::rstest;
use sea_orm::{ConnectionTrait, Database, RuntimeErr};
use similar_asserts::assert_eq;

use super::{DataLayerError, DbErr, to_data_layer_error, to_update_data_layer_error};

#[rstest]
#[case::insert_unique("INSERT INTO child VALUES (1, 1)", true)]
#[case::insert_foreign_key("INSERT INTO child VALUES (3, 99)", false)]
#[case::update_unique("UPDATE child SET id = 1 WHERE id = 2", true)]
#[case::update_foreign_key("UPDATE child SET parent_id = 99 WHERE id = 2", false)]
#[tokio::test]
async fn constraint_errors_retain_details(
    #[case] statement: &str,
    #[case] unique: bool,
    #[values(to_data_layer_error, to_update_data_layer_error)] map: fn(DbErr) -> DataLayerError,
) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.execute_unprepared(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE parent (id INTEGER PRIMARY KEY);
         CREATE TABLE child (
             id INTEGER PRIMARY KEY,
             parent_id INTEGER REFERENCES parent(id)
         );
         INSERT INTO parent VALUES (1);
         INSERT INTO child VALUES (1, 1), (2, 1);",
    )
    .await
    .unwrap();

    let original = db.execute_unprepared(statement).await.unwrap_err();
    let details = original.to_string();
    let error = map(original.clone());

    if unique {
        assert!(matches!(error, DataLayerError::AlreadyExists(_)));
        assert_eq!(error.error_code(), ErrorCode::BR_0357);
        assert!(
            error
                .to_string()
                .contains("UNIQUE constraint failed: child.id")
        );
    } else {
        assert!(matches!(error, DataLayerError::IncorrectParameters(_)));
        assert_eq!(error.error_code(), ErrorCode::BR_0000);
        assert!(error.to_string().contains("FOREIGN KEY constraint failed"));
    }
    assert!(error.to_string().contains(&details));
    assert_eq!(
        error.source().unwrap().downcast_ref::<DbErr>(),
        Some(&original)
    );
    // Services add context before logging the error using Display.
    assert!(
        error
            .error_while("writing a record")
            .to_string()
            .contains(&details)
    );
}

#[rstest]
#[case::not_found(DbErr::RecordNotFound("credential 123 was not found".into()))]
#[case::not_updated(DbErr::RecordNotUpdated)]
fn update_errors_retain_details(#[case] original: DbErr) {
    let error = to_update_data_layer_error(original.clone());

    assert!(matches!(error, DataLayerError::RecordNotUpdated(_)));
    assert_eq!(error.error_code(), ErrorCode::BR_0000);
    assert!(error.to_string().contains(&original.to_string()));
    assert_eq!(
        error.source().unwrap().downcast_ref::<DbErr>(),
        Some(&original)
    );
}

#[rstest]
#[case::connection(DbErr::Conn(RuntimeErr::Internal("connection unavailable".into())))]
#[case::query(DbErr::Query(RuntimeErr::Internal("unknown column credential.format".into())))]
#[case::execution(DbErr::Exec(RuntimeErr::Internal("disk full".into())))]
#[case::not_inserted(DbErr::RecordNotInserted)]
fn other_database_errors_retain_details(
    #[case] original: DbErr,
    #[values(to_data_layer_error, to_update_data_layer_error)] map: fn(DbErr) -> DataLayerError,
) {
    let error = map(original.clone());

    assert!(matches!(error, DataLayerError::Db(_)));
    assert_eq!(error.error_code(), ErrorCode::BR_0054);
    assert!(error.to_string().contains(&original.to_string()));
    assert_eq!(
        error.source().unwrap().downcast_ref::<DbErr>(),
        Some(&original)
    );
}
