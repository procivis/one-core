use std::sync::mpsc;

use rstest::rstest;
use sea_orm::{ConnectionTrait, Database};
use similar_asserts::assert_eq;
use tokio::sync::oneshot;

use super::*;

async fn setup() -> TransactionManagerImpl {
    TransactionManagerImpl::new(Database::connect("sqlite::memory:").await.unwrap())
}

#[tokio::test]
async fn callback_runs_immediately_without_transaction() {
    let manager = setup().await;
    let (sender, receiver) = mpsc::channel();
    manager.on_commit(Box::new(move || sender.send(()).unwrap()));
    receiver.try_recv().unwrap();
}

#[tokio::test]
async fn callback_observes_committed_data() {
    let manager = setup().await;
    manager
        .execute_unprepared("CREATE TABLE test_commit (id INTEGER PRIMARY KEY)")
        .await
        .unwrap();
    let db = manager.db.clone();
    let (sender, mut receiver) = oneshot::channel();

    manager
        .tx(async {
            manager
                .execute_unprepared("INSERT INTO test_commit (id) VALUES (1)")
                .await?;
            manager.on_commit(Box::new(move || {
                // The transaction context must be gone when callbacks execute.
                assert!(TX_CONTEXT.try_with(|_| ()).is_err());
                tokio::spawn(async move {
                    let row = db
                        .query_one_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            "SELECT id FROM test_commit",
                        ))
                        .await
                        .unwrap()
                        .unwrap();
                    sender.send(row.try_get::<i32>("", "id").unwrap()).unwrap();
                });
            }));
            assert!(matches!(
                receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            Ok::<_, DbErr>(())
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), receiver)
            .await
            .unwrap()
            .unwrap(),
        1
    );
}

#[rstest]
#[tokio::test]
async fn nested_callbacks_follow_transaction_outcome(
    #[values(false, true)] rollback_outer: bool,
    #[values(false, true)] rollback_inner: bool,
) {
    let manager = setup().await;
    let (sender, receiver) = mpsc::channel();
    let receiver = std::sync::Mutex::new(receiver);

    let result = manager
        .tx(async {
            let outer_sender = sender.clone();
            manager.on_commit(Box::new(move || outer_sender.send("outer").unwrap()));
            let inner_result = manager
                .tx(async {
                    let inner_sender = sender.clone();
                    manager.on_commit(Box::new(move || inner_sender.send("inner").unwrap()));
                    assert!(receiver.lock().unwrap().try_recv().is_err());
                    if rollback_inner {
                        return Err(DataLayerError::TransactionError("inner rollback".into()));
                    }
                    Ok(())
                })
                .await?;
            assert_eq!(inner_result.is_err(), rollback_inner);
            // Releasing a savepoint must not dispatch any callbacks.
            assert!(receiver.lock().unwrap().try_recv().is_err());
            manager.on_commit(Box::new(move || sender.send("after inner").unwrap()));
            if rollback_outer {
                return Err(DataLayerError::TransactionError("outer rollback".into()));
            }
            Ok(())
        })
        .await
        .unwrap();

    assert_eq!(result.is_err(), rollback_outer);
    let expected = if rollback_outer {
        vec![]
    } else if rollback_inner {
        vec!["outer", "after inner"]
    } else {
        vec!["outer", "inner", "after inner"]
    };
    assert_eq!(
        receiver
            .into_inner()
            .unwrap()
            .try_iter()
            .collect::<Vec<_>>(),
        expected
    );
}

#[tokio::test]
async fn cancelled_transaction_discards_callbacks() {
    let manager = setup().await;
    let (sender, receiver) = mpsc::channel();
    let (registered, ready) = oneshot::channel();
    let transaction = manager.transaction(Box::pin(async {
        manager.on_commit(Box::new(move || sender.send(()).unwrap()));
        registered.send(()).unwrap();
        std::future::pending().await
    }));
    tokio::select! {
        _ = transaction => panic!("Transaction should stay pending"),
        _ = ready => {}
    }
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
}

#[tokio::test]
async fn failed_commit_discards_callbacks() {
    let manager = setup().await;
    manager
        .execute_unprepared("PRAGMA foreign_keys = ON")
        .await
        .unwrap();
    manager
        .execute_unprepared("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
        .await
        .unwrap();
    manager
        .execute_unprepared(
            "CREATE TABLE child (parent_id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)",
        )
        .await
        .unwrap();
    let (sender, receiver) = mpsc::channel();

    let result = manager
        .tx(async {
            // The foreign key is checked at commit rather than at insertion.
            manager
                .execute_unprepared("INSERT INTO child VALUES (1)")
                .await
                .unwrap();
            manager.on_commit(Box::new(move || sender.send(()).unwrap()));
            Ok::<_, DbErr>(())
        })
        .await;

    assert!(matches!(result, Err(DataLayerError::TransactionError(_))));
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
}
