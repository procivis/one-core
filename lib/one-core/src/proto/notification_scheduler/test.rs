use std::pin::Pin;
use std::sync::Mutex;

use rstest::rstest;
use serde_json::json;
use similar_asserts::assert_eq;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::*;
use crate::proto::notification_sender::{MockNotificationSender, NotificationResult};
use crate::proto::transaction_manager::{AccessMode, IsolationLevel, NoTransactionManager};
use crate::repository::error::DataLayerError;
use crate::repository::notification_repository::MockNotificationRepository;

#[derive(Default)]
struct DeferredCommit {
    callback: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[async_trait::async_trait]
impl TransactionManager for DeferredCommit {
    fn on_commit(&self, callback: Box<dyn FnOnce() + Send>) {
        assert!(self.callback.lock().unwrap().replace(callback).is_none());
    }

    async fn transaction_with_config(
        &self,
        _future: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'async_trait>>,
        _isolation_level: Option<IsolationLevel>,
        _access_mode: Option<AccessMode>,
    ) -> Result<Result<(), anyhow::Error>, DataLayerError> {
        unreachable!("Scheduling only registers a commit callback")
    }
}

#[rstest]
#[case::accepted(NotificationPayload::Credential(Uuid::new_v4().into(), CredentialStateEnum::Accepted), "ACCEPTED")]
#[case::suspended(NotificationPayload::Credential(Uuid::new_v4().into(), CredentialStateEnum::Suspended), "SUSPENDED")]
#[case::revoked(NotificationPayload::Credential(Uuid::new_v4().into(), CredentialStateEnum::Revoked), "REVOKED")]
#[case::rejected(NotificationPayload::Credential(Uuid::new_v4().into(), CredentialStateEnum::Rejected), "REJECTED")]
#[case::error(NotificationPayload::Credential(Uuid::new_v4().into(), CredentialStateEnum::Error), "ERROR")]
#[case::proof(NotificationPayload::Proof(Uuid::new_v4().into(), ProofStateEnum::Accepted), "ACCEPTED")]
#[tokio::test]
async fn notification_dispatch_waits_for_commit(
    #[case] payload: NotificationPayload,
    #[case] status: &'static str,
    #[values(false, true)] in_transaction: bool,
) {
    let id = Uuid::new_v4().into();
    let mut repository = MockNotificationRepository::new();
    repository
        .expect_create()
        .once()
        .return_once(move |notification| {
            let body: serde_json::Value = serde_json::from_slice(&notification.payload).unwrap();
            assert_eq!(body["status"], status);
            Ok(id)
        });
    let (sent, mut received) = oneshot::channel();
    let mut sender = MockNotificationSender::new();
    sender
        .expect_send_notification()
        .once()
        .return_once(move |id, _| {
            sent.send(id).unwrap();
            Ok(NotificationResult::Delivered)
        });
    let config = CoreConfig {
        task: serde_json::from_value(json!({
            "WEBHOOK_NOTIFY": {
                "type": "WEBHOOK_NOTIFY",
                "display": "Webhook",
                "params": { "public": { "requestTimeoutSeconds": 30 } }
            }
        }))
        .unwrap(),
        ..Default::default()
    };
    let deferred = Arc::new(DeferredCommit::default());
    let tx_manager: Arc<dyn TransactionManager> = if in_transaction {
        deferred.clone()
    } else {
        Arc::new(NoTransactionManager)
    };
    let scheduler = NotificationSchedulerImpl::new(
        Arc::new(repository),
        Arc::new(sender),
        tx_manager,
        Arc::new(config),
    );

    assert_eq!(
        scheduler
            .schedule(
                "https://example.com/webhook",
                payload,
                "WEBHOOK_NOTIFY".into(),
                Uuid::new_v4().into(),
                None,
            )
            .await
            .unwrap(),
        id
    );

    if in_transaction {
        assert!(matches!(
            received.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        let callback = deferred
            .callback
            .lock()
            .unwrap()
            .take()
            .expect("Dispatch must be registered for commit");
        callback();
    }
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), received)
            .await
            .unwrap()
            .unwrap(),
        id
    );
}
