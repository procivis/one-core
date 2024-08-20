use std::future::Future;
use std::sync::Arc;

use futures::FutureExt;
use tokio::select;
use tokio::sync::oneshot::{Receiver, Sender};
use tokio::sync::{oneshot, Mutex, MutexGuard};
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;
use uuid::Uuid;

use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::provider::bluetooth_low_energy::BleError;

/// Represents flow that requires exclusive access to BLE
struct Action {
    /// Unique id
    task_id: Uuid,
    /// Id of flow that is running
    flow_id: Uuid,
    /// Indicates if flow has multiple steps
    expect_continuation: bool,
    tracker: TaskTracker,
    abort: Sender<()>,
    _cancellation_token: DropGuard,
}

impl Action {
    fn finished(&self) -> bool {
        !self.expect_continuation && self.tracker.is_empty()
    }

    async fn abort(self) {
        let _ = self.abort.send(());
        self.tracker.wait().await;
    }
}

/// Represents action that should be taken when another flow is using BLE
pub enum OnConflict {
    /// Do not abort active task
    DoNothing,
    /// Abort active task
    Replace,
    /// Abort active task if [`Action::flow_id`] matches given flow_id
    ReplaceIfSameFlow,
}

pub enum JoinResult<T> {
    Ok(T),
    Aborted,
}

impl<T> JoinResult<T> {
    pub fn ok_or<E>(self, err: E) -> Result<T, E> {
        match self {
            JoinResult::Ok(v) => Ok(v),
            JoinResult::Aborted => Err(err),
        }
    }
}

pub enum ScheduleResult<T> {
    Scheduled {
        /// Handle to async computation
        handle: Receiver<JoinResult<T>>,
        task_id: Uuid,
    },
    Busy,
}

impl<T> ScheduleResult<T> {
    pub async fn value_or<E>(self, err: E) -> Result<(Uuid, JoinResult<T>), E> {
        match self {
            Self::Scheduled { handle, task_id } => {
                let result = handle.await.map_err(|_| err)?;
                Ok((task_id, result))
            }
            Self::Busy => Err(err),
        }
    }

    pub fn is_scheduled(&self) -> bool {
        matches!(self, Self::Scheduled { .. })
    }
}

pub struct BleStatus {
    pub central: bool,
    pub peripheral: bool,
}

/// Ensures exclusive access to BLE interface
#[derive(Clone)]
pub struct BleWaiter {
    central: Arc<dyn BleCentral>,
    peripheral: Arc<dyn BlePeripheral>,
    state: Arc<Mutex<Option<Action>>>,
}

impl BleWaiter {
    pub fn new(central: Arc<dyn BleCentral>, peripheral: Arc<dyn BlePeripheral>) -> Self {
        Self {
            central,
            peripheral,
            state: Default::default(),
        }
    }

    /// Schedule flow
    pub async fn schedule<F, C, FR, CR>(
        &self,
        flow_id: Uuid,
        flow: F,
        cancelation: C,
        on_conflict: OnConflict,
        expect_continuation: bool,
    ) -> ScheduleResult<FR::Output>
    where
        F: FnOnce(Uuid, Arc<dyn BleCentral>, Arc<dyn BlePeripheral>) -> FR,
        FR: Future + Send + 'static,
        FR::Output: Send + 'static,
        C: (FnOnce(Arc<dyn BleCentral>, Arc<dyn BlePeripheral>) -> CR) + Send + 'static,
        CR: Future + Send,
    {
        let mut state = self.state.lock().await;
        match (state.as_ref(), on_conflict) {
            (None, _) => {
                let (action, handle) = self.spawn(flow_id, flow, cancelation, expect_continuation);
                let task_id = action.task_id;
                state.replace(action);
                ScheduleResult::Scheduled { handle, task_id }
            }
            (Some(action), _) if action.finished() => {
                let (action, handle) = self.spawn(flow_id, flow, cancelation, expect_continuation);
                let task_id = action.task_id;
                state.replace(action);
                ScheduleResult::Scheduled { handle, task_id }
            }
            (Some(_), OnConflict::DoNothing) => ScheduleResult::Busy,
            (Some(_), OnConflict::Replace) => {
                self.abort_inner(&mut state, None, false).await;
                let (action, handle) = self.spawn(flow_id, flow, cancelation, expect_continuation);
                let task_id = action.task_id;
                state.replace(action);
                ScheduleResult::Scheduled { handle, task_id }
            }
            (Some(running), OnConflict::ReplaceIfSameFlow) if running.flow_id == flow_id => {
                self.abort_inner(&mut state, None, false).await;
                let (action, handle) = self.spawn(flow_id, flow, cancelation, expect_continuation);
                let task_id = action.task_id;
                state.replace(action);
                ScheduleResult::Scheduled { handle, task_id }
            }
            (Some(_), OnConflict::ReplaceIfSameFlow) => ScheduleResult::Busy,
        }
    }

    /// Schedule next step of flow
    pub async fn schedule_continuation<F, C, FR, CR>(
        &self,
        task_id: Uuid,
        flow: F,
        cancelation: C,
        expect_continuation: bool,
    ) -> ScheduleResult<FR::Output>
    where
        F: FnOnce(Uuid, Arc<dyn BleCentral>, Arc<dyn BlePeripheral>) -> FR,
        FR: Future + Send + 'static,
        FR::Output: Send + 'static,
        C: (FnOnce(Arc<dyn BleCentral>, Arc<dyn BlePeripheral>) -> CR) + Send + 'static,
        CR: Future + Send,
    {
        let mut state = self.state.lock().await;
        match state.as_ref() {
            None => ScheduleResult::Busy,
            Some(action) if action.task_id == task_id && action.expect_continuation => {
                action.tracker.wait().await;
                let (action, handle) =
                    self.spawn(action.flow_id, flow, cancelation, expect_continuation);
                let task_id = action.task_id;
                state.replace(action);
                ScheduleResult::Scheduled { handle, task_id }
            }
            Some(_) => ScheduleResult::Busy,
        }
    }

    pub async fn abort(&self, flow_id: Option<Uuid>) {
        let mut state = self.state.lock().await;
        self.abort_inner(&mut state, flow_id, true).await
    }

    pub async fn is_enabled(&self) -> Result<BleStatus, BleError> {
        let central = self.central.is_adapter_enabled().await?;
        let peripheral = self.peripheral.is_adapter_enabled().await?;
        Ok(BleStatus {
            central,
            peripheral,
        })
    }

    fn spawn<C, F, FR, CR>(
        &self,
        flow_id: Uuid,
        flow: F,
        cancellation: C,
        expect_continuation: bool,
    ) -> (Action, Receiver<JoinResult<FR::Output>>)
    where
        F: FnOnce(Uuid, Arc<dyn BleCentral>, Arc<dyn BlePeripheral>) -> FR,
        FR: Future + Send + 'static,
        FR::Output: Send + 'static,
        C: (FnOnce(Arc<dyn BleCentral>, Arc<dyn BlePeripheral>) -> CR) + Send + 'static,
        CR: Future + Send,
    {
        let task_id = Uuid::new_v4();
        let tracker = TaskTracker::new();
        let cancellation_token = CancellationToken::new();
        let (abort, on_abort) = oneshot::channel();
        let (finish, on_finish) = oneshot::channel();
        let task = flow(task_id, self.central.clone(), self.peripheral.clone());
        let central = self.central.clone();
        let peripheral = self.peripheral.clone();

        let on_abort = on_abort.shared();

        let cloned_token = cancellation_token.clone();
        let cloned_abort = on_abort.clone();

        let cancellation_handler = tokio::spawn(async move {
            select! {
                biased;

                Ok(_) = cloned_abort => {
                    let _ = cancellation(central.clone(), peripheral.clone()).await;
                }
                _ = cloned_token.cancelled() => {}
            }
        });

        tracker.spawn(async move {
            let result = select! {
                val = task => JoinResult::Ok(val),
                Ok(_) = on_abort => {
                    let _ = cancellation_handler.await;
                    JoinResult::Aborted
                }
            };
            let _ = finish.send(result);
        });

        tracker.close();

        (
            Action {
                task_id,
                flow_id,
                tracker,
                abort,
                expect_continuation,
                _cancellation_token: cancellation_token.drop_guard(),
            },
            on_finish,
        )
    }

    async fn abort_inner<'a>(
        &self,
        state: &mut MutexGuard<'_, Option<Action>>,
        flow_id: Option<Uuid>,
        abort_if_finished: bool,
    ) {
        let Some(action) = state.take() else {
            return;
        };

        if action.tracker.is_empty() && !abort_if_finished {
            return;
        }

        match flow_id {
            None => action.abort().await,
            Some(flow_id) if action.flow_id == flow_id => action.abort().await,
            Some(_) => (),
        }
    }
}
