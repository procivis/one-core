use std::future::Future;
use std::sync::Arc;

use futures::future::BoxFuture;
use futures::FutureExt;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
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
    handle: JoinHandle<()>,
    cancellation: Box<dyn FnOnce() -> BoxFuture<'static, ()> + Send + 'static>,
}

impl Action {
    fn finished(&self) -> bool {
        !self.expect_continuation && self.handle.is_finished()
    }

    async fn abort(self) {
        self.handle.abort();
        (self.cancellation)().await;
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

pub enum Abort {
    Always,
    Flow(Uuid),
    Task(Uuid),
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
        handle: BoxFuture<'static, JoinResult<T>>,
        task_id: Uuid,
    },
    Busy,
}

impl<T> ScheduleResult<T> {
    pub async fn value_or<E>(self, err: E) -> Result<(Uuid, JoinResult<T>), E> {
        match self {
            Self::Scheduled { handle, task_id } => Ok((task_id, handle.await)),
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
        cancellation: C,
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
        let should_replace = match (state.as_ref(), on_conflict) {
            (None, _) => true,
            (Some(action), _) if action.finished() => true,
            (Some(_), OnConflict::DoNothing) => false,
            (Some(_), OnConflict::Replace) => true,
            (Some(running), OnConflict::ReplaceIfSameFlow) if running.flow_id == flow_id => true,
            (Some(_), OnConflict::ReplaceIfSameFlow) => false,
        };

        if !should_replace {
            return ScheduleResult::Busy;
        }

        self.abort_inner(&mut state, Abort::Always).await;
        let (action, handle) = self.spawn(flow_id, flow, cancellation, expect_continuation);
        let task_id = action.task_id;
        state.replace(action);
        ScheduleResult::Scheduled { handle, task_id }
    }

    /// Schedule next step of flow
    pub async fn schedule_continuation<F, C, FR, CR>(
        &self,
        task_id: Uuid,
        flow: F,
        cancellation: C,
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
        match state.take_if(|action| action.task_id == task_id && action.expect_continuation) {
            None => ScheduleResult::Busy,
            Some(action) => {
                let _ = action.handle.await;
                let (action, handle) =
                    self.spawn(action.flow_id, flow, cancellation, expect_continuation);
                let task_id = action.task_id;
                state.replace(action);
                ScheduleResult::Scheduled { handle, task_id }
            }
        }
    }

    pub async fn abort(&self, abort: Abort) {
        let mut state = self.state.lock().await;
        self.abort_inner(&mut state, abort).await
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
    ) -> (Action, BoxFuture<'static, JoinResult<FR::Output>>)
    where
        F: FnOnce(Uuid, Arc<dyn BleCentral>, Arc<dyn BlePeripheral>) -> FR,
        FR: Future + Send + 'static,
        FR::Output: Send + 'static,
        C: (FnOnce(Arc<dyn BleCentral>, Arc<dyn BlePeripheral>) -> CR) + Send + 'static,
        CR: Future + Send,
    {
        let task_id = Uuid::new_v4();
        let task = flow(task_id, self.central.clone(), self.peripheral.clone());
        let (finish, mut on_finish) = mpsc::channel(2);
        let finish_clone = finish.clone();

        let handle = tokio::spawn(async move {
            let val = task.await;
            let _ = finish.send(JoinResult::Ok(val)).await;
        });

        let central = self.central.clone();
        let peripheral = self.peripheral.clone();

        let cancellation = Box::new(move || {
            async move {
                cancellation(central, peripheral).await;
                let _ = finish_clone.send(JoinResult::Aborted).await;
            }
            .boxed()
        });

        let on_finish =
            async move { on_finish.recv().await.unwrap_or(JoinResult::Aborted) }.boxed();

        (
            Action {
                task_id,
                flow_id,
                expect_continuation,
                handle,
                cancellation,
            },
            on_finish,
        )
    }

    async fn abort_inner(&self, state: &mut Option<Action>, abort: Abort) {
        let Some(action) = state.take() else {
            return;
        };

        if action.finished() {
            return;
        }

        match abort {
            Abort::Always => action.abort().await,
            Abort::Flow(flow_id) if action.flow_id == flow_id => action.abort().await,
            Abort::Task(task_id) if action.task_id == task_id => action.abort().await,
            _ => (),
        }
    }
}
