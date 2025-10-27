use std::future::Future;
use std::sync::Arc;

use futures::FutureExt;
use futures::future::BoxFuture;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;
use uuid::Uuid;

use super::BleError;
use super::low_level::ble_central::{BleCentral, TrackingBleCentral};
use super::low_level::ble_peripheral::{BlePeripheral, TrackingBlePeripheral};

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
    /// Per-flow tracking central
    tracking_central: TrackingBleCentral,
    /// Per-flow tracking peripheral
    tracking_peripheral: TrackingBlePeripheral,
}

impl Action {
    fn finished(&self) -> bool {
        !self.expect_continuation && self.handle.is_finished()
    }

    async fn abort(self) {
        // Stop the task
        self.handle.abort();
        // Run any custom cancellation logic
        (self.cancellation)().await;
        // Teardown the tracking central
        if let Err(err) = self.tracking_central.teardown().await {
            warn!("Failed to teardown BLE central tracking during abort: {err}");
        }
        // Teardown the tracking peripheral
        if let Err(err) = self.tracking_peripheral.teardown().await {
            warn!("Failed to teardown BLE peripheral tracking during abort: {err}");
        }
    }
}

/// Represents action that should be taken when another flow is using BLE
#[expect(dead_code)]
pub enum OnConflict {
    /// Do not abort active task
    DoNothing,
    /// Abort active task
    Replace,
    /// Abort active task if [`Action::flow_id`] matches given flow_id
    ReplaceIfSameFlow,
}

#[expect(dead_code)]
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
            Self::Ok(v) => Ok(v),
            Self::Aborted => Err(err),
        }
    }
}

pub enum ScheduleResult<T, E> {
    Scheduled {
        /// Handle to async computation
        handle: BoxFuture<'static, JoinResult<Result<T, E>>>,
        task_id: Uuid,
    },
    Busy,
}

impl<T, E> ScheduleResult<T, E> {
    pub async fn value_or<Err>(self, err: Err) -> Result<(Uuid, JoinResult<Result<T, E>>), Err> {
        match self {
            Self::Scheduled { handle, task_id } => Ok((task_id, handle.await)),
            Self::Busy => Err(err),
        }
    }

    pub fn is_scheduled(&self) -> bool {
        matches!(self, Self::Scheduled { .. })
    }
}

#[expect(dead_code)]
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
    pub async fn schedule<F, C, FR, CR, T, E>(
        &self,
        flow_id: Uuid,
        flow: F,
        cancellation: C,
        on_conflict: OnConflict,
        expect_continuation: bool,
    ) -> ScheduleResult<T, E>
    where
        F: FnOnce(Uuid, TrackingBleCentral, TrackingBlePeripheral) -> FR,
        FR: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
        C: (FnOnce(TrackingBleCentral, TrackingBlePeripheral) -> CR) + Send + 'static,
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
        let (action, handle) =
            self.spawn(flow_id, flow, cancellation, expect_continuation, None, None);
        let task_id = action.task_id;
        state.replace(action);
        ScheduleResult::Scheduled { handle, task_id }
    }

    /// Schedule next step of flow
    pub async fn schedule_continuation<F, C, FR, CR, T, E>(
        &self,
        task_id: Uuid,
        flow: F,
        cancellation: C,
        expect_continuation: bool,
    ) -> ScheduleResult<T, E>
    where
        F: FnOnce(Uuid, TrackingBleCentral, TrackingBlePeripheral) -> FR,
        FR: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
        C: (FnOnce(TrackingBleCentral, TrackingBlePeripheral) -> CR) + Send + 'static,
        CR: Future + Send,
    {
        let mut state = self.state.lock().await;
        match state.take_if(|action| action.task_id == task_id && action.expect_continuation) {
            None => ScheduleResult::Busy,
            Some(action) => {
                let result = action.handle.await;
                if let Err(err) = result {
                    warn!("Scheduling continuation of task {task_id}. Previous step failed: {err}");
                }
                let (new_action, handle) = self.spawn(
                    action.flow_id,
                    flow,
                    cancellation,
                    expect_continuation,
                    Some(action.tracking_central),
                    Some(action.tracking_peripheral),
                );
                let task_id = new_action.task_id;
                state.replace(new_action);
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

    fn spawn<C, F, FR, CR, T, E>(
        &self,
        flow_id: Uuid,
        flow: F,
        cancellation: C,
        expect_continuation: bool,
        existing_tracking_central: Option<TrackingBleCentral>,
        existing_tracking_peripheral: Option<TrackingBlePeripheral>,
    ) -> (Action, BoxFuture<'static, JoinResult<Result<T, E>>>)
    where
        F: FnOnce(Uuid, TrackingBleCentral, TrackingBlePeripheral) -> FR,
        FR: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
        C: (FnOnce(TrackingBleCentral, TrackingBlePeripheral) -> CR) + Send + 'static,
        CR: Future + Send,
    {
        let task_id = Uuid::new_v4();
        let tracking_central = existing_tracking_central
            .unwrap_or_else(|| TrackingBleCentral::new(self.central.clone()));
        let tracking_peripheral = existing_tracking_peripheral
            .unwrap_or_else(|| TrackingBlePeripheral::new(self.peripheral.clone()));
        let task = flow(
            task_id,
            tracking_central.clone(),
            tracking_peripheral.clone(),
        );
        let (finish, mut on_finish) = mpsc::channel(2);
        let finish_clone = finish.clone();

        let tracking_central_for_completion = tracking_central.clone();
        let tracking_peripheral_for_completion = tracking_peripheral.clone();
        let handle = tokio::spawn(async move {
            let result = task.await;

            // Automatic teardown logic based on result and continuation expectation
            let should_teardown = match &result {
                // Always teardown on error
                Err(_) => true,
                // Teardown on success only if no continuation expected
                Ok(_) => !expect_continuation,
            };

            if should_teardown {
                if let Err(err) = tracking_central_for_completion.teardown().await {
                    warn!("Failed to teardown BLE central tracking after flow completion: {err}");
                }
                if let Err(err) = tracking_peripheral_for_completion.teardown().await {
                    warn!(
                        "Failed to teardown BLE peripheral tracking after flow completion: {err}"
                    );
                }
            }

            let send_result = finish.send(JoinResult::Ok(result)).await;
            if let Err(err) = send_result {
                warn!("Failed to send finish signal: {err}");
            }
        });

        let tracking_central_for_cancellation = tracking_central.clone();
        let tracking_peripheral_for_cancellation = tracking_peripheral.clone();

        let cancellation = Box::new(move || {
            async move {
                cancellation(
                    tracking_central_for_cancellation,
                    tracking_peripheral_for_cancellation,
                )
                .await;
                let result = finish_clone.send(JoinResult::Aborted).await;
                if let Err(err) = result {
                    warn!("Failed to send finish (aborted) signal: {err}");
                }
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
                tracking_central,
                tracking_peripheral,
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
