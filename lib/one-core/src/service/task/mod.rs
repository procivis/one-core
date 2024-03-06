use std::sync::Arc;

use crate::provider::task::provider::TaskProvider;

pub mod service;

#[derive(Clone)]
pub struct TaskService {
    task_provider: Arc<dyn TaskProvider>,
}

impl TaskService {
    pub fn new(task_provider: Arc<dyn TaskProvider>) -> Self {
        Self { task_provider }
    }
}
