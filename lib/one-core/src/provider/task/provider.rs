use std::{collections::HashMap, sync::Arc};

use super::Task;

#[cfg_attr(test, mockall::automock)]
pub trait TaskProvider: Send + Sync {
    fn get_task(&self, task_id: &str) -> Option<Arc<dyn Task>>;
}

pub struct TaskProviderImpl {
    tasks: HashMap<String, Arc<dyn Task>>,
}

impl TaskProviderImpl {
    pub fn new(tasks: HashMap<String, Arc<dyn Task>>) -> Self {
        Self { tasks }
    }
}

impl TaskProvider for TaskProviderImpl {
    fn get_task(&self, task_id: &str) -> Option<Arc<dyn Task>> {
        self.tasks.get(task_id).cloned()
    }
}
