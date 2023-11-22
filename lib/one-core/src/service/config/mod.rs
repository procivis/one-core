use std::sync::Arc;

use crate::config::core_config::CoreConfig;

pub mod dto;
pub mod service;

mod mapper;

#[derive(Clone)]
pub struct ConfigService {
    config: Arc<CoreConfig>,
}

impl ConfigService {
    pub fn new(config: Arc<CoreConfig>) -> Self {
        Self { config }
    }
}

#[cfg(test)]
mod test;
