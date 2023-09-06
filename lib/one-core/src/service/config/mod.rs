use crate::config::data_structure::CoreConfig;
use std::sync::Arc;

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
