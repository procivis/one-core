use crate::repository::revocation_list_repository::RevocationListRepository;
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;
mod validator;

#[derive(Clone)]
pub struct RevocationListService {
    revocation_list_repository: Arc<dyn RevocationListRepository + Send + Sync>,
}

impl RevocationListService {
    pub fn new(
        revocation_list_repository: Arc<dyn RevocationListRepository + Send + Sync>,
    ) -> Self {
        Self {
            revocation_list_repository,
        }
    }
}

#[cfg(test)]
mod test;
