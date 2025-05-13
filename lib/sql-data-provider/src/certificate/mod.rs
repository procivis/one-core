use std::sync::Arc;

use one_core::repository::key_repository::KeyRepository;
use sea_orm::DatabaseConnection;

pub mod history;
pub mod mapper;
pub mod repository;

pub(crate) struct CertificateProvider {
    pub db: DatabaseConnection,

    pub key_repository: Arc<dyn KeyRepository>,
}

#[cfg(test)]
mod test;
