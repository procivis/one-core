use one_core::repository::did_repository::DidRepository;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

pub mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct OrganisationProvider {
    pub db: DatabaseConnection,
    pub did_repository: Arc<dyn DidRepository + Send + Sync>,
}
