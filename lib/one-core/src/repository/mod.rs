pub mod error;

// Old traits. FIXME: Remove one day
pub mod data_provider;

// New traits
pub mod organisation_repository;

use std::sync::Arc;

use data_provider::DataProvider;
use organisation_repository::OrganisationRepository;

pub trait DataRepository {
    fn get_data_provider(&self) -> Arc<dyn DataProvider + Send + Sync>;
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository + Send + Sync>;
}
