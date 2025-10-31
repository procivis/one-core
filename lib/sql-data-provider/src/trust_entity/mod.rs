use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;

use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod model;
pub mod repository;

pub(crate) struct TrustEntityProvider {
    pub db: TransactionManagerImpl,
    pub trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}
