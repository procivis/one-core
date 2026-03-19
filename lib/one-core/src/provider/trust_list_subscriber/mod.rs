use std::collections::HashMap;

use serde::Serialize;
use shared_types::IdentifierId;
use standardized_types::etsi_119_602::TrustedEntityInformation;
use url::Url;

use crate::model::identifier::Identifier;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;

pub mod error;
pub(crate) mod etsi_lote;
pub mod provider;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait TrustListSubscriber: Send + Sync {
    fn get_capabilities(&self) -> TrustListSubscriberCapabilities;

    async fn validate_subscription(
        &self,
        reference: &Url,
        role: Option<TrustListRoleEnum>,
    ) -> Result<TrustListValidationSuccess, TrustListSubscriberError>;

    async fn resolve_entries(
        &self,
        reference: &Url,
        identifiers: &[Identifier],
    ) -> Result<HashMap<IdentifierId, TrustEntityResponse>, TrustListSubscriberError>;
}

#[derive(Debug, Serialize)]
pub struct TrustListSubscriberCapabilities {
    pub roles: Vec<TrustListRoleEnum>,
}

#[derive(Debug)]
pub struct TrustListValidationSuccess {
    pub role: TrustListRoleEnum,
}

#[derive(Debug)]
pub enum TrustEntityResponse {
    LOTE(TrustedEntityInformation),
}
