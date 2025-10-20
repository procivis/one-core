use shared_types::{IdentifierId, OrganisationId};

use crate::config::core_config::{ConfigExt, CoreConfig, KeyAlgorithmType};
use crate::model::certificate::CertificateRelations;
use crate::model::did::{DidRelations, KeyFilter};
use crate::model::identifier::IdentifierRelations;
use crate::model::key::KeyRelations;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::wallet_provider::error::WalletProviderError;

pub(super) async fn validate_wallet_provider_issuer(
    id: Option<&OrganisationId>,
    issuer_id: IdentifierId,
    identifier_repository: &dyn IdentifierRepository,
) -> Result<(), ServiceError> {
    let Some(id) = id else {
        return Err(BusinessLogicError::IdentifierOrganisationMismatch)?;
    };
    let identifier = identifier_repository
        .get(
            issuer_id,
            &IdentifierRelations {
                organisation: Default::default(),
                did: Some(DidRelations {
                    keys: Some(KeyRelations::default()),
                    ..Default::default()
                }),
                key: Some(KeyRelations::default()),
                certificates: Some(CertificateRelations {
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                }),
            },
        )
        .await?;
    let Some(identifier) = identifier else {
        return Err(EntityNotFoundError::Identifier(issuer_id))?;
    };
    if !identifier
        .organisation
        .as_ref()
        .is_some_and(|org| &org.id == id)
    {
        return Err(BusinessLogicError::IdentifierOrganisationMismatch)?;
    };
    identifier
        .find_matching_key(&KeyFilter {
            role: None,
            algorithms: Some(vec![KeyAlgorithmType::Ecdsa]),
        })?
        .ok_or(WalletProviderError::IssuerKeyWithAlgorithmNotFound(
            KeyAlgorithmType::Ecdsa,
        ))?;
    Ok(())
}

pub(super) async fn validate_wallet_provider(
    wallet_provider: &str,
    config: &CoreConfig,
    organisation_repository: &dyn OrganisationRepository,
) -> Result<(), ServiceError> {
    config.wallet_provider.get_if_enabled(wallet_provider)?;
    if let Some(org) = organisation_repository
        .get_organisation_for_wallet_provider(wallet_provider)
        .await?
    {
        Err(BusinessLogicError::WalletProviderAlreadyAssociated(org.id))?
    }
    Ok(())
}
