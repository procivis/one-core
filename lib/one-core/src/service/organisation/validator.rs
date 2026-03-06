use shared_types::{IdentifierId, OrganisationId};

use super::error::OrganisationServiceError;
use crate::config::core_config::{ConfigExt, CoreConfig, KeyAlgorithmType};
use crate::error::ContextWithErrorCode;
use crate::model::certificate::CertificateRelations;
use crate::model::did::DidRelations;
use crate::model::identifier::IdentifierRelations;
use crate::model::key::KeyRelations;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::wallet_provider::error::WalletProviderError;
use crate::util::key_selection::KeyFilter;

pub(super) async fn validate_wallet_provider_issuer(
    id: Option<&OrganisationId>,
    issuer_id: IdentifierId,
    identifier_repository: &dyn IdentifierRepository,
) -> Result<(), OrganisationServiceError> {
    let Some(id) = id else {
        return Err(OrganisationServiceError::IdentifierOrganisationMismatch);
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
        .await
        .error_while("getting identifier")?;
    let Some(identifier) = identifier else {
        return Err(OrganisationServiceError::IdentifierNotFound(issuer_id));
    };

    if !identifier
        .organisation
        .as_ref()
        .is_some_and(|org| &org.id == id)
    {
        return Err(OrganisationServiceError::IdentifierOrganisationMismatch);
    };

    identifier
        .select_key(
            KeyFilter {
                did_role: None,
                algorithms: Some(vec![KeyAlgorithmType::Ecdsa]),
                ..Default::default()
            }
            .into(),
        )
        .error_while("selecting identifier key")?;
    Ok(())
}

pub(super) async fn validate_wallet_provider(
    wallet_provider: &str,
    config: &CoreConfig,
    organisation_repository: &dyn OrganisationRepository,
) -> Result<(), OrganisationServiceError> {
    config
        .wallet_provider
        .get_if_enabled(wallet_provider)
        .map_err(|_| WalletProviderError::WalletProviderNotConfigured)
        .error_while("checking config")?;
    if let Some(org) = organisation_repository
        .get_organisation_for_wallet_provider(wallet_provider)
        .await
        .error_while("getting organisation")?
    {
        return Err(OrganisationServiceError::WalletProviderAlreadyAssociated(
            org.id,
        ));
    }
    Ok(())
}
