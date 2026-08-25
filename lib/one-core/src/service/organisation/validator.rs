use shared_types::{IdentifierId, OrganisationId};

use super::dto::UpsertOrganisationConfigurationDTO;
use super::error::OrganisationServiceError;
use crate::config::core_config::{ConfigExt, CoreConfig, KeyAlgorithmType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::instance::InstanceRole;
use crate::model::list_filter::ListFilterCondition;
use crate::model::list_query::ListPagination;
use crate::model::organisation::{Organisation, OrganisationFilterValue, OrganisationListQuery};
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::repository::error::DataLayerError;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::instance::service::provider_metadata_url;
use crate::service::managed_instance::error::ManagedInstanceError;
use crate::util::key_selection::KeyFilter;

pub(super) async fn validate_provider_issuer(
    id: Option<&OrganisationId>,
    issuer_id: IdentifierId,
    identifier_repository: &dyn IdentifierRepository,
) -> Result<(), OrganisationServiceError> {
    let Some(id) = id else {
        return Err(OrganisationServiceError::IdentifierOrganisationMismatch);
    };

    let identifier = identifier_repository
        .get(issuer_id)
        .await
        .error_while("getting identifier")?;

    if &identifier.organisation.id() != id {
        return Err(OrganisationServiceError::IdentifierOrganisationMismatch);
    };

    identifier
        .select_key(KeyFilter::algorithms(vec![KeyAlgorithmType::Ecdsa]).into())
        .await
        .error_while("selecting identifier key")?;
    Ok(())
}

pub(super) async fn validate_parent_organisation(
    organisation_id: OrganisationId,
    parent_organisation_id: OrganisationId,
    organisation_repository: &dyn OrganisationRepository,
) -> Result<(), OrganisationServiceError> {
    if organisation_id == parent_organisation_id {
        return Err(OrganisationServiceError::InvalidParentOrganisation);
    }

    let parent = organisation_repository
        .get_organisation(&parent_organisation_id)
        .await
        .map_err(|error| match error {
            DataLayerError::EntityNotFound { .. } => {
                OrganisationServiceError::ParentOrganisationNotFound(parent_organisation_id)
            }
            error => error.error_while("getting parent organisation").into(),
        })?;

    if parent.parent_organisation.is_some() {
        return Err(OrganisationServiceError::InvalidParentOrganisation);
    }

    let children = organisation_repository
        .get_organisation_list(OrganisationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            filtering: Some(ListFilterCondition::Value(
                OrganisationFilterValue::ParentOrganisations(vec![organisation_id]),
            )),
            ..Default::default()
        })
        .await
        .error_while("checking for existing children")?;
    if children.total_items > 0 {
        return Err(OrganisationServiceError::InvalidParentOrganisation);
    }

    Ok(())
}

pub(super) async fn validate_wallet_provider(
    organisation_id: OrganisationId,
    wallet_provider: &str,
    config: &CoreConfig,
    organisation_repository: &dyn OrganisationRepository,
) -> Result<(), OrganisationServiceError> {
    config
        .wallet_provider
        .get_if_enabled(wallet_provider)
        .map_err(|_| ManagedInstanceError::WalletProviderNotConfigured)
        .error_while("checking config")?;
    if let Some(org) = organisation_repository
        .get_organisation_for_wallet_provider(wallet_provider)
        .await
        .error_while("getting organisation")?
        && org.id != organisation_id
    {
        return Err(OrganisationServiceError::WalletProviderAlreadyAssociated(
            org.id,
        ));
    }
    Ok(())
}

pub(super) async fn validate_verifier_provider(
    organisation_id: OrganisationId,
    verifier_provider: &str,
    config: &CoreConfig,
    organisation_repository: &dyn OrganisationRepository,
) -> Result<(), OrganisationServiceError> {
    config
        .verifier_provider
        .get_if_enabled(verifier_provider)
        .map_err(|_| OrganisationServiceError::VerifierProviderNotConfigured)
        .error_while("checking config")?;
    if let Some(org) = organisation_repository
        .get_organisation_for_verifier_provider(verifier_provider)
        .await
        .error_while("getting organisation")?
        && org.id != organisation_id
    {
        return Err(OrganisationServiceError::VerifierProviderAlreadyAssociated(
            org.id,
        ));
    }
    Ok(())
}

/// An `enforceEcosystemAs*` flag may only be turned off while the provider backing the
/// instance of the corresponding role does not mandate ecosystem enforcement: the holder flag
/// is governed by the wallet provider, the verifier flag by the verifier provider. No provider
/// mandates the issuer flag, which the organisation therefore governs on its own.
pub(super) async fn validate_ecosystem_enforcement(
    organisation: Option<&Organisation>,
    update: &UpsertOrganisationConfigurationDTO,
    instance_repository: &dyn InstanceRepository,
    wallet_provider_client: &dyn WalletProviderClient,
    verifier_provider_client: &dyn VerifierProviderClient,
) -> Result<(), OrganisationServiceError> {
    let disabled_roles = [
        (InstanceRole::Wallet, update.enforce_ecosystem_as_holder),
        (InstanceRole::Verifier, update.enforce_ecosystem_as_verifier),
    ]
    .into_iter()
    .filter(|(_, enforce)| enforce == &Some(false))
    .map(|(role, _)| role);

    // A not-yet-existing organisation cannot have an instance linked to a provider.
    let Some(organisation) = organisation else {
        return Ok(());
    };

    for role in disabled_roles {
        let enforced = provider_enforces_ecosystems(
            role,
            organisation,
            instance_repository,
            wallet_provider_client,
            verifier_provider_client,
        )
        .await?;
        if enforced {
            return Err(OrganisationServiceError::EcosystemEnforcementMandated);
        }
    }

    Ok(())
}

/// Whether the provider backing the organisation's instance of the given role requires its
/// instances to enforce the ecosystems it advertises.
async fn provider_enforces_ecosystems(
    role: InstanceRole,
    organisation: &Organisation,
    instance_repository: &dyn InstanceRepository,
    wallet_provider_client: &dyn WalletProviderClient,
    verifier_provider_client: &dyn VerifierProviderClient,
) -> Result<bool, OrganisationServiceError> {
    let Some(instance) = instance_repository
        .get_by_role(role, organisation.id)
        .await
        .error_while("getting instance")?
    else {
        return Ok(false);
    };

    Ok(match role {
        InstanceRole::Wallet => {
            wallet_provider_client
                .get_wallet_provider_metadata(instance.into())
                .await
                .error_while("getting wallet provider metadata")?
                .feature_flags
                .ecosystems_enforcement_enabled
        }
        InstanceRole::Verifier => {
            let metadata_url = provider_metadata_url(
                &instance.provider_url,
                &instance.provider_name,
                InstanceRole::Verifier,
            );
            verifier_provider_client
                .get_verifier_provider_metadata(&metadata_url)
                .await
                .error_while("getting verifier provider metadata")?
                .feature_flags
                .ecosystems_enforcement_enabled
        }
    })
}
