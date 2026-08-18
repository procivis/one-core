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

pub(super) async fn validate_wallet_provider_issuer(
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

/// The `enforceEcosystemAs*` flags may only be turned off while none of the providers
/// backing the organisation's instances mandates ecosystem enforcement.
pub(super) async fn validate_ecosystem_enforcement(
    organisation: Option<&Organisation>,
    update: &UpsertOrganisationConfigurationDTO,
    instance_repository: &dyn InstanceRepository,
    wallet_provider_client: &dyn WalletProviderClient,
    verifier_provider_client: &dyn VerifierProviderClient,
) -> Result<(), OrganisationServiceError> {
    let disables_enforcement = [
        update.enforce_ecosystem_as_issuer,
        update.enforce_ecosystem_as_holder,
        update.enforce_ecosystem_as_verifier,
    ]
    .contains(&Some(false));
    if !disables_enforcement {
        return Ok(());
    }

    // A not-yet-existing organisation cannot have an instance linked to a provider.
    let Some(organisation) = organisation else {
        return Ok(());
    };

    let enforced = provider_enforces_ecosystems(
        organisation,
        instance_repository,
        wallet_provider_client,
        verifier_provider_client,
    )
    .await?;
    if enforced {
        return Err(OrganisationServiceError::EcosystemEnforcementMandated);
    }

    Ok(())
}

/// Whether the provider backing either of the organisation's instances requires its
/// instances to enforce the ecosystems it advertises.
async fn provider_enforces_ecosystems(
    organisation: &Organisation,
    instance_repository: &dyn InstanceRepository,
    wallet_provider_client: &dyn WalletProviderClient,
    verifier_provider_client: &dyn VerifierProviderClient,
) -> Result<bool, OrganisationServiceError> {
    let wallet_instance = instance_repository
        .get_by_role(InstanceRole::Wallet, organisation.id)
        .await
        .error_while("getting wallet instance")?;
    if let Some(wallet_instance) = wallet_instance {
        let metadata = wallet_provider_client
            .get_wallet_provider_metadata(wallet_instance.into())
            .await
            .error_while("getting wallet provider metadata")?;
        if metadata.feature_flags.ecosystems_enforcement_enabled {
            return Ok(true);
        }
    }

    let verifier_instance = instance_repository
        .get_by_role(InstanceRole::Verifier, organisation.id)
        .await
        .error_while("getting verifier instance")?;
    if let Some(verifier_instance) = verifier_instance {
        let metadata_url = provider_metadata_url(
            &verifier_instance.provider_url,
            &verifier_instance.provider_name,
            InstanceRole::Verifier,
        );
        let metadata = verifier_provider_client
            .get_verifier_provider_metadata(&metadata_url)
            .await
            .error_while("getting verifier provider metadata")?;
        if metadata.feature_flags.ecosystems_enforcement_enabled {
            return Ok(true);
        }
    }

    Ok(false)
}
