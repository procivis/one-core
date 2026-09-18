use shared_types::{IdentifierId, OrganisationId};

use super::dto::UpsertOrganisationConfigurationDTO;
use super::error::OrganisationServiceError;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::instance::InstanceRole;
use crate::model::list_filter::ListFilterCondition;
use crate::model::list_query::ListPagination;
use crate::model::organisation::{Organisation, OrganisationFilterValue, OrganisationListQuery};
use crate::proto::verifier_provider_client::VerifierProviderClient;
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::provider::ProviderExt;
use crate::provider::verifier::provider::VerifierProviderDirectory;
use crate::provider::wallet::provider::WalletProviderDirectory;
use crate::repository::error::DataLayerError;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::instance::service::provider_metadata_url;
use crate::util::key_selection::KeyFilter;

pub(super) async fn validate_provider_issuer(
    organisation: Option<&Organisation>,
    issuer_id: &IdentifierId,
    requested_provider: Option<&String>,
    identifier_repository: &dyn IdentifierRepository,
    provider_type: InstanceRole,
    wallet_provider_directory: &dyn WalletProviderDirectory,
    verifier_provider_directory: &dyn VerifierProviderDirectory,
) -> Result<(), OrganisationServiceError> {
    let Some(organisation) = organisation else {
        return Err(OrganisationServiceError::IdentifierOrganisationMismatch);
    };

    let identifier = identifier_repository
        .get(*issuer_id)
        .await
        .error_while("getting identifier")?;

    if identifier.organisation.id() != organisation.id {
        return Err(OrganisationServiceError::IdentifierOrganisationMismatch);
    };

    identifier
        .select_key(
            KeyFilter::algorithms(vec![KeyAlgorithmType::Ecdsa])
                .error_while("selecting identifier key")?
                .into(),
        )
        .await
        .error_while("selecting identifier key")?;

    let provider_id = requested_provider.or(match provider_type {
        InstanceRole::Wallet => organisation.wallet_provider.as_ref(),
        InstanceRole::Verifier => organisation.verifier_provider.as_ref(),
    });
    if let Some(provider_id) = provider_id {
        let signer_identifier_types = match provider_type {
            InstanceRole::Wallet => {
                wallet_provider_directory
                    .get_provider(provider_id)?
                    .get_capabilities()
                    .signer_identifier_types
            }
            InstanceRole::Verifier => {
                verifier_provider_directory
                    .get_provider(provider_id)?
                    .get_capabilities()
                    .signer_identifier_types
            }
        };

        let identifier_type = identifier.data.r#type().into();
        if !signer_identifier_types.contains(&identifier_type) {
            return Err(OrganisationServiceError::InvalidIdentifierType(
                identifier_type,
            ));
        }
    }

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

#[expect(clippy::too_many_arguments)]
pub(super) async fn validate_provider(
    organisation_id: OrganisationId,
    provider_id: &str,
    provider_type: InstanceRole,
    organisation_repository: &dyn OrganisationRepository,
    wallet_provider_directory: &dyn WalletProviderDirectory,
    verifier_provider_directory: &dyn VerifierProviderDirectory,
    identifier_repository: &dyn IdentifierRepository,
    issuer_kept_from_current_org: Option<&Organisation>,
) -> Result<(), OrganisationServiceError> {
    let (signer_identifier_types, current_provider_org) = match provider_type {
        InstanceRole::Wallet => {
            let provider = wallet_provider_directory.get_provider(provider_id)?;
            provider.ensure_enabled()?;
            (
                provider.get_capabilities().signer_identifier_types,
                organisation_repository
                    .get_organisation_for_wallet_provider(provider_id)
                    .await
                    .error_while("getting organisation")?,
            )
        }
        InstanceRole::Verifier => {
            let provider = verifier_provider_directory.get_provider(provider_id)?;
            provider.ensure_enabled()?;
            (
                provider.get_capabilities().signer_identifier_types,
                organisation_repository
                    .get_organisation_for_verifier_provider(provider_id)
                    .await
                    .error_while("getting organisation")?,
            )
        }
    };

    if let Some(org) = current_provider_org
        && org.id != organisation_id
    {
        return Err(OrganisationServiceError::ProviderAlreadyAssociated(
            org.id,
            provider_type,
        ));
    }

    // check that current issuer matches the provider, when staying unchanged,
    // if the issuer changes the validation is covered in `validate_provider_issuer``
    if let Some(current_org) = issuer_kept_from_current_org {
        let current_identifier_id = match provider_type {
            InstanceRole::Wallet => current_org.wallet_provider_issuer.as_ref(),
            InstanceRole::Verifier => current_org.verifier_provider_issuer.as_ref(),
        };

        if let Some(current_identifier_id) = current_identifier_id {
            let identifier = identifier_repository
                .get(*current_identifier_id)
                .await
                .error_while("getting identifier")?;

            let identifier_type = identifier.data.r#type().into();
            if !signer_identifier_types.contains(&identifier_type) {
                return Err(OrganisationServiceError::InvalidIdentifierType(
                    identifier_type,
                ));
            }
        }
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
