use std::sync::Arc;

use uuid::Uuid;

use crate::model::identifier::Identifier;
use crate::model::instance::Instance;
use crate::model::list_filter::{ComparisonType, ListFilterCondition, ValueComparison};
use crate::model::organisation::{
    Organisation, OrganisationConfiguration, OrganisationFilterValue, UpdateOrganisationRequest,
};
use crate::model::relation::Related;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::managed_instance::dto::EcosystemMetadataDTO;
use crate::service::organisation::dto::{
    CreateOrganisationRequestDTO, EcosystemInfoDTO, GetOrganisationDetailsResponseDTO,
    GetOrganisationListItemResponseDTO, InstanceDetailResponseDTO, OrganisationFilterParamsDTO,
    SetOrganisationConfigurationDTO, UpdateOrganisationRequestDTO, VerifierInstanceFeatureFlagsDTO,
    VerifierProviderDetailResponseDTO, WalletInstanceFeatureFlagsDTO,
    WalletProviderDetailResponseDTO,
};
use crate::service::organisation::error::OrganisationServiceError;

pub(super) fn request_to_model(
    request: CreateOrganisationRequestDTO,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Organisation {
    let now = crate::clock::now_utc();
    let id = request.id.unwrap_or(Uuid::new_v4().into());
    Organisation {
        id,
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        wallet_provider: None,
        wallet_provider_issuer: None,
        parent_organisation: request.parent_organisation.map(|organisation_id| {
            Related::new(organisation_id, organisation_repository.to_owned())
        }),
        verifier_provider: None,
        verifier_provider_issuer: None,
        configuration: request
            .configuration
            .map(|configuration| apply_configuration_update(configuration, None))
            .unwrap_or_default(),
    }
}

impl From<UpdateOrganisationRequestDTO> for UpdateOrganisationRequest {
    fn from(request: UpdateOrganisationRequestDTO) -> Self {
        Self {
            parent_organisation: request.parent_organisation,
            deactivate: request.deactivate,
            wallet_provider: request.wallet_provider,
            wallet_provider_issuer: request.wallet_provider_issuer,
            verifier_provider: request.verifier_provider,
            verifier_provider_issuer: request.verifier_provider_issuer,
            // Configuration is merged with the existing value (partial update) in the
            // service, which has access to the organisation's current state.
            configuration: None,
        }
    }
}

pub(super) fn detail_from_model(
    organisation: Organisation,
    ecosystems: Vec<EcosystemInfoDTO>,
    wallet_provider_issuer: Option<Identifier>,
    verifier_provider_issuer: Option<Identifier>,
    wallet_instance: Option<InstanceDetailResponseDTO<WalletInstanceFeatureFlagsDTO>>,
    verifier_instance: Option<InstanceDetailResponseDTO<VerifierInstanceFeatureFlagsDTO>>,
) -> GetOrganisationDetailsResponseDTO {
    GetOrganisationDetailsResponseDTO {
        id: organisation.id,
        created_date: organisation.created_date,
        last_modified: organisation.last_modified,
        deactivated_at: organisation.deactivated_at,
        configuration: Some(organisation.configuration.into()),
        ecosystems,
        wallet_provider: map_to_wallet_provider(
            organisation.wallet_provider,
            wallet_provider_issuer,
        ),
        verifier_provider: map_to_verifier_provider(
            organisation.verifier_provider,
            verifier_provider_issuer,
        ),
        parent_organisation: organisation
            .parent_organisation
            .map(|parent_organisation| parent_organisation.id()),
        wallet_instance,
        verifier_instance,
    }
}

pub(super) async fn instance_detail_from_model<T>(
    instance: Instance,
    feature_flags: impl Into<T>,
) -> Result<Option<InstanceDetailResponseDTO<T>>, OrganisationServiceError> {
    let Some(authentication_key) = instance.authentication_key else {
        return Ok(None);
    };
    Ok(Some(InstanceDetailResponseDTO {
        id: instance.id,
        provider_url: instance.provider_url,
        provider_name: instance.provider_name,
        authentication_key_type: authentication_key.as_ref().await?.key_type.to_owned(),
        feature_flags: feature_flags.into(),
    }))
}

pub(super) fn list_item_from_model(
    organisation: Organisation,
    wallet_provider_issuer: Option<Identifier>,
    verifier_provider_issuer: Option<Identifier>,
) -> GetOrganisationListItemResponseDTO {
    GetOrganisationListItemResponseDTO {
        id: organisation.id,
        created_date: organisation.created_date,
        last_modified: organisation.last_modified,
        deactivated_at: organisation.deactivated_at,
        wallet_provider: map_to_wallet_provider(
            organisation.wallet_provider,
            wallet_provider_issuer,
        ),
        verifier_provider: map_to_verifier_provider(
            organisation.verifier_provider,
            verifier_provider_issuer,
        ),
        parent_organisation: organisation
            .parent_organisation
            .map(|parent_organisation| parent_organisation.id()),
    }
}

pub(super) fn apply_configuration_update(
    update: SetOrganisationConfigurationDTO,
    current_settings: Option<OrganisationConfiguration>,
) -> OrganisationConfiguration {
    let existing_configuration = current_settings.unwrap_or_default();
    OrganisationConfiguration {
        selected_ecosystems: update
            .selected_ecosystems
            .unwrap_or(existing_configuration.selected_ecosystems),
        enforce_ecosystem_as_issuer: update
            .enforce_ecosystem_as_issuer
            .unwrap_or(existing_configuration.enforce_ecosystem_as_issuer),
        enforce_ecosystem_as_holder: update
            .enforce_ecosystem_as_holder
            .unwrap_or(existing_configuration.enforce_ecosystem_as_holder),
        enforce_ecosystem_as_verifier: update
            .enforce_ecosystem_as_verifier
            .unwrap_or(existing_configuration.enforce_ecosystem_as_verifier),
    }
}

fn map_to_wallet_provider(
    provider_name: Option<String>,
    wallet_provider_issuer: Option<Identifier>,
) -> Option<WalletProviderDetailResponseDTO> {
    if provider_name.is_some() || wallet_provider_issuer.is_some() {
        Some(WalletProviderDetailResponseDTO {
            provider_name,
            issuer: wallet_provider_issuer.map(Into::into),
        })
    } else {
        None
    }
}

fn map_to_verifier_provider(
    provider_name: Option<String>,
    verifier_provider_issuer: Option<Identifier>,
) -> Option<VerifierProviderDetailResponseDTO> {
    if provider_name.is_some() || verifier_provider_issuer.is_some() {
        Some(VerifierProviderDetailResponseDTO {
            provider_name,
            issuer: verifier_provider_issuer.map(Into::into),
        })
    } else {
        None
    }
}

impl From<OrganisationFilterParamsDTO> for ListFilterCondition<OrganisationFilterValue> {
    fn from(filter: OrganisationFilterParamsDTO) -> Self {
        let created_date_after = filter.created_date_after.map(|date| {
            OrganisationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = filter.created_date_before.map(|date| {
            OrganisationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = filter.last_modified_after.map(|date| {
            OrganisationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = filter.last_modified_before.map(|date| {
            OrganisationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let has_parent_organisation = filter
            .has_parent_organisation
            .map(OrganisationFilterValue::HasParentOrganisation);
        let parent_organisations = filter
            .parent_organisations
            .map(OrganisationFilterValue::ParentOrganisations);

        ListFilterCondition::<OrganisationFilterValue>::default()
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & has_parent_organisation
            & parent_organisations
    }
}

/// Folds ecosystems advertised by more than one provider into a single entry: an
/// organisation with both a wallet and a verifier provider is offered the same ecosystem
/// by each of them, and it participates in it as a whole rather than per provider.
/// Display information is taken from the first observed entry.
pub(super) fn merge_ecosystems(ecosystems: Vec<EcosystemMetadataDTO>) -> Vec<EcosystemMetadataDTO> {
    let mut merged: Vec<EcosystemMetadataDTO> = vec![];

    for ecosystem in ecosystems {
        let Some(existing) = merged
            .iter_mut()
            .find(|existing| existing.name == ecosystem.name)
        else {
            merged.push(ecosystem);
            continue;
        };
        for collection in ecosystem.trust_collections {
            if !existing
                .trust_collections
                .iter()
                .any(|existing| existing.id == collection.id)
            {
                existing.trust_collections.push(collection);
            }
        }
        extend_unique(
            &mut existing.credential_schemas,
            ecosystem.credential_schemas,
        );
        extend_unique(&mut existing.proof_schemas, ecosystem.proof_schemas);
    }
    merged
}

fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}
