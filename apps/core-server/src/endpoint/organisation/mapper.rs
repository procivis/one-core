use one_core::service::error::ValidationError;
use one_core::service::organisation::dto::{
    OrganisationConfigurationDTO, UpsertOrganisationConfigurationDTO, UpsertOrganisationRequestDTO,
};
use shared_types::{IdentifierId, OrganisationId};

use super::dto::{
    CreateOrganisationResponseRestDTO, OrganisationConfigurationRestDTO,
    UpsertOrganisationConfigurationRestDTO, UpsertOrganisationRequestRestDTO,
    UpsertProviderRequestRestDTO,
};

impl From<OrganisationId> for CreateOrganisationResponseRestDTO {
    fn from(value: OrganisationId) -> Self {
        Self { id: value }
    }
}

#[expect(deprecated)]
impl From<OrganisationConfigurationDTO> for OrganisationConfigurationRestDTO {
    fn from(value: OrganisationConfigurationDTO) -> Self {
        Self {
            selected_ecosystems: value.selected_ecosystems,
            trusted_issuer_required: value.enforce_ecosystem_as_verifier,
            trusted_rp_required: value.enforce_ecosystem_as_holder,
            trusted_wallet_provider_required: value.enforce_ecosystem_as_issuer,
            enforce_ecosystem_as_issuer: value.enforce_ecosystem_as_issuer,
            enforce_ecosystem_as_holder: value.enforce_ecosystem_as_holder,
            enforce_ecosystem_as_verifier: value.enforce_ecosystem_as_verifier,
        }
    }
}

/// Unpacks a nested, double-optional provider update into the flat double-optional
/// name/issuer pair the service layer expects: omitted key -> no change to either
/// sub-field; `null` -> clear both; an object -> set name/issuer independently (each
/// `None` inside the object clears just that one).
fn unpack_provider(
    provider: Option<Option<UpsertProviderRequestRestDTO>>,
) -> (Option<Option<String>>, Option<Option<IdentifierId>>) {
    match provider {
        None => (None, None),
        Some(None) => (Some(None), Some(None)),
        Some(Some(provider)) => (Some(provider.name), Some(provider.issuer)),
    }
}

/// Maps the organization configuration update, accepting either the deprecated
/// `trusted*` flags or their `enforceEcosystemAs*` replacements. Mixing the two
/// generations in a single request is rejected, as the intent would be ambiguous.
fn upsert_configuration_from_request(
    request: UpsertOrganisationConfigurationRestDTO,
) -> Result<UpsertOrganisationConfigurationDTO, ValidationError> {
    #[expect(deprecated)]
    let UpsertOrganisationConfigurationRestDTO {
        selected_ecosystems,
        trusted_issuer_required,
        trusted_rp_required,
        trusted_wallet_provider_required,
        enforce_ecosystem_as_issuer,
        enforce_ecosystem_as_holder,
        enforce_ecosystem_as_verifier,
    } = request;

    let deprecated_used = [
        trusted_issuer_required.map(|_| "trustedIssuerRequired"),
        trusted_rp_required.map(|_| "trustedRpRequired"),
        trusted_wallet_provider_required.map(|_| "trustedWalletProviderRequired"),
    ]
    .into_iter()
    .flatten()
    .next();
    let replacement_used = [
        enforce_ecosystem_as_issuer.map(|_| "enforceEcosystemAsIssuer"),
        enforce_ecosystem_as_holder.map(|_| "enforceEcosystemAsHolder"),
        enforce_ecosystem_as_verifier.map(|_| "enforceEcosystemAsVerifier"),
    ]
    .into_iter()
    .flatten()
    .next();

    if let (Some(deprecated), Some(replacement)) = (deprecated_used, replacement_used) {
        return Err(ValidationError::MixedDeprecatedAndReplacementFields {
            deprecated: deprecated.to_string(),
            replacement: replacement.to_string(),
        });
    }

    Ok(UpsertOrganisationConfigurationDTO {
        selected_ecosystems: selected_ecosystems
            .map(|ecosystems| ecosystems.into_iter().map(Into::into).collect()),
        enforce_ecosystem_as_issuer: enforce_ecosystem_as_issuer
            .or(trusted_wallet_provider_required),
        enforce_ecosystem_as_holder: enforce_ecosystem_as_holder.or(trusted_rp_required),
        enforce_ecosystem_as_verifier: enforce_ecosystem_as_verifier.or(trusted_issuer_required),
    })
}

pub(crate) fn upsert_request_from_request(
    id: OrganisationId,
    request: UpsertOrganisationRequestRestDTO,
) -> Result<UpsertOrganisationRequestDTO, ValidationError> {
    let (wallet_provider, wallet_provider_issuer) = unpack_provider(request.wallet_provider);
    let (verifier_provider, verifier_provider_issuer) = unpack_provider(request.verifier_provider);

    Ok(UpsertOrganisationRequestDTO {
        id,
        deactivate: request.deactivate,
        wallet_provider,
        wallet_provider_issuer,
        verifier_provider,
        verifier_provider_issuer,
        configuration: request
            .configuration
            .map(upsert_configuration_from_request)
            .transpose()?,
        trust_collections: request.trust_collections,
        parent_organisation: request.parent_organisation,
    })
}
