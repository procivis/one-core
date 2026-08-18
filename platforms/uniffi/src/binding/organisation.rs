use one_core::service::managed_instance::dto::DisplayNameDTO;
use one_core::service::organisation::dto::{
    EcosystemInfoDTO, GetOrganisationDetailsResponseDTO, InstanceDetailResponseDTO,
    OrganisationConfigurationDTO, VerifierProviderDetailResponseDTO,
    WalletProviderDetailResponseDTO,
};
use one_dto_mapper::{From, convert_inner};

use super::OneCore;
use super::mapper::OptionalString;
use crate::binding::identifier::GetIdentifierListItemBindingDTO;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, from_id_opt, from_timestamp_opt, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Creates an organization.
    #[uniffi::method]
    pub async fn create_organisation(
        &self,
        request: CreateOrganisationRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .organisation_service
            .create_organisation(request.try_into()?)
            .await?
            .to_string())
    }

    /// Updates or deactivates an organization if it exists, otherwise
    /// creates a new organization using the provided UUID and name.
    #[uniffi::method]
    pub async fn upsert_organisation(
        &self,
        request: UpsertOrganisationRequestBindingDTO,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .organisation_service
            .upsert_organisation(request.try_into()?)
            .await?)
    }

    /// Returns details of an existing organization.
    #[uniffi::method]
    pub async fn get_organisation(
        &self,
        id: String,
    ) -> Result<GetOrganisationDetailsResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let id = into_id(&id)?;
        let response = core.organisation_service.get_organisation(&id).await?;
        Ok(response.into())
    }

    /// Returns the ecosystems offered to this organization by its wallet or
    /// verifier provider, annotated with whether the organization currently
    /// selected each one. Ecosystems this system is not configured for are
    /// omitted.
    /// If there is no wallet or verifier provider, the ecosystems
    /// configured in the local system are returned.
    #[uniffi::method]
    pub async fn get_organisation_ecosystems(
        &self,
        id: String,
    ) -> Result<Vec<EcosystemInfoBindingDTO>, BindingError> {
        let core = self.use_core().await?;
        let id = into_id(&id)?;
        let response = core.organisation_service.get_ecosystems(&id).await?;
        Ok(convert_inner(response))
    }
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CreateOrganisationRequest")]
pub struct CreateOrganisationRequestBindingDTO {
    /// If no UUID is passed, one will be created.
    pub id: Option<String>,
    pub parent_organisation: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "UpsertOrganisationRequest")]
pub struct UpsertOrganisationRequestBindingDTO {
    /// Unique identifier of the organization to create or update.
    pub id: String,
    /// Set to `true` to deactivate the organization.
    pub deactivate: Option<bool>,
    /// Wallet Provider use only.
    pub wallet_provider: Option<OptionalString>,
    /// Wallet Provider use only.
    pub wallet_provider_issuer: Option<OptionalString>,
    /// Verifier Provider use only.
    pub verifier_provider: Option<OptionalString>,
    /// Verifier Provider use only.
    pub verifier_provider_issuer: Option<OptionalString>,
    /// Policy-level configuration for this organization.
    pub configuration: Option<UpsertOrganisationConfigurationBindingDTO>,
    /// The trust collections this organization's wallet subscribes to,
    /// selected from those made available by the Wallet Provider. Omit to
    /// leave the current selection unchanged.
    pub trust_collections: Option<Vec<String>>,
    /// The parent organization this organization inherits policy-level
    /// configuration from, if any.
    pub parent_organisation: Option<OptionalString>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "UpsertOrganisationConfiguration")]
pub struct UpsertOrganisationConfigurationBindingDTO {
    pub selected_ecosystems: Option<Vec<String>>,
    /// When true, the issuer will only issue credentials to wallet units of one of
    /// the selected ecosystems.
    pub enforce_ecosystem_as_issuer: Option<bool>,
    /// When true, the wallet only accepts issuance and presentation requests
    /// from members of one of the selected ecosystems.
    pub enforce_ecosystem_as_holder: Option<bool>,
    /// When true, the verifier will only accept presentations of credentials
    /// issued by issuers of the selected ecosystems. Ecosystems must be consistent
    /// across presentations belonging to the same proof request.
    pub enforce_ecosystem_as_verifier: Option<bool>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "OrganisationDetail")]
#[from(GetOrganisationDetailsResponseDTO)]
pub struct GetOrganisationDetailsResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn = "from_timestamp_opt")]
    pub deactivated_at: Option<String>,
    /// The parent organization this organization inherits policy-level
    /// configuration from, if any.
    #[from(with_fn = "from_id_opt")]
    pub parent_organisation: Option<String>,
    /// Policy-level configuration for this organization.
    #[from(with_fn = convert_inner)]
    pub configuration: Option<OrganisationConfigurationBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub wallet_provider: Option<WalletProviderDetailResponseBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub verifier_provider: Option<VerifierProviderDetailResponseBindingDTO>,
    /// Wallet registration details for this organization's Business
    /// Wallet.
    #[from(with_fn = convert_inner)]
    pub wallet_instance: Option<InstanceDetailResponseBindingDTO>,
    /// Verifier registration details for this organization's Business
    /// Verifier.
    #[from(with_fn = convert_inner)]
    pub verifier_instance: Option<InstanceDetailResponseBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "InstanceDetail")]
#[from(InstanceDetailResponseDTO)]
pub(crate) struct InstanceDetailResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub provider_url: String,
    pub provider_name: String,
    pub authentication_key_type: String,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "WalletProviderDetail")]
#[from(WalletProviderDetailResponseDTO)]
pub(crate) struct WalletProviderDetailResponseBindingDTO {
    /// Wallet Provider configuration used by this organization to provide
    /// wallets.
    pub provider_name: Option<String>,
    /// Identifier used by this organization to provide wallets.
    #[from(with_fn = convert_inner)]
    pub issuer: Option<GetIdentifierListItemBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "VerifierProviderDetail")]
#[from(VerifierProviderDetailResponseDTO)]
pub(crate) struct VerifierProviderDetailResponseBindingDTO {
    /// Verifier Provider configuration used by this organization.
    pub provider_name: Option<String>,
    /// Identifier used by this organization to authenticate to the
    /// verifier provider.
    #[from(with_fn = convert_inner)]
    pub issuer: Option<GetIdentifierListItemBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "OrganisationConfiguration")]
#[from(OrganisationConfigurationDTO)]
pub(crate) struct OrganisationConfigurationBindingDTO {
    #[from(with_fn = convert_inner)]
    pub selected_ecosystems: Vec<String>,
    /// When true, the issuer will only issue credentials to holders of one of
    /// the selected ecosystems.
    pub enforce_ecosystem_as_issuer: bool,
    /// When true, the wallet only accepts issuance and presentation requests
    /// from members of one of the selected ecosystems.
    pub enforce_ecosystem_as_holder: bool,
    /// When true, the verifier will only validate presentations of credentials
    /// issued within one of the selected ecosystems.
    pub enforce_ecosystem_as_verifier: bool,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "EcosystemInfo")]
#[from(EcosystemInfoDTO)]
pub struct EcosystemInfoBindingDTO {
    /// When true, the organization has selected this ecosystem.
    pub selected: bool,
    /// Ecosystem provider name.
    #[from(with_fn_ref = "ToString::to_string")]
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub display_name: Vec<DisplayNameBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub description: Vec<DisplayNameBindingDTO>,
    pub logo: String,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(DisplayNameDTO)]
#[uniffi(name = "DisplayName")]
pub struct DisplayNameBindingDTO {
    pub lang: String,
    pub value: String,
}
