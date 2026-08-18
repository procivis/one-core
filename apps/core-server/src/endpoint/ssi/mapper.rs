use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::service::managed_instance::dto;
use one_core::service::verifier_provider::dto::FeatureFlags;

use crate::endpoint::ssi::dto::OpenID4VCIErrorResponseRestDTO;
use crate::endpoint::ssi::verifier_provider::dto::VerifierFeatureFlagsRestDTO;
use crate::endpoint::ssi::wallet_provider::dto::FeatureFlagsRestDTO;

impl From<OpenID4VCIError> for OpenID4VCIErrorResponseRestDTO {
    fn from(value: OpenID4VCIError) -> Self {
        Self {
            error: value.into(),
            error_description: None,
        }
    }
}

#[expect(deprecated)]
impl From<dto::FeatureFlags> for FeatureFlagsRestDTO {
    fn from(value: dto::FeatureFlags) -> Self {
        Self {
            trust_ecosystems_enabled: value.ecosystems_enabled,
            ecosystems_enabled: value.ecosystems_enabled,
            refresh_credential_batch_enabled: value.refresh_credential_batch_enabled,
            document_signing_enabled: value.document_signing_enabled,
            ecosystems_enforcement_enabled: value.ecosystems_enforcement_enabled,
        }
    }
}

#[expect(deprecated)]
impl From<FeatureFlags> for VerifierFeatureFlagsRestDTO {
    fn from(value: FeatureFlags) -> Self {
        Self {
            trust_ecosystems_enabled: value.ecosystems_enabled,
            ecosystems_enabled: value.ecosystems_enabled,
            access_certificate_provisioning_enabled: value.access_certificate_provisioning_enabled,
            ecosystems_enforcement_enabled: value.ecosystems_enforcement_enabled,
        }
    }
}
