use one_core::provider::issuance_protocol::error::OpenID4VCIError;
use one_core::service::managed_instance::dto;
use one_core::service::verifier_provider::dto::FeatureFlags;

use crate::endpoint::ssi::dto::{OpenID4VCIErrorResponseRestDTO, OpenID4VCIErrorRestEnum};
use crate::endpoint::ssi::verifier_provider::dto::VerifierFeatureFlagsRestDTO;
use crate::endpoint::ssi::wallet_provider::dto::FeatureFlagsRestDTO;

impl From<OpenID4VCIError> for OpenID4VCIErrorResponseRestDTO {
    fn from(value: OpenID4VCIError) -> Self {
        let error_description = match &value {
            OpenID4VCIError::InvalidGrant { description }
            | OpenID4VCIError::InvalidRequest { description } => description.to_owned(),
            _ => None,
        };
        Self {
            error: value.into(),
            error_description,
        }
    }
}

// the description goes into `error_description`, the `error` itself must stay a plain code
impl From<OpenID4VCIError> for OpenID4VCIErrorRestEnum {
    fn from(value: OpenID4VCIError) -> Self {
        match value {
            OpenID4VCIError::UnsupportedGrantType => Self::UnsupportedGrantType,
            OpenID4VCIError::InvalidGrant { .. } => Self::InvalidGrant,
            OpenID4VCIError::InvalidClient => Self::InvalidClient,
            OpenID4VCIError::InvalidRequest { .. } => Self::InvalidRequest,
            OpenID4VCIError::InvalidToken => Self::InvalidToken,
            OpenID4VCIError::InvalidNonce => Self::InvalidNonce,
            OpenID4VCIError::InvalidOrMissingProof => Self::InvalidOrMissingProof,
            OpenID4VCIError::UnsupportedCredentialFormat => Self::UnsupportedCredentialFormat,
            OpenID4VCIError::UnsupportedCredentialType => Self::UnsupportedCredentialType,
            OpenID4VCIError::CredentialRequestDenied => Self::CredentialRequestDenied,
            OpenID4VCIError::InvalidNotificationId => Self::InvalidNotificationId,
            OpenID4VCIError::InvalidNotificationRequest => Self::InvalidNotificationRequest,
            OpenID4VCIError::InvalidEncryptionParameters => Self::InvalidEncryptionParameters,
            OpenID4VCIError::UseAttestationChallenge => Self::UseAttestationChallenge,
            OpenID4VCIError::UseFreshAttestation => Self::UseFreshAttestation,
            OpenID4VCIError::InvalidDpopProof => Self::InvalidDpopProof,
            OpenID4VCIError::UseDpopNonce => Self::UseDpopNonce,
        }
    }
}

impl OpenID4VCIErrorResponseRestDTO {
    pub(crate) fn with_description(error: OpenID4VCIError, description: String) -> Self {
        Self {
            error: error.into(),
            error_description: Some(description),
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
            dc_api_integration_enabled: value.dc_api_integration_enabled,
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
