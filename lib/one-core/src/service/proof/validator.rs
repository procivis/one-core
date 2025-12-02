use std::collections::HashSet;
use std::str::FromStr;

use url::Url;

use super::dto::CreateProofRequestDTO;
use crate::config::core_config::{
    CoreConfig, IdentifierType, VerificationEngagement, VerificationEngagementConfig,
    VerificationProtocolConfig, VerificationProtocolType,
};
use crate::model::did::{Did, KeyFilter, KeyRole};
use crate::model::key::Key;
use crate::model::proof::ProofStateEnum::Requested;
use crate::model::proof::{Proof, ProofRole};
use crate::model::proof_schema::ProofSchema;
use crate::proto::session_provider::SessionProvider;
use crate::provider::credential_formatter::model::Features;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::verification_protocol::VerificationProtocol;
use crate::provider::verification_protocol::dto::PresentationDefinitionVersion;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4Vp20Params;
use crate::provider::verification_protocol::openid4vp::draft25::model::OpenID4Vp25Params;
use crate::service::error::{
    BusinessLogicError, MissingProviderError, ServiceError, ValidationError,
};
use crate::validator::{
    throw_if_endpoint_version_incompatible, throw_if_org_relation_not_matching_session,
    throw_if_proof_state_not_eq,
};

pub(super) fn throw_if_proof_not_in_session_org(
    proof: &Proof,
    session_provider: &dyn SessionProvider,
) -> Result<(), ServiceError> {
    let organisation = if let Some(schema) = proof.schema.as_ref() {
        // verifier case
        schema.organisation.as_ref()
    } else if let Some(interaction) = proof.interaction.as_ref() {
        // holder case
        interaction.organisation.as_ref()
    } else {
        return Err(ServiceError::MappingError(
            "proof organisation could not be determined".to_string(),
        ));
    };
    throw_if_org_relation_not_matching_session(organisation, session_provider)
}

pub(super) fn validate_format_and_exchange_protocol_compatibility(
    exchange: &str,
    config: &CoreConfig,
    proof_schema: &ProofSchema,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<(), ServiceError> {
    let input_schemas = proof_schema
        .input_schemas
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "input_schemas is None".to_string(),
        ))?;

    let exchange_type = config.verification_protocol.get_fields(exchange)?.r#type;

    input_schemas.iter().try_for_each(|input_schema| {
        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))?;

        let formatter = formatter_provider
            .get_credential_formatter(&credential_schema.format.to_string())
            .ok_or(MissingProviderError::Formatter(
                credential_schema.format.to_string(),
            ))?;

        let capabilities = formatter.get_capabilities();
        if !capabilities
            .proof_exchange_protocols
            .contains(&exchange_type)
        {
            return Err(ServiceError::BusinessLogic(
                BusinessLogicError::IncompatibleProofExchangeProtocol,
            ));
        }

        if !capabilities
            .verification_identifier_types
            .contains(&IdentifierType::Did)
        {
            return Err(ServiceError::BusinessLogic(
                BusinessLogicError::IncompatibleProofVerificationIdentifier,
            ));
        }

        Ok(())
    })?;

    Ok(())
}

pub(super) fn validate_did_and_format_compatibility(
    proof_schema: &ProofSchema,
    verifier_did: &Did,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<(), ServiceError> {
    let input_schemas = proof_schema
        .input_schemas
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "input_schemas is None".to_string(),
        ))?;

    let key_agreement_key =
        verifier_did.find_first_matching_key(&KeyFilter::role_filter(KeyRole::KeyAgreement))?;

    input_schemas.iter().try_for_each(|input_schema| {
        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))?;

        let formatter = formatter_provider
            .get_credential_formatter(&credential_schema.format.to_string())
            .ok_or(MissingProviderError::Formatter(
                credential_schema.format.to_string(),
            ))?;

        let capabilities = formatter.get_capabilities();
        if capabilities
            .features
            .contains(&Features::RequiresPresentationEncryption)
            && key_agreement_key.is_none()
        {
            return Err(ServiceError::Validation(ValidationError::NoKeyWithRole(
                KeyRole::KeyAgreement,
            )));
        }
        Ok(())
    })
}

pub(super) fn validate_scan_to_verify_compatibility(
    request: &CreateProofRequestDTO,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    let exchange_type = config
        .verification_protocol
        .get_fields(&request.protocol)?
        .r#type;
    match exchange_type {
        VerificationProtocolType::ScanToVerify => {
            if request.redirect_uri.is_some() || request.scan_to_verify.is_none() {
                return Err(ServiceError::Validation(
                    ValidationError::InvalidScanToVerifyParameters,
                ));
            }
        }
        _ => {
            if request.scan_to_verify.is_some() {
                return Err(ServiceError::Validation(
                    ValidationError::InvalidScanToVerifyParameters,
                ));
            }
        }
    };

    Ok(())
}

pub(super) fn validate_mdl_exchange(
    exchange: &str,
    engagement: Option<&str>,
    redirect_uri: Option<&str>,
    config: &VerificationProtocolConfig,
) -> Result<(), ServiceError> {
    let exchange_type = config.get_fields(exchange)?.r#type;
    match exchange_type {
        VerificationProtocolType::IsoMdl if redirect_uri.is_some() => Err(
            ServiceError::Validation(ValidationError::InvalidMdlParameters),
        ),
        VerificationProtocolType::IsoMdl if engagement.is_some() => Ok(()),
        _ if engagement.is_some() => Err(ServiceError::Validation(
            ValidationError::InvalidMdlParameters,
        )),
        _ => Ok(()),
    }
}

pub(super) fn validate_redirect_uri(
    exchange: &str,
    redirect_uri: Option<&str>,
    config: &VerificationProtocolConfig,
) -> Result<(), ServiceError> {
    let fields = config.get_fields(exchange)?;

    let redirect_uri_config = match fields.r#type {
        VerificationProtocolType::OpenId4VpDraft20 => {
            let exchange_params: OpenID4Vp20Params = config.get(exchange)?;
            Some(exchange_params.redirect_uri)
        }
        VerificationProtocolType::OpenId4VpDraft25 => {
            let exchange_params: OpenID4Vp25Params = config.get(exchange)?;
            Some(exchange_params.redirect_uri)
        }
        VerificationProtocolType::OpenId4VpFinal1_0 => {
            let exchange_params: crate::provider::verification_protocol::openid4vp::final1_0::model::Params = config.get(exchange)?;
            Some(exchange_params.redirect_uri)
        }
        _ => None,
    };

    if let Some(redirect_uri) = redirect_uri {
        let Some(config) = redirect_uri_config else {
            return Err(ValidationError::InvalidRedirectUri.into());
        };

        if !config.enabled {
            return Err(ValidationError::InvalidRedirectUri.into());
        }
        let url = Url::parse(redirect_uri).map_err(|_| ValidationError::InvalidRedirectUri)?;

        if !config.allowed_schemes.contains(&url.scheme().to_string()) {
            return Err(ValidationError::InvalidRedirectUri.into());
        }
    }
    Ok(())
}

pub(super) fn validate_verification_key_storage_compatibility(
    proof_schema: &ProofSchema,
    verifier_key: &Key,
    formatter_provider: &dyn CredentialFormatterProvider,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    let input_schemas = proof_schema
        .input_schemas
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "input_schemas is None".to_string(),
        ))?;

    let storage_type = config
        .key_storage
        .get_fields(&verifier_key.storage_type)?
        .r#type;

    input_schemas.iter().try_for_each(|input_schema| {
        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))?;

        let formatter = formatter_provider
            .get_credential_formatter(&credential_schema.format.to_string())
            .ok_or(MissingProviderError::Formatter(
                credential_schema.format.to_string(),
            ))?;

        let capabilities = formatter.get_capabilities();
        if !capabilities
            .verification_key_storages
            .contains(&storage_type)
        {
            return Err(ServiceError::BusinessLogic(
                BusinessLogicError::IncompatibleProofVerificationKeyStorage,
            ));
        }

        Ok(())
    })?;

    Ok(())
}

pub(super) fn validate_verifier_engagement(
    iso_mdl_engagement: Option<&str>,
    engagement: Option<&str>,
    config: &VerificationEngagementConfig,
) -> Result<(), ServiceError> {
    match (iso_mdl_engagement, engagement) {
        (None, None) => Ok(()),
        (Some(_), Some(engagement)) => {
            let enabled = VerificationEngagement::from_str(engagement)
                .ok()
                .and_then(|e| config.get(&e))
                .map(|e| e.enabled())
                .unwrap_or(false);

            if enabled {
                Ok(())
            } else {
                Err(
                    ValidationError::MissingVerificationEngagementConfig(engagement.to_string())
                        .into(),
                )
            }
        }
        (Some(_), None) => Err(ValidationError::MissingEngagementForISOmDLFlow.into()),
        (None, Some(_)) => Err(ValidationError::EngagementProvidedForNonISOmDLFlow.into()),
    }
}

pub(super) fn validate_holder_engagements(
    engagements: &[impl AsRef<str>],
    config: &VerificationEngagementConfig,
) -> Result<HashSet<VerificationEngagement>, ValidationError> {
    if engagements.is_empty() {
        return Err(ValidationError::MissingVerificationEngagementConfig(
            "-".to_string(),
        ));
    }

    let mut result = HashSet::new();
    for engagement in engagements {
        let engagement_type = VerificationEngagement::from_str(engagement.as_ref())
            .map_err(|e| ValidationError::MissingVerificationEngagementConfig(e.to_string()))?;
        let enabled = config
            .get(&engagement_type)
            .map(|e| e.enabled())
            .unwrap_or(false);

        if !enabled {
            return Err(ValidationError::MissingVerificationEngagementConfig(
                engagement.as_ref().to_string(),
            ));
        }

        result.insert(engagement_type);
    }
    Ok(result)
}

pub(super) fn validate_proof_for_proof_definition(
    proof: &Proof,
    session_provider: &dyn SessionProvider,
    verification_protocol: &dyn VerificationProtocol,
    endpoint_version: &PresentationDefinitionVersion,
) -> Result<(), ServiceError> {
    throw_if_proof_not_in_session_org(proof, session_provider)?;

    if proof.role != ProofRole::Holder {
        return Err(BusinessLogicError::InvalidProofRole { role: proof.role }.into());
    }

    throw_if_proof_state_not_eq(proof, Requested)?;
    throw_if_endpoint_version_incompatible(verification_protocol, endpoint_version)
}

#[cfg(test)]
mod tests {
    use assert2::let_assert;

    use super::*;
    use crate::config::core_config::{ConfigEntryDisplay, VerificationEngagementFields};
    use crate::service::test_utilities::generic_config;

    #[test]
    fn test_validate_engagement_success() {
        // given
        let iso_mdl_engagement = Some("iso_mdl");
        let engagement = Some("QR_CODE");
        let mut config = VerificationEngagementConfig::default();
        config.insert(
            VerificationEngagement::QrCode,
            VerificationEngagementFields {
                display: ConfigEntryDisplay::TranslationId("test".to_string()),
                order: Some(1),
                enabled: Some(true),
            },
        );

        // when
        let result = validate_verifier_engagement(iso_mdl_engagement, engagement, &config);

        // then
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_engagement_fails_missing_iso_mdl_engagement() {
        // given
        let iso_mdl_engagement = None;
        let engagement = Some("QR_CODE");
        let config = VerificationEngagementConfig::default();

        // when
        let result = validate_verifier_engagement(iso_mdl_engagement, engagement, &config);

        // then
        let_assert!(Err(e) = result);
        let_assert!(
            ServiceError::Validation(ValidationError::EngagementProvidedForNonISOmDLFlow) = e
        );
    }

    #[test]
    fn test_validate_engagement_fails_when_iso_mdl_is_some_and_engagement_is_missing() {
        // given
        let iso_mdl_engagement = Some("iso_mdl");
        let engagement = None;
        let mut config = VerificationEngagementConfig::default();
        config.insert(
            VerificationEngagement::QrCode,
            VerificationEngagementFields {
                display: ConfigEntryDisplay::TranslationId("test".to_string()),
                order: Some(1),
                enabled: Some(true),
            },
        );

        // when
        let result = validate_verifier_engagement(iso_mdl_engagement, engagement, &config);

        // then
        let_assert!(Err(e) = result);
        let_assert!(ServiceError::Validation(ValidationError::MissingEngagementForISOmDLFlow) = e);
    }

    #[test]
    fn test_validate_engagement_fails_when_engagement_config_is_missing() {
        // given
        let iso_mdl_engagement = Some("iso_mdl");
        let engagement = Some("QR_CODE");
        let config = VerificationEngagementConfig::default();

        // when
        let result = validate_verifier_engagement(iso_mdl_engagement, engagement, &config);

        // then
        let_assert!(Err(e) = result);
        let_assert!(
            ServiceError::Validation(ValidationError::MissingVerificationEngagementConfig(m)) = e
        );
        assert!(m == "QR_CODE");
    }

    #[test]
    fn test_validate_engagement_fails_when_engagement_config_is_disabled() {
        // given
        let iso_mdl_engagement = Some("iso_mdl");
        let engagement = Some("QR_CODE");
        let mut config = VerificationEngagementConfig::default();
        config.insert(
            VerificationEngagement::QrCode,
            VerificationEngagementFields {
                display: ConfigEntryDisplay::TranslationId("test".to_string()),
                order: Some(1),
                enabled: Some(false),
            },
        );

        // when
        let result = validate_verifier_engagement(iso_mdl_engagement, engagement, &config);

        // then
        let_assert!(Err(e) = result);
        let_assert!(
            ServiceError::Validation(ValidationError::MissingVerificationEngagementConfig(m)) = e
        );
        assert!(m == "QR_CODE");
    }

    #[test]
    fn test_validate_mdl_exchange() {
        let config = generic_config().core.verification_protocol;
        let engagement = Some("engagement");
        let uri = Some("uri");

        assert!(validate_mdl_exchange("ISO_MDL", engagement, None, &config).is_ok());
        assert!(validate_mdl_exchange("ISO_MDL", engagement, uri, &config).is_err());
        assert!(validate_mdl_exchange("ISO_MDL", None, uri, &config).is_err());

        assert!(validate_mdl_exchange("OPENID4VP_DRAFT20", None, uri, &config).is_ok());
        assert!(validate_mdl_exchange("OPENID4VP_DRAFT20", engagement, uri, &config).is_err());
        assert!(validate_mdl_exchange("OPENID4VP_DRAFT20", engagement, None, &config).is_err());
    }
}
