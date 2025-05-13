use url::Url;

use super::dto::CreateProofRequestDTO;
use crate::config::core_config::{
    CoreConfig, IdentifierType, VerificationProtocolConfig, VerificationProtocolType,
};
use crate::model::did::{Did, KeyRole};
use crate::model::key::Key;
use crate::model::proof_schema::ProofSchema;
use crate::provider::credential_formatter::model::Features;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4Vp20Params;
use crate::provider::verification_protocol::openid4vp::draft25::model::OpenID4Vp25Params;
use crate::service::error::{
    BusinessLogicError, MissingProviderError, ServiceError, ValidationError,
};

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
            .get_formatter(&credential_schema.format.to_string())
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

    let key_agreement_key = verifier_did.find_first_key_by_role(KeyRole::KeyAgreement)?;

    input_schemas.iter().try_for_each(|input_schema| {
        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))?;

        let formatter = formatter_provider
            .get_formatter(&credential_schema.format.to_string())
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
        .get_fields(&request.exchange)?
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
            .get_formatter(&credential_schema.format.to_string())
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
