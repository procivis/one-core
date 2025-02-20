use url::Url;

use super::dto::CreateProofRequestDTO;
use crate::config::core_config::{CoreConfig, ExchangeConfig, ExchangeType};
use crate::model::key::Key;
use crate::model::proof_schema::ProofSchema;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::exchange_protocol::openid4vc::model::OpenID4VCParams;
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

    let exchange_type = config.exchange.get_fields(exchange)?.r#type.to_string();

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

        Ok(())
    })?;

    Ok(())
}

pub(super) fn validate_scan_to_verify_compatibility(
    request: &CreateProofRequestDTO,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    let exchange_type = config.exchange.get_fields(&request.exchange)?.r#type;
    match exchange_type {
        ExchangeType::ScanToVerify => {
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
    config: &ExchangeConfig,
) -> Result<(), ServiceError> {
    let exchange_type = config.get_fields(exchange)?.r#type;
    match exchange_type {
        ExchangeType::IsoMdl if redirect_uri.is_some() => Err(ServiceError::Validation(
            ValidationError::InvalidMdlParameters,
        )),
        ExchangeType::IsoMdl if engagement.is_some() => Ok(()),
        _ if engagement.is_some() => Err(ServiceError::Validation(
            ValidationError::InvalidMdlParameters,
        )),
        _ => Ok(()),
    }
}

pub(super) fn validate_redirect_uri(
    exchange: &str,
    redirect_uri: Option<&str>,
    config: &ExchangeConfig,
) -> Result<(), ServiceError> {
    let fields = config.get_fields(exchange)?;
    match fields.r#type {
        ExchangeType::OpenId4Vc => {
            if let Some(redirect_uri) = redirect_uri {
                let exchange_params: OpenID4VCParams = config.get(exchange)?;

                if exchange_params.presentation.redirect_uri.disabled {
                    return Err(ValidationError::InvalidRedirectUri.into());
                }

                let url =
                    Url::parse(redirect_uri).map_err(|_| ValidationError::InvalidRedirectUri)?;

                if !exchange_params
                    .presentation
                    .redirect_uri
                    .allowed_schemes
                    .contains(&url.scheme().to_string())
                {
                    return Err(ValidationError::InvalidRedirectUri.into());
                }
            }

            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) fn validate_verification_key_storage_compatibility(
    proof_schema: &ProofSchema,
    verifier_key: &Key,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<(), ServiceError> {
    let input_schemas = proof_schema
        .input_schemas
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "input_schemas is None".to_string(),
        ))?;

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
            .contains(&verifier_key.storage_type)
        {
            return Err(ServiceError::BusinessLogic(
                BusinessLogicError::IncompatibleProofVerificationKeyStorage,
            ));
        }

        Ok(())
    })?;

    Ok(())
}
