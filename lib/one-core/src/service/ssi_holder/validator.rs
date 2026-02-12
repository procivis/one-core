use crate::config::core_config::{self, CoreConfig};
use crate::config::validator::protocol::validate_protocol_type;
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::model::identifier::IdentifierType;
use crate::proto::session_provider::SessionProvider;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::issuance_protocol::HolderBindingInput;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::error::ServiceError::MappingError;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::ssi_holder::dto::InitiateIssuanceRequestDTO;
use crate::validator::throw_if_org_relation_not_matching_session;

pub(super) fn validate_credentials_match_session_organisation(
    credentials: &[Credential],
    session_provider: &dyn SessionProvider,
) -> Result<(), ServiceError> {
    credentials
        .iter()
        .map(|cred| {
            throw_if_org_relation_not_matching_session(
                cred.schema
                    .as_ref()
                    .ok_or(MappingError(format!(
                        "Credential schema is missing on credential `{}`",
                        cred.id
                    )))?
                    .organisation
                    .as_ref(),
                session_provider,
            )?;
            Ok::<_, ServiceError>(())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(())
}

pub(super) fn validate_holder_capabilities(
    config: &core_config::CoreConfig,
    holder_binding: &HolderBindingInput,
    capabilities: &FormatterCapabilities,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), ServiceError> {
    if !capabilities
        .holder_identifier_types
        .contains(&holder_binding.identifier.r#type.to_owned().into())
    {
        return Err(BusinessLogicError::IncompatibleHolderIdentifier.into());
    }

    if holder_binding.identifier.r#type == IdentifierType::Did {
        let did = holder_binding
            .identifier
            .did
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Missing identifier did".to_string(),
            ))?;
        let did_type = config.did.get_fields(&did.did_method)?.r#type;
        if !capabilities.holder_did_methods.contains(&did_type) {
            return Err(BusinessLogicError::IncompatibleHolderDidMethod.into());
        }
    }

    let key_algorithm = holder_binding
        .key
        .key_algorithm_type()
        .and_then(|alg| key_algorithm_provider.key_algorithm_from_type(alg))
        .ok_or(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
            holder_binding.key.key_type.to_owned(),
        ))
        .error_while("getting key algorithm")?;
    if !capabilities
        .holder_key_algorithms
        .contains(&key_algorithm.algorithm_type())
    {
        return Err(BusinessLogicError::IncompatibleHolderKeyAlgorithm.into());
    }

    Ok(())
}

pub(super) fn validate_initiate_issuance_request(
    request: &InitiateIssuanceRequestDTO,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    validate_protocol_type(&request.protocol, &config.issuance_protocol)?;

    if request.scope.is_none()
        && request
            .authorization_details
            .as_ref()
            .is_none_or(|details| details.is_empty())
    {
        return Err(IssuanceProtocolError::InvalidRequest(
            "Scope or authenticationDetails must be specified".to_string(),
        )
        .into());
    }

    Ok(())
}
