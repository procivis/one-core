use super::dto::InitiateIssuanceRequestDTO;
use super::error::HolderServiceError;
use crate::config::core_config::CoreConfig;
use crate::config::validator::protocol::validate_protocol_type;
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::model::identifier::IdentifierData;
use crate::proto::session_provider::SessionProvider;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::issuance_protocol::HolderBindingInput;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::validator::throw_if_org_id_not_matching_session;

pub(super) async fn validate_credentials_match_session_organisation(
    credentials: &[Credential],
    session_provider: &dyn SessionProvider,
) -> Result<(), HolderServiceError> {
    for cred in credentials {
        let schema = cred.common().schema.as_ref().await?;
        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), session_provider)
            .error_while("checking session")?;
    }
    Ok(())
}

pub(super) async fn validate_holder_capabilities(
    config: &CoreConfig,
    holder_binding: &HolderBindingInput,
    capabilities: &FormatterCapabilities,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), HolderServiceError> {
    if !capabilities
        .holder_identifier_types
        .contains(&holder_binding.identifier.data.r#type().into())
    {
        return Err(HolderServiceError::IncompatibleHolderIdentifier);
    }

    if let IdentifierData::Did(did) = &holder_binding.identifier.data {
        let did = did.as_ref().await?;
        let did_type = config
            .did
            .get_fields(&did.did_method)
            .error_while("getting did config")?
            .r#type;
        if !capabilities.holder_did_methods.contains(&did_type) {
            return Err(HolderServiceError::IncompatibleHolderDidMethod);
        }
    }

    let key_algorithm = key_algorithm_provider
        .key_algorithm_from_key(&holder_binding.key)
        .error_while("getting key algorithm")?;
    if !capabilities
        .holder_key_algorithms
        .contains(&key_algorithm.algorithm_type())
    {
        return Err(HolderServiceError::IncompatibleHolderKeyAlgorithm);
    }

    Ok(())
}

pub(super) fn validate_initiate_issuance_request(
    request: &InitiateIssuanceRequestDTO,
    config: &CoreConfig,
) -> Result<(), HolderServiceError> {
    validate_protocol_type(&request.protocol, &config.issuance_protocol)
        .error_while("checking protocol")?;

    if request.scope.is_none()
        && request
            .authorization_details
            .as_ref()
            .is_none_or(|details| details.is_empty())
    {
        return Err(HolderServiceError::InvalidInput(
            "Scope or authenticationDetails must be specified".to_string(),
        ));
    }

    Ok(())
}
