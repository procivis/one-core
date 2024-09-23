use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::model::interaction::Interaction;
use crate::provider::exchange_protocol::openid4vc::model::OpenID4VPInteractionData;
use crate::provider::exchange_protocol::openid4vc::ExchangeProtocolError;
use crate::provider::http_client::HttpClient;

pub fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    interaction: Option<&Interaction>,
) -> Result<DataDTO, ExchangeProtocolError> {
    let data = interaction
        .ok_or(ExchangeProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .data
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "interaction data is missing".to_string(),
        ))?;
    serde_json::from_slice(data).map_err(ExchangeProtocolError::JsonError)
}

pub fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, ExchangeProtocolError> {
    serde_json::to_vec(&dto).map_err(ExchangeProtocolError::JsonError)
}

pub async fn interaction_data_from_query(
    query: &str,
    client: &Arc<dyn HttpClient>,
    allow_insecure_http_transport: bool,
) -> Result<OpenID4VPInteractionData, ExchangeProtocolError> {
    let mut interaction_data: OpenID4VPInteractionData = serde_qs::from_str(query)
        .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

    if interaction_data.client_metadata.is_some() && interaction_data.client_metadata_uri.is_some()
    {
        return Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata and client_metadata_uri cannot be set together".to_string(),
        ));
    }

    if interaction_data.presentation_definition.is_some()
        && interaction_data.presentation_definition_uri.is_some()
    {
        return Err(ExchangeProtocolError::InvalidRequest(
            "presentation_definition and presentation_definition_uri cannot be set together"
                .to_string(),
        ));
    }

    if let Some(client_metadata_uri) = &interaction_data.client_metadata_uri {
        if !allow_insecure_http_transport && client_metadata_uri.scheme() != "https" {
            return Err(ExchangeProtocolError::InvalidRequest(
                "client_metadata_uri must use HTTPS scheme".to_string(),
            ));
        }

        let client_metadata = client
            .get(client_metadata_uri.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        interaction_data.client_metadata = Some(client_metadata);
    }

    if let Some(presentation_definition_uri) = &interaction_data.presentation_definition_uri {
        if !allow_insecure_http_transport && presentation_definition_uri.scheme() != "https" {
            return Err(ExchangeProtocolError::InvalidRequest(
                "presentation_definition_uri must use HTTPS scheme".to_string(),
            ));
        }

        let presentation_definition = client
            .get(presentation_definition_uri.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        interaction_data.presentation_definition = Some(presentation_definition);
    }

    Ok(interaction_data)
}

pub fn validate_interaction_data(
    interaction_data: &OpenID4VPInteractionData,
) -> Result<(), ExchangeProtocolError> {
    if interaction_data.redirect_uri.is_some() {
        return Err(ExchangeProtocolError::InvalidRequest(
            "redirect_uri must be None".to_string(),
        ));
    }
    assert_query_param(&interaction_data.response_type, "vp_token", "response_type")?;
    assert_query_param(
        &interaction_data.client_id_scheme,
        "redirect_uri",
        "client_id_scheme",
    )?;
    assert_query_param(
        &interaction_data.response_mode,
        "direct_post",
        "response_mode",
    )?;

    let client_metadata =
        interaction_data
            .client_metadata
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "client_metadata is None".to_string(),
            ))?;

    if client_metadata.client_id_scheme != interaction_data.client_id_scheme {
        return Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata.client_id_scheme must match client_scheme".to_string(),
        ));
    }

    match client_metadata.vp_formats.get("jwt_vp_json") {
        None => Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata.vp_formats must contain 'jwt_vp_json'".to_string(),
        )),
        Some(jwt_vp_json) => {
            if jwt_vp_json.alg.contains(&"EdDSA".to_string()) {
                Ok(())
            } else {
                Err(ExchangeProtocolError::InvalidRequest(
                    "client_metadata.vp_formats[\"jwt_vp_json\"] must contain 'EdDSA' algorithm"
                        .to_string(),
                ))
            }
        }
    }?;

    Ok(())
}

fn assert_query_param(
    value: &str,
    expected_value: &str,
    key: &str,
) -> Result<(), ExchangeProtocolError> {
    if value != expected_value {
        return Err(ExchangeProtocolError::InvalidRequest(format!(
            "{key} must be '{expected_value}'"
        )));
    }
    Ok(())
}
