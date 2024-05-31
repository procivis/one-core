use crate::provider::exchange_protocol::openid4vc::dto::OpenID4VPInteractionData;
use crate::provider::exchange_protocol::ExchangeProtocolError;

pub(super) fn validate_interaction_data(
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
