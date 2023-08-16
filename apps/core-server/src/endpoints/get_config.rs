use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::{dto::response::config::ConfigDTO, AppState};

#[utoipa::path(
    get,
    path = "/api/config/v1",
    responses(
        (status = 200, description = "OK", body = ConfigDTO),
        (status = 401, description = "Unauthorized")
    ),
    tag = "other",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_config(state: State<AppState>) -> Response {
    let config = state.core.get_config().await;
    match ConfigDTO::try_from(config) {
        Ok(config) => (StatusCode::OK, Json(config)).into_response(),
        Err(error) => {
            tracing::error!("Failed to get config: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::dto::response::config::ConfigDTO;
    use one_core::config::data_structure::{
        AccessModifier, DatatypeEntity, DatatypeParams, DatatypeStringParams, DatatypeType, Param,
        ParamsEnum, TranslatableString,
    };

    #[test]
    fn convert_internal_structure_to_dto() {
        let config = one_core::config::data_structure::CoreConfig {
            format: Default::default(),
            exchange: Default::default(),
            revocation: Default::default(),
            did: Default::default(),
            datatype: HashMap::from([(
                "test".to_string(),
                DatatypeEntity {
                    r#type: DatatypeType::String,
                    display: TranslatableString::Value("display".to_string()),
                    order: None,
                    params: Some(ParamsEnum::Parsed(DatatypeParams::String(
                        DatatypeStringParams {
                            autocomplete: Some(Param::<bool> {
                                access: AccessModifier::Public,
                                value: false,
                            }),
                            placeholder: None,
                            error: None,
                            pattern: None,
                        },
                    ))),
                },
            )]),
        };
        let output = ConfigDTO::try_from(config).unwrap();
        let text_output = serde_json::to_string_pretty(&output).unwrap();

        assert_eq!(
            r#"{
  "format": {},
  "exchange": {},
  "revocation": {},
  "did": {},
  "datatype": {
    "test": {
      "display": "display",
      "order": null,
      "params": {
        "autocomplete": false
      },
      "type": "STRING"
    }
  }
}"#,
            text_output
        );
    }

    #[test]
    fn do_not_serialize_private_parameters() {
        let config = one_core::config::data_structure::CoreConfig {
            format: Default::default(),
            exchange: Default::default(),
            revocation: Default::default(),
            did: Default::default(),
            datatype: HashMap::from([(
                "test".to_string(),
                DatatypeEntity {
                    r#type: DatatypeType::String,
                    display: TranslatableString::Value("display".to_string()),
                    order: None,
                    params: Some(ParamsEnum::Parsed(DatatypeParams::String(
                        DatatypeStringParams {
                            autocomplete: Some(Param::<bool> {
                                access: AccessModifier::Private,
                                value: false,
                            }),
                            placeholder: None,
                            error: None,
                            pattern: None,
                        },
                    ))),
                },
            )]),
        };

        let output = ConfigDTO::try_from(config).unwrap();
        let text_output = serde_json::to_string_pretty(&output).unwrap();

        assert_eq!(
            r#"{
  "format": {},
  "exchange": {},
  "revocation": {},
  "did": {},
  "datatype": {
    "test": {
      "display": "display",
      "order": null,
      "params": {},
      "type": "STRING"
    }
  }
}"#,
            text_output
        );
    }
}
