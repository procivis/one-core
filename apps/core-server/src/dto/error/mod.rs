pub(crate) mod status_code;

use axum::Json;
use axum::extract::rejection::{FormRejection, JsonRejection, PathRejection, QueryRejection};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::typed_header::TypedHeaderRejection;
use one_core::error::{ErrorCode, ErrorData};
use proc_macros::options_not_nullable;
use serde::Serialize;
use utoipa::ToSchema;

use crate::dto::common::ecosystem::EcosystemOutcomesRestDTO;

#[options_not_nullable]
#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorResponseRestDTO {
    pub code: &'static str,
    pub message: String,
    pub cause: Option<Cause>,
    /// Only set on BR_0476, where it carries the ecosystem outcomes behind the failure.
    pub data: Option<ErrorDataRestDTO>,
    /// HTTP status to use with [`IntoResponse`].
    /// `None` falls back to 400
    #[serde(skip)]
    pub status: Option<StatusCode>,
}

#[options_not_nullable]
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ErrorDataRestDTO {
    pub ecosystem_errors: Option<EcosystemOutcomesRestDTO>,
}

impl From<ErrorData> for ErrorDataRestDTO {
    fn from(value: ErrorData) -> Self {
        match value {
            ErrorData::EcosystemsResolved(outcomes) => Self {
                ecosystem_errors: Some(outcomes.into()),
            },
        }
    }
}

impl ErrorResponseRestDTO {
    pub fn hide_cause(mut self, hide: bool) -> ErrorResponseRestDTO {
        if hide {
            self.cause = None;
        }

        self
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct Cause {
    pub message: String,
}

impl Cause {
    pub fn with_message_from_error(error: &impl std::error::Error) -> Cause {
        Cause {
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ErrorResponseRestDTO {
    fn into_response(self) -> axum::response::Response {
        let status = self.status.unwrap_or(StatusCode::BAD_REQUEST);
        (status, Json(self)).into_response()
    }
}

// For Qs
impl From<(StatusCode, String)> for ErrorResponseRestDTO {
    fn from(value: (StatusCode, String)) -> Self {
        Self {
            code: ErrorCode::BR_0084.into(),
            message: "General input validation error".to_string(),
            cause: Some(Cause { message: value.1 }),
            data: None,
            status: Some(value.0),
        }
    }
}

impl From<TypedHeaderRejection> for ErrorResponseRestDTO {
    fn from(value: TypedHeaderRejection) -> Self {
        Self {
            code: ErrorCode::BR_0084.into(),
            message: "General input validation error".to_string(),
            cause: Some(Cause {
                message: format!("{:?}", value.reason()),
            }),
            data: None,
            status: None,
        }
    }
}

macro_rules! gen_from_rejection {
    ($from:ty, $rejection:ty ) => {
        impl From<$from> for $rejection {
            fn from(value: $from) -> Self {
                // Only 413 is propagated for now;
                // All other extractor rejections keep the existing 400 default
                let status = (value.status() == StatusCode::PAYLOAD_TOO_LARGE)
                    .then_some(StatusCode::PAYLOAD_TOO_LARGE);
                Self {
                    code: ErrorCode::BR_0084.into(),
                    message: "General input validation error".to_string(),
                    cause: Some(Cause {
                        message: value.body_text(),
                    }),
                    data: None,
                    status,
                }
            }
        }
    };
}

gen_from_rejection!(JsonRejection, ErrorResponseRestDTO);
gen_from_rejection!(QueryRejection, ErrorResponseRestDTO);
gen_from_rejection!(PathRejection, ErrorResponseRestDTO);
gen_from_rejection!(FormRejection, ErrorResponseRestDTO);
