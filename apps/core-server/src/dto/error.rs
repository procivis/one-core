use axum::Json;
use axum::extract::rejection::{FormRejection, JsonRejection, PathRejection, QueryRejection};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::typed_header::TypedHeaderRejection;
use one_core::service::error::ErrorCode;
use serde::Serialize;
use serde_with::skip_serializing_none;
use utoipa::ToSchema;

#[skip_serializing_none]
#[derive(Serialize, ToSchema)]
pub struct ErrorResponseRestDTO {
    pub code: &'static str,
    pub message: String,
    pub cause: Option<Cause>,
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
pub struct Cause {
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
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

// For Qs
impl From<(StatusCode, String)> for ErrorResponseRestDTO {
    fn from(value: (StatusCode, String)) -> Self {
        Self {
            code: ErrorCode::BR_0084.into(),
            message: "General input validation error".to_string(),
            cause: Some(Cause { message: value.1 }),
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
        }
    }
}

macro_rules! gen_from_rejection {
    ($from:ty, $rejection:ty ) => {
        impl From<$from> for $rejection {
            fn from(value: $from) -> Self {
                Self {
                    code: ErrorCode::BR_0084.into(),
                    message: "General input validation error".to_string(),
                    cause: Some(Cause {
                        message: value.body_text(),
                    }),
                }
            }
        }
    };
}

gen_from_rejection!(JsonRejection, ErrorResponseRestDTO);
gen_from_rejection!(QueryRejection, ErrorResponseRestDTO);
gen_from_rejection!(PathRejection, ErrorResponseRestDTO);
gen_from_rejection!(FormRejection, ErrorResponseRestDTO);
