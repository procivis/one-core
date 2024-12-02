use axum::extract::rejection::{FormRejection, JsonRejection, PathRejection, QueryRejection};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::typed_header::TypedHeaderRejection;
use one_dto_mapper::From;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, From, ToSchema)]
#[schema(example = "BR_XXXX")]
#[from("one_core::service::error::ErrorCode")]
#[allow(non_camel_case_types)]
pub enum ErrorCode {
    BR_0000,
    BR_0001,
    BR_0002,
    BR_0003,
    BR_0004,
    BR_0005,
    BR_0006,
    BR_0007,
    BR_0008,
    BR_0009,
    BR_0010,
    BR_0011,
    BR_0012,
    BR_0013,
    BR_0014,
    BR_0015,
    BR_0017,
    BR_0018,
    BR_0019,
    BR_0020,
    BR_0022,
    BR_0023,
    BR_0024,
    BR_0025,
    BR_0026,
    BR_0027,
    BR_0028,
    BR_0029,
    BR_0030,
    BR_0031,
    BR_0032,
    BR_0033,
    BR_0034,
    BR_0035,
    BR_0036,
    BR_0037,
    BR_0038,
    BR_0039,
    BR_0040,
    BR_0041,
    BR_0042,
    BR_0043,
    BR_0044,
    BR_0045,
    BR_0046,
    BR_0047,
    BR_0048,
    BR_0049,
    BR_0050,
    BR_0051,
    BR_0052,
    BR_0053,
    BR_0054,
    BR_0055,
    BR_0056,
    BR_0057,
    BR_0058,
    BR_0059,
    BR_0060,
    BR_0061,
    BR_0062,
    BR_0063,
    BR_0064,
    BR_0065,
    BR_0066,
    BR_0084,
    BR_0085,
    BR_0086,
    BR_0087,
    BR_0088,
    BR_0089,
    BR_0090,
    BR_0091,
    BR_0092,
    BR_0094,
    BR_0095,
    BR_0096,
    BR_0097,
    BR_0098,
    BR_0099,
    BR_0100,
    BR_0101,
    BR_0103,
    BR_0104,
    BR_0105,
    BR_0106,
    BR_0107,
    BR_0108,
    BR_0109,
    BR_0110,
    BR_0111,
    BR_0112,
    BR_0113,
    BR_0114,
    BR_0115,
    BR_0117,
    BR_0118,
    BR_0120,
    BR_0121,
    BR_0122,
    BR_0123,
    BR_0125,
    BR_0126,
    BR_0127,
    BR_0128,
    BR_0130,
    BR_0131,
    BR_0132,
    BR_0133,
    BR_0135,
    BR_0137,
    BR_0138,
    BR_0139,
    BR_0140,
    BR_0142,
    BR_0144,
    BR_0145,
    BR_0146,
    BR_0147,
    BR_0156,
    BR_0157,
    BR_0158,
    BR_0159,
    BR_0160,
    BR_0162,
    BR_0163,
    BR_0164,
    BR_0166,
    BR_0169,
    BR_0170,
    BR_0172,
    BR_0173,
    BR_0177,
    BR_0178,
    BR_0179,
    BR_0180,
    BR_0181,
    BR_0183,
    BR_0184,
    BR_0187,
    BR_0188,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorResponseRestDTO {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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
            code: ErrorCode::BR_0084,
            message: "General input validation error".to_string(),
            cause: Some(Cause { message: value.1 }),
        }
    }
}

impl From<TypedHeaderRejection> for ErrorResponseRestDTO {
    fn from(value: TypedHeaderRejection) -> Self {
        Self {
            code: ErrorCode::BR_0084,
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
                    code: ErrorCode::BR_0084,
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
