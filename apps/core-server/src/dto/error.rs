use dto_mapper::From;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, From, ToSchema)]
#[schema(example = "BR_XXXX")]
#[convert(from = "one_core::service::error::ErrorCode")]
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
    BR_0016,
    BR_0017,
    BR_0018,
    BR_0019,
    BR_0020,
    BR_0021,
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
