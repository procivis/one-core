use dto_mapper::From;
use one_core::service::error::ServiceError;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Serialize, From, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[convert(from = "one_core::service::error::ErrorCode")]
pub enum ErrorCode {
    OrganisationAlreadyExists,

    DidNotFound,
    DidInvalidType,
    DidInvalidMethod,
    DidDeactivated,
    DidValueAlreadyExists,
    DidCannotDeactivate,

    CredentialSchemaAlreadyExists,

    Credential001,
    CredentialInvalidState,

    ProofSchemaAlreadyExists,

    ProofInvalidState,

    Database,
    ResponseMapping,

    Unmapped,
}

// derive IntoResponse for this
#[derive(Serialize, ToSchema)]
pub struct ErrorResponseRestDTO {
    pub code: ErrorCode,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<Cause>,
    #[serde(skip)]
    pub error: ServiceError,
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
