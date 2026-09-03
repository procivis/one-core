use one_core::mapper::opt_secret_string;
use proc_macros::options_not_nullable;
use secrecy::SecretString;
use serde::Serialize;
use standardized_types::mapper::secret_string;
use standardized_types::oauth2::token::ExpiresIn;
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct SwiyuOpenID4VCITokenResponseRestDTO {
    #[serde(with = "secret_string")]
    #[schema(value_type = String, example = "secret")]
    pub access_token: SecretString,
    pub token_type: String,
    pub expires_in: ExpiresIn,
    #[serde(with = "opt_secret_string")]
    #[schema(value_type = String, example = "secret", nullable = false)]
    pub refresh_token: Option<SecretString>,
    pub refresh_token_expires_in: Option<ExpiresIn>,
}
