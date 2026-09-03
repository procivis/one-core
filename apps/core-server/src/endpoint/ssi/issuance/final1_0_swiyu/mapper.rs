use standardized_types::oauth2::token::TokenResponse;

use crate::endpoint::ssi::issuance::final1_0_swiyu::dto::SwiyuOpenID4VCITokenResponseRestDTO;

impl From<TokenResponse> for SwiyuOpenID4VCITokenResponseRestDTO {
    fn from(value: TokenResponse) -> Self {
        let TokenResponse {
            access_token,
            expires_in,
            refresh_token,
            refresh_token_expires_in,
            ..
        } = value;
        Self {
            access_token,
            token_type: "BEARER".to_string(),
            expires_in,
            refresh_token,
            refresh_token_expires_in,
        }
    }
}
