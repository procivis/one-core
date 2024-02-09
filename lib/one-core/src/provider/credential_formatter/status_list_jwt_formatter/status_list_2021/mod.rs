use self::model::VC;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::{error::FormatterError, VerificationFn};
use shared_types::DidValue;

mod model;

pub struct StatusList2021JWTFormatter {}

impl StatusList2021JWTFormatter {
    pub async fn parse_status_list(
        status_list_token: &str,
        issuer_did: &DidValue,
        verification: VerificationFn,
    ) -> Result<String, FormatterError> {
        let jwt: Jwt<VC> = Jwt::build_from_token(status_list_token, verification).await?;

        let payload = jwt.payload;
        if !payload
            .issuer
            .is_some_and(|issuer| issuer == issuer_did.as_str())
        {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Invalid issuer".to_string(),
            ));
        }

        if issuer_did != &payload.custom.vc.issuer {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Invalid issuer".to_string(),
            ));
        }

        Ok(payload.custom.vc.credential_subject.encoded_list)
    }
}
