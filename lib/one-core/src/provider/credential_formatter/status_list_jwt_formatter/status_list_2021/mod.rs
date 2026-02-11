use shared_types::DidValue;

use self::model::VC;
use crate::error::ContextWithErrorCode;
use crate::proto::jwt::Jwt;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::VerificationFn;

mod model;

pub struct StatusList2021JWTFormatter {}

impl StatusList2021JWTFormatter {
    pub async fn parse_status_list(
        status_list_token: &str,
        issuer_did: &DidValue,
        verification: VerificationFn,
    ) -> Result<String, FormatterError> {
        let jwt: Jwt<VC> = Jwt::build_from_token(status_list_token, Some(&(verification)), None)
            .await
            .error_while("parsing StatusList2021 token")?;

        let payload = jwt.payload;
        if payload
            .issuer
            .is_none_or(|issuer| issuer != issuer_did.as_str())
        {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Invalid issuer".to_string(),
            ));
        }

        if issuer_did.as_str() != payload.custom.vc.issuer.as_str() {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Invalid issuer".to_string(),
            ));
        }

        Ok(payload.custom.vc.credential_subject.encoded_list)
    }
}
