use self::model::VC;
use one_providers::common_models::did::DidValue;
use one_providers::credential_formatter::{
    error::FormatterError, imp::jwt::Jwt, model::VerificationFn,
};

mod model;

pub struct StatusList2021JWTFormatter {}

impl StatusList2021JWTFormatter {
    pub async fn parse_status_list(
        status_list_token: &str,
        issuer_did: &DidValue,
        verification: VerificationFn,
    ) -> Result<String, FormatterError> {
        let jwt: Jwt<VC> = Jwt::build_from_token(status_list_token, Some(verification)).await?;

        let payload = jwt.payload;
        if !payload
            .issuer
            .is_some_and(|issuer| issuer == issuer_did.as_str())
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
