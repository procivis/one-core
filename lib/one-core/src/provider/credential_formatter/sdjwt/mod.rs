use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::DecomposedToken;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::credential_formatter::sdjwt::disclosures::{parse_token, select_disclosures};
use crate::provider::credential_formatter::sdjwt::model::Sdvc;

pub mod disclosures;
pub mod mapper;
pub mod model;

#[cfg(test)]
pub mod test;

pub(crate) enum SdJwtType {
    SdJwt,
    SdJwtVc,
}

pub(crate) fn detect_sdjwt_type_from_token(token: &str) -> Result<SdJwtType, FormatterError> {
    let without_claims = match token.split_once('~') {
        None => token,
        Some((without_claims, _)) => without_claims,
    };
    let jwt: DecomposedToken<Sdvc> = Jwt::decompose_token(without_claims)?;

    if jwt.payload.vc_type.is_some() {
        Ok(SdJwtType::SdJwtVc)
    } else {
        Ok(SdJwtType::SdJwt)
    }
}

pub(crate) fn prepare_sd_presentation(
    presentation: CredentialPresentation,
) -> Result<String, FormatterError> {
    let model::DecomposedToken { jwt, disclosures } = parse_token(&presentation.token)?;

    let disclosed_keys = presentation.disclosed_keys;
    let disclosures = select_disclosures(disclosed_keys, disclosures)?;

    let sdjwt = serialize(jwt.to_owned(), disclosures);

    Ok(sdjwt)
}

pub(crate) fn serialize(jwt: String, disclosures: Vec<String>) -> String {
    let mut token = jwt;
    token.push('~');

    let disclosures = disclosures.join("~");
    if !disclosures.is_empty() {
        token.push_str(&disclosures);
        token.push('~');
    }

    token
}
