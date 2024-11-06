use itertools::Itertools;
use one_crypto::CryptoProvider;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::DecomposedToken;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::credential_formatter::sdjwt::disclosures::{
    extract_disclosures, get_disclosures_by_claim_name,
};
use crate::provider::credential_formatter::sdjwt::model::{Disclosure, Sdvc};

pub mod disclosures;
pub mod mapper;
pub mod model;
pub mod verifier;

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
    crypto: &dyn CryptoProvider,
) -> Result<String, FormatterError> {
    let model::DecomposedToken {
        jwt,
        deserialized_disclosures,
    } = extract_disclosures(&presentation.token)?;

    let decomposed_jwt: DecomposedToken<Sdvc> = Jwt::decompose_token(jwt)?;
    let algorithm = decomposed_jwt
        .payload
        .custom
        .hash_alg
        .unwrap_or("sha-256".to_string());
    let hasher = crypto
        .get_hasher(&algorithm)
        .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;

    let disclosures = presentation
        .disclosed_keys
        .iter()
        .map(|key| get_disclosures_by_claim_name(key, &deserialized_disclosures, &*hasher))
        .collect::<Result<Vec<Vec<Disclosure>>, FormatterError>>()?
        .into_iter()
        .flatten()
        .map(|disclosure| disclosure.base64_encoded_disclosure)
        .unique()
        .collect::<Vec<String>>();

    let mut token = jwt.to_owned();
    for disclosure in disclosures {
        token.push('~');
        token.push_str(&disclosure);
    }

    Ok(token)
}
