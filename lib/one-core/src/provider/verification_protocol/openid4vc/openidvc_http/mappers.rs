use crate::config::core_config::FormatType;
use crate::provider::verification_protocol::openid4vc::model::PresentedCredential;
use crate::provider::verification_protocol::openid4vc::VerificationProtocolError;

pub(crate) fn map_credential_formats_to_presentation_format(
    presented: &[PresentedCredential],
) -> Result<(String, String), VerificationProtocolError> {
    // MDOC credential(s) are sent as a MDOC presentation, using the MDOC formatter
    if presented.len() == 1
        && presented
            .iter()
            .all(|cred| cred.credential_schema.format == FormatType::Mdoc.to_string())
    {
        return Ok((FormatType::Mdoc.to_string(), "mso_mdoc".to_owned()));
    }

    // The SD_JWT presentations can contains only one credential
    if presented.len() == 1
        && presented
            .iter()
            .all(|cred| cred.credential_schema.format == FormatType::SdJwt.to_string())
    {
        return Ok((FormatType::SdJwt.to_string(), "vc+sd-jwt".to_owned()));
    }

    if presented.iter().all(|cred| {
        cred.credential_schema.format == FormatType::JsonLdClassic.to_string()
            || cred.credential_schema.format == FormatType::JsonLdBbsPlus.to_string()
    }) {
        return Ok((FormatType::JsonLdClassic.to_string(), "ldp_vp".to_owned()));
    }

    // Fallback, handle all other formats via enveloped JWT
    Ok((FormatType::Jwt.to_string(), "jwt_vp_json".to_owned()))
}
