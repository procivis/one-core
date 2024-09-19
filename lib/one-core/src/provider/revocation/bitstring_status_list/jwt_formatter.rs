use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shared_types::DidValue;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{AuthenticationFn, VerificationFn};
use crate::provider::revocation::bitstring_status_list::model::{
    ContentType, CredentialSubject, StatusPurpose, SubjectType, VCContent, VC,
};
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;

pub struct BitstringStatusListJwtFormatter {}

impl BitstringStatusListJwtFormatter {
    pub async fn format_status_list(
        revocation_list_url: String,
        issuer_did: &Did,
        encoded_list: String,
        algorithm: String,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
    ) -> Result<String, FormatterError> {
        let subject = format!("{}#list", revocation_list_url);
        let vc = VC {
            vc: VCContent {
                context: vcdm_v2_base_context(),
                id: None,
                r#type: vec![
                    ContentType::VerifiableCredential,
                    ContentType::BitstringStatusListCredential,
                ],
                issuer: issuer_did.did.to_owned(),
                valid_from: Some(OffsetDateTime::now_utc()),
                issued: None,
                valid_until: None,
                credential_subject: CredentialSubject {
                    id: subject.to_owned(),
                    r#type: SubjectType::BitstringStatusList,
                    status_purpose,
                    encoded_list,
                },
            },
        };

        let payload = JWTPayload {
            issuer: Some(issuer_did.did.to_string()),
            jwt_id: Some(revocation_list_url),
            subject: Some(subject),
            custom: vc,
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            nonce: None,
        };

        let jwt = Jwt::new("JWT".to_owned(), algorithm, None, payload);

        jwt.tokenize(auth_fn).await
    }

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

        if issuer_did != &payload.custom.vc.issuer {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Invalid issuer".to_string(),
            ));
        }

        Ok(payload.custom.vc.credential_subject.encoded_list)
    }
}

pub(super) fn into_timestamp<S>(dt: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted = format!(
        "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month() as i32,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    formatted.serialize(s)
}

pub(super) fn into_timestamp_opt<S>(dt: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(dt) => into_timestamp(dt, s),
        None => s.serialize_none(),
    }
}

pub(super) fn from_timestamp_opt<'de, D>(
    deserializer: D,
) -> Result<Option<OffsetDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    Option::<String>::deserialize(deserializer).and_then(|string| {
        string
            .map(|string| {
                OffsetDateTime::parse(&string, &Rfc3339)
                    .map_err(|err| Error::custom(err.to_string()))
            })
            .transpose()
    })
}
