use std::{collections::HashMap, str::FromStr, sync::Arc};

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use mockall::predicate::eq;
use shared_types::DidValue;
use time::{macros::datetime, Duration, OffsetDateTime};
use uuid::Uuid;

use super::SDJWTFormatter;

use crate::{
    config::data_structure::{AccessModifier, FormatJwtParams, Param},
    crypto::{hasher::MockHasher, signer::error::SignerError, MockCryptoProvider},
    provider::credential_formatter::{
        jwt::model::JWTPayload,
        model::{CredentialPresentation, CredentialStatus},
        sdjwt_formatter::model::Sdvc,
        CredentialFormatter, TokenVerifier,
    },
    service::{
        credential::dto::{
            CredentialDetailResponseDTO, CredentialStateEnum, DetailCredentialClaimResponseDTO,
            DetailCredentialSchemaResponseDTO,
        },
        credential_schema::dto::CredentialClaimSchemaDTO,
    },
};

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

struct VerifyVerification {
    issuer_did_value: Option<String>,
    algorithm: String,
    token: String,
    signature: Vec<u8>,
}

#[async_trait]
impl TokenVerifier for VerifyVerification {
    async fn verify<'a>(
        &self,
        issuer_did_value: Option<DidValue>,
        algorithm: &'a str,
        token: &'a str,
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        assert_eq!(
            self.issuer_did_value,
            issuer_did_value.map(|v| v.to_string())
        );
        assert_eq!(self.algorithm.as_str(), algorithm);
        assert_eq!(self.token.as_str(), token);
        assert_eq!(self.signature, signature);

        Ok(())
    }
}

fn test_credential_detail_response_dto() -> CredentialDetailResponseDTO {
    let id = Uuid::from_str("9a414a60-9e6b-4757-8011-9aa870ef4788").unwrap();

    CredentialDetailResponseDTO {
        id,
        created_date: get_dummy_date(),
        issuance_date: get_dummy_date(),
        revocation_date: None,
        state: CredentialStateEnum::Created,
        last_modified: get_dummy_date(),
        schema: DetailCredentialSchemaResponseDTO {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "Credential schema name".to_string(),
            format: "Credential schema format".to_string(),
            revocation_method: "Credential schema revocation method".to_string(),
            organisation_id: id,
        },
        issuer_did: Some("Issuer DID".parse().unwrap()),
        claims: vec![
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "name".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                },
                value: "John".to_string(),
            },
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "age".to_string(),
                    datatype: "NUMBER".to_string(),
                    required: true,
                },
                value: "42".to_string(),
            },
        ],
    }
}

#[tokio::test]
async fn test_format_credential() {
    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .times(2) // Number of claims
        .returning(|_| Ok(String::from("YWJjMTIz")));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .once()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    crypto
        .expect_generate_salt_base64()
        .times(2) // Number of claims
        .returning(|| String::from("MTIzYWJj"));

    let leeway = 45u64;

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: FormatJwtParams {
            leeway: Some(Param {
                access: AccessModifier::Public,
                value: leeway,
            }),
        },
    };

    let credential_details = test_credential_detail_response_dto();

    let result = sd_formatter.format_credentials(
        &credential_details,
        Some(CredentialStatus {
            id: "STATUS_ID".to_string(),
            r#type: "TYPE".to_string(),
            status_purpose: "PURPOSE".to_string(),
            additional_fields: HashMap::from([("Field1".to_owned(), "Val1".to_owned())]),
        }),
        &"holder_did".parse().unwrap(),
        "algorithm",
        vec!["Context1".to_string()],
        vec!["Type1".to_string()],
        Box::new(move |_: &str| Ok(vec![65u8, 66, 67])),
    );

    assert!(result.is_ok());

    let token = result.unwrap();

    let parts: Vec<&str> = token.splitn(3, '~').collect();

    assert_eq!(parts.len(), 3);
    assert_eq!(
        parts[1],
        &Base64UrlSafeNoPadding::encode_to_string(r#"["MTIzYWJj","name","John"]"#).unwrap()
    );
    assert_eq!(
        parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"["MTIzYWJj","age","42"]"#).unwrap()
    );

    let jwt_parts: Vec<&str> = parts[0].splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(r#"{"alg":"algorithm","typ":"SDJWT"}"#).unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<Sdvc> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        payload.expires_at,
        Some(payload.issued_at.unwrap() + Duration::days(365 * 2)),
    );
    assert_eq!(
        payload.invalid_before,
        Some(payload.issued_at.unwrap() - Duration::seconds(leeway as i64)),
    );

    assert_eq!(payload.issuer, Some(String::from("Issuer DID")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vc = payload.custom.vc;

    assert!(vc
        .credential_subject
        .claims
        .iter()
        .all(|hashed_claim| hashed_claim == "YWJjMTIz"));

    assert!(vc.context.contains(&String::from("Context1")));
    assert!(vc.r#type.contains(&String::from("Type1")));

    assert_eq!(vc.credential_status.as_ref().unwrap().id, "STATUS_ID");
    assert_eq!(vc.credential_status.as_ref().unwrap().r#type, "TYPE");
    assert_eq!(
        vc.credential_status.as_ref().unwrap().status_purpose,
        "PURPOSE"
    );
    assert_eq!(
        vc.credential_status
            .as_ref()
            .unwrap()
            .additional_fields
            .get("Field1"),
        Some(&"Val1".to_string())
    );
}

#[tokio::test]
async fn test_extract_credentials() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
        eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjcw\
        MjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6\
        IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBj\
        b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3Yx\
        IiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5\
        cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZV0pqTVRJeiIsIllX\
        SmpNVEl6Il19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwi\
        dHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFVSUE9TRSIsIkZpZWxkMSI6\
        IlZhbDEifX0sIl9zZF9hbGciOiJzaGEtMjU2In0";
    let token = format!(
        "{jwt_token}.QUJD~WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0~WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0"
    );

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .times(2) // Number of claims
        .returning(|_| Ok(String::from("YWJjMTIz")));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .once()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let leeway = 45u64;

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: FormatJwtParams {
            leeway: Some(Param {
                access: AccessModifier::Public,
                value: leeway,
            }),
        },
    };

    let verify_fn: Box<dyn TokenVerifier + Send + Sync> = Box::new(VerifyVerification {
        issuer_did_value: Some("Issuer DID".to_string()),
        algorithm: "algorithm".to_string(),
        token: jwt_token.to_owned(),
        signature: vec![65u8, 66, 67],
    });

    let result = sd_formatter.extract_credentials(&token, verify_fn).await;

    let credentials = result.unwrap();

    assert_eq!(credentials.issuer_did, Some("Issuer DID".parse().unwrap()));
    assert_eq!(credentials.subject, Some("holder_did".to_string()));

    assert_eq!(credentials.status.as_ref().unwrap().id, "STATUS_ID");
    assert_eq!(credentials.status.as_ref().unwrap().r#type, "TYPE");
    assert_eq!(
        credentials.status.as_ref().unwrap().status_purpose,
        "PURPOSE"
    );
    assert_eq!(
        credentials
            .status
            .as_ref()
            .unwrap()
            .additional_fields
            .get("Field1"),
        Some(&"Val1".to_string())
    );

    assert_eq!(credentials.claims.values.get("name").unwrap(), "John");
    assert_eq!(credentials.claims.values.get("age").unwrap(), "42");
}

#[tokio::test]
async fn test_format_credential_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
    eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjcw\
    MjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6\
    IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBj\
    b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3Yx\
    IiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5\
    cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZV0pqTVRJeiIsIllX\
    SmpNVEl6Il19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwi\
    dHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFVSUE9TRSIsIkZpZWxkMSI6\
    IlZhbDEifX0sIl9zZF9hbGciOiJzaGEtMjU2In0";

    let name_claim = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let age_claim = "WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0";
    let original_token = format!("{jwt_token}.QUJD~{name_claim}~{age_claim}");

    let crypto = MockCryptoProvider::default();

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: FormatJwtParams {
            leeway: Some(Param {
                access: AccessModifier::Public,
                value: 45u64,
            }),
        },
    };

    // Both
    let credential_presentation = CredentialPresentation {
        token: original_token.clone(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = sd_formatter.format_credential_presentation(credential_presentation);
    assert!(result.is_ok());
    let token = result.unwrap();
    assert!(token.contains(name_claim));
    assert!(token.contains(age_claim));

    // Just name
    let credential_presentation = CredentialPresentation {
        token: original_token.clone(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = sd_formatter.format_credential_presentation(credential_presentation);
    assert!(result.is_ok());
    let token = result.unwrap();
    assert!(token.contains(name_claim));
    assert!(!token.contains(age_claim));

    // Just age
    let credential_presentation = CredentialPresentation {
        token: original_token.clone(),
        disclosed_keys: vec!["age".to_string()],
    };

    let result = sd_formatter.format_credential_presentation(credential_presentation);
    assert!(result.is_ok());
    let token = result.unwrap();
    assert!(!token.contains(name_claim));
    assert!(token.contains(age_claim));

    // No disclosures
    let credential_presentation = CredentialPresentation {
        token: original_token.clone(),
        disclosed_keys: vec![],
    };

    let result = sd_formatter.format_credential_presentation(credential_presentation);
    assert!(result.is_ok());
    let token = result.unwrap();
    assert!(!token.contains(name_claim));
    assert!(!token.contains(age_claim));

    // Incorrect key
    let credential_presentation = CredentialPresentation {
        token: original_token,
        disclosed_keys: vec!["test".to_string()],
    };

    let result = sd_formatter.format_credential_presentation(credential_presentation);
    assert!(result.is_ok());
    let token = result.unwrap();

    //No disclosures in the result
    assert!(!token.contains('~'));
}

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.eyJpYXQiOjE2OT\
    kzNTE4NDEsImV4cCI6MTY5OTM1MjE0MSwibmJmIjoxNjk5MzUxNzk2LCJpc3MiOiJob2xkZXJfZGlkIiwic3ViIjoia\
    G9sZGVyX2RpZCIsImp0aSI6ImI0Y2M0OWQ1LThkMGUtNDgxZS1iMWViLThlNGU4Yjk2OTZiMSIsInZwIjp7IkBjb250\
    ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVB\
    yZXNlbnRhdGlvbiJdLCJfc2Rfand0IjpbImV5SmhiR2NpT2lKaGJHZHZjbWwwYUcwaUxDSjBlWEFpT2lKVFJFcFhWQ0\
    o5LmV5SnBZWFFpT2pFMk9Ua3lOekF5TmpZc0ltVjRjQ0k2TVRjMk1qTTBNakkyTml3aWJtSm1Jam94TmprNU1qY3dNa\
    kl4TENKcGMzTWlPaUpKYzNOMVpYSWdSRWxFSWl3aWMzVmlJam9pYUc5c1pHVnlYMlJwWkNJc0ltcDBhU0k2SWpsaE5E\
    RTBZVFl3TFRsbE5tSXRORGMxTnkwNE1ERXhMVGxoWVRnM01HVm1ORGM0T0NJc0luWmpJanA3SWtCamIyNTBaWGgwSWp\
    wYkltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwzWXhJaXdpUTI5dWRHVjRkRE\
    VpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbFI1Y0dVeElsMHNJbU55WldSbGJuU\
    nBZV3hUZFdKcVpXTjBJanA3SWw5elpDSTZXeUpaVjBwcVRWUkplaUlzSWxsWFNtcE5WRWw2SWwxOUxDSmpjbVZrWlc1\
    MGFXRnNVM1JoZEhWeklqcDdJbWxrSWpvaVUxUkJWRlZUWDBsRUlpd2lkSGx3WlNJNklsUlpVRVVpTENKemRHRjBkWE5\
    RZFhKd2IzTmxJam9pVUZWU1VFOVRSU0lzSWtacFpXeGtNU0k2SWxaaGJERWlmWDBzSWw5elpGOWhiR2NpT2lKemFHRX\
    RNalUySW4wLlFVSkR-V3lKTlZFbDZXVmRLYWlJc0ltNWhiV1VpTENKS2IyaHVJbDB-V3lKTlZFbDZXVmRLYWlJc0ltR\
    m5aU0lzSWpReUlsMCJdfX0";
    let presentation_token = format!("{jwt_token}.QUJD");

    let crypto = MockCryptoProvider::default();

    let leeway = 45u64;

    let sd_formatter = SDJWTFormatter {
        crypto: Arc::new(crypto),
        params: FormatJwtParams {
            leeway: Some(Param {
                access: AccessModifier::Public,
                value: leeway,
            }),
        },
    };

    let verify_fn: Box<dyn TokenVerifier + Send + Sync> = Box::new(VerifyVerification {
        issuer_did_value: Some("holder_did".to_string()), // Presentation is issued by holder
        algorithm: "algorithm".to_string(),
        token: jwt_token.to_owned(),
        signature: vec![65u8, 66, 67],
    });

    let result: Result<
        crate::provider::credential_formatter::model::Presentation,
        crate::provider::credential_formatter::error::FormatterError,
    > = sd_formatter
        .extract_presentation(&presentation_token, verify_fn)
        .await;

    assert!(result.is_ok());

    let presentation = result.unwrap();

    assert_eq!(
        presentation.expires_at,
        Some(presentation.issued_at.unwrap() + Duration::minutes(5)),
    );

    assert_eq!(presentation.credentials.len(), 1);
    assert_eq!(presentation.issuer_did, Some("holder_did".parse().unwrap()));
}
