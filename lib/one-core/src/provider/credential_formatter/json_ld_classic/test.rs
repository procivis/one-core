use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use mockall::predicate::eq;
use one_crypto::{MockCryptoProvider, MockHasher};
use serde_json::json;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};

use crate::model::credential_schema::{BackgroundProperties, LayoutProperties, LayoutType};
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::credential_formatter::json_ld_classic::{JsonLdClassic, Params};
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchemaData, CredentialSchemaMetadata, ExtractPresentationCtx,
    FormatPresentationCtx, Issuer, MockSignatureProvider, MockTokenVerifier, PublishedClaim,
    PublishedClaimValue,
};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::service::test_utilities::prepare_caching_loader;

#[tokio::test]
async fn test_format_with_layout() {
    let token = create_token(true).await;
    assert_eq!(
        token["credentialSchema"]["metadata"]["layoutProperties"]["background"]["color"].as_str(),
        Some("color"),
    );
    assert_eq!(
        token["credentialSchema"]["metadata"]["layoutType"].as_str(),
        Some("CARD"),
    );
}

#[tokio::test]
async fn test_format_with_layout_disabled() {
    let token = create_token(false).await;
    assert!(token["credentialSchema"]["metadata"].is_null());
}

async fn create_token(include_layout: bool) -> serde_json::Value {
    let issuer_did = Issuer::Url(
        "did:key:z6Mkw7WbDmMJ5X8w1V7D4eFFJoVqMdkaGZQuFkp5ZZ4r1W3y"
            .parse()
            .unwrap(),
    );

    let credential_data = CredentialData {
        id: None,
        issuance_date: OffsetDateTime::now_utc(),
        valid_for: time::Duration::seconds(10),
        claims: vec![PublishedClaim {
            key: "a/b/c".to_string(),
            value: PublishedClaimValue::String("15".to_string()),
            datatype: Some("STRING".to_string()),
            array_item: false,
        }],
        issuer_did: issuer_did.clone(),
        status: vec![],
        schema: CredentialSchemaData {
            id: Some("credential-schema-id".to_string()),
            r#type: Some("FallbackSchema2024".to_string()),
            context: None,
            name: "credential-schema-name".to_string(),
            metadata: Some(CredentialSchemaMetadata {
                layout_type: LayoutType::Card,
                layout_properties: LayoutProperties {
                    background: Some(BackgroundProperties {
                        color: Some("color".to_string()),
                        image: None,
                    }),
                    logo: None,
                    primary_attribute: None,
                    secondary_attribute: None,
                    picture_attribute: None,
                    code: None,
                },
            }),
        },
        name: None,
        description: None,
        terms_of_use: vec![],
        evidence: vec![],
        related_resource: None,
    };

    let holder_did = DidValue::from("holder-did".to_string());

    let mut did_method_provider = MockDidMethodProvider::new();

    did_method_provider
        .expect_resolve()
        .withf({
            let holder_did = holder_did.clone();

            move |did| did == &holder_did
        })
        .returning(|holder_did| {
            Ok(DidDocument {
                context: json!({}),
                id: holder_did.to_owned(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                        r#use: None,
                        crv: "P-256".to_string(),
                        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                    }),
                }],
                authentication: None,
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                rest: Default::default(),
            })
        });

    let params = Params {
        leeway: Duration::seconds(60),
        embed_layout_properties: Some(include_layout),
    };
    let algorithm = "ES256";

    let key_algorithm = MockKeyAlgorithm::new();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_get_key_algorithm()
        .never()
        .returning({
            let key_algorithm = Arc::new(key_algorithm);
            move |_| Some(key_algorithm.clone())
        });

    let mut hasher = MockHasher::default();

    hasher.expect_hash().returning(|_| {
        Ok("WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc"
            .as_bytes()
            .to_vec())
    });

    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let reqwest_client = reqwest::Client::builder()
        .https_only(false)
        .build()
        .expect("Failed to create reqwest::Client");

    let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new(reqwest_client));

    let formatter = JsonLdClassic::new(
        params,
        Arc::new(crypto),
        Some("http://base_url".into()),
        Arc::new(did_method_provider),
        prepare_caching_loader(None),
        client,
    );

    let mut auth_fn = MockSignatureProvider::new();
    auth_fn.expect_sign().returning(|msg| Ok(msg.to_vec()));
    auth_fn
        .expect_get_key_id()
        .returning(|| Some("keyid".to_string()));

    let formatted_credential = formatter
        .format_credentials(
            credential_data,
            &Some(holder_did).to_owned(),
            algorithm,
            vec![],
            vec![],
            Box::new(auth_fn),
            None,
            None,
        )
        .await
        .unwrap();

    let parsed_json: serde_json::Value = serde_json::from_str(&formatted_credential).unwrap();
    parsed_json
}

static JWT_TOKEN: &str = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjc\
wMjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aS\
I6IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7I\
kBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxz\
L3YxIiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCI\
sIlR5cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJyWmp5eEY0ek\
U3ZmRSbWtjVVQ4SGtyOF9JSFNCZXMxejFwWldQMnZMQlJFIiwiS0dQbGRsUEIzO\
TV4S0pSaks4azJLNVV2c0VuczlRaEw3TzdKVXU1OUVSayJdfSwiY3JlZGVudGlh\
bFN0YXR1cyI6eyJpZCI6IlNUQVRVU19JRCIsInR5cGUiOiJUWVBFIiwic3RhdHV\
zUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19LCJfc2RfYWxnIj\
oic2hhLTI1NiJ9";

static JSONLD_TOKEN: &str = r#"{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713"
    ],
    "type": [
        "VerifiableCredential",
        "TestSubject"
    ],
    "issuer": "did:key:z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB",
    "validFrom": "2024-09-04T10:23:39.061276647Z",
    "credentialSubject": {
        "id": "did:key:z6Mki2njTKAL6rctJpMzHEeL35qhnG1wQaTG2knLVSk93Bj5",
        "TestSubject": {
            "Key": "test"
        }
    },
    "proof": {
        "type": "DataIntegrityProof",
        "created": "2024-09-04T10:23:39.06128179Z",
        "cryptosuite": "eddsa-rdfc-2022",
        "verificationMethod": "did:key:z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB#z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB",
        "proofPurpose": "assertionMethod",
        "proofValue": "z4h6Bhi7zcGroHnBrjubdgWuSj5TyuDqkNNAVLKTNpCqYoRWB48EGwzCGUByfaWmbbH9RLPisPx4TyRFHHSz3ReEY"
    },
    "credentialSchema": {
        "id": "0f87b718-435a-4562-ae9a-b1a57eeec713",
        "type": "ProcivisOneSchema2024"
    }
}"#;

#[tokio::test]
async fn test_format_presentation_multi_tokens() {
    let issuer_did =
        DidValue::from("did:key:z6Mkw7WbDmMJ5X8w1V7D4eFFJoVqMdkaGZQuFkp5ZZ4r1W3y".to_string());

    let holder_did = DidValue::from("holder-did".to_string());

    let mut did_method_provider = MockDidMethodProvider::new();

    did_method_provider
        .expect_resolve()
        .withf({
            let holder_did = holder_did.clone();

            move |did| did == &holder_did
        })
        .returning(|holder_did| {
            Ok(DidDocument {
                context: json!({}),
                id: holder_did.to_owned(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                        r#use: None,
                        crv: "P-256".to_string(),
                        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                    }),
                }],
                authentication: None,
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                rest: Default::default(),
            })
        });

    let params = Params {
        leeway: Duration::seconds(60),
        embed_layout_properties: Some(true),
    };
    let algorithm = "ES256";

    let key_algorithm = MockKeyAlgorithm::new();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_get_key_algorithm()
        .never()
        .returning({
            let key_algorithm = Arc::new(key_algorithm);
            move |_| Some(key_algorithm.clone())
        });

    let mut hasher = MockHasher::default();

    hasher.expect_hash().returning(|_| {
        Ok("WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc"
            .as_bytes()
            .to_vec())
    });

    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let reqwest_client = reqwest::Client::builder()
        .https_only(false)
        .build()
        .expect("Failed to create reqwest::Client");

    let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new(reqwest_client));

    let formatter = JsonLdClassic::new(
        params,
        Arc::new(crypto),
        Some("http://base_url".into()),
        Arc::new(did_method_provider),
        prepare_caching_loader(Some((
            "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713",
            &json!(
                {
                    "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type",
                        "TestCredential": {
                            "@id": "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713/TestCredential",
                            "@context": {
                                "@version": 1.1,
                                "@protected": true,
                                "id": "@id",
                                "type": "@type"
                            }
                        },
                        "TestSubject": {
                            "@id": "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713/TestSubject",
                            "@context": {
                                "@version": 1.1,
                                "@protected": true,
                                "id": "@id",
                                "type": "@type",
                                "Key": "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713/TestSchema#Key",
                            }
                        }
                    }
                }
            )
            .to_string()
        ))),
        client,
    );

    let mut auth_fn = MockSignatureProvider::new();
    auth_fn.expect_sign().returning(|msg| Ok(msg.to_vec()));
    auth_fn
        .expect_get_key_id()
        .returning(|| Some("keyid".to_string()));

    let formatted_presentation = formatter
        .format_presentation(
            vec![JWT_TOKEN.to_owned(), JSONLD_TOKEN.to_owned()].as_slice(),
            &issuer_did,
            algorithm,
            Box::new(auth_fn),
            FormatPresentationCtx {
                token_formats: Some(vec!["JWT".to_owned(), "JSON_LD_CLASSIC".to_owned()]),
                vc_format_map: HashMap::from_iter(vec![
                    ("JSON_LD_CLASSIC".to_string(), "ldp_vc".to_string()),
                    ("JWT".to_string(), "jwt_vc_json".to_string()),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let value = serde_json::Value::from_str(&formatted_presentation).unwrap();

    assert_eq!(
        value["verifiableCredential"][0]["type"],
        "EnvelopedVerifiableCredential"
    );
    assert_eq!(
        value["verifiableCredential"][1]["type"][0],
        "VerifiableCredential"
    );
    assert_eq!(value["verifiableCredential"][1]["type"][1], "TestSubject");
}

static PRESENTATION_TOKEN: &str = r#"{
    "@context": [
        "https://www.w3.org/ns/credentials/v2"
    ],
    "type": "VerifiablePresentation",
    "issuanceDate": "2024-09-04T11:00:00.084411735Z",
    "verifiableCredential": [
        {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": "EnvelopedVerifiableCredential",
            "id": "data:application/jwt_vc_json,eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5MjcwMjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJyWmp5eEY0ekU3ZmRSbWtjVVQ4SGtyOF9JSFNCZXMxejFwWldQMnZMQlJFIiwiS0dQbGRsUEIzOTV4S0pSaks4azJLNVV2c0VuczlRaEw3TzdKVXU1OUVSayJdfSwiY3JlZGVudGlhbFN0YXR1cyI6eyJpZCI6IlNUQVRVU19JRCIsInR5cGUiOiJUWVBFIiwic3RhdHVzUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19LCJfc2RfYWxnIjoic2hhLTI1NiJ9"
        },
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713"
            ],
            "type": [
                "VerifiableCredential",
                "TestSubject"
            ],
            "issuer": "did:key:z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB",
            "validFrom": "2024-09-04T10:23:39.061276647Z",
            "credentialSubject": {
                "id": "did:key:z6Mki2njTKAL6rctJpMzHEeL35qhnG1wQaTG2knLVSk93Bj5",
                "TestSubject": {
                    "Key": "test"
                }
            },
            "proof": {
                "type": "DataIntegrityProof",
                "created": "2024-09-04T10:23:39.06128179Z",
                "cryptosuite": "eddsa-rdfc-2022",
                "verificationMethod": "did:key:z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB#z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB",
                "proofPurpose": "assertionMethod",
                "proofValue": "z4h6Bhi7zcGroHnBrjubdgWuSj5TyuDqkNNAVLKTNpCqYoRWB48EGwzCGUByfaWmbbH9RLPisPx4TyRFHHSz3ReEY"
            },
            "credentialSchema": {
                "id": "0f87b718-435a-4562-ae9a-b1a57eeec713",
                "type": "ProcivisOneSchema2024"
            }
        }
    ],
    "holder": "did:key:z6Mkw7WbDmMJ5X8w1V7D4eFFJoVqMdkaGZQuFkp5ZZ4r1W3y",
    "proof": {
        "type": "DataIntegrityProof",
        "created": "2024-09-04T11:00:00.084427442Z",
        "cryptosuite": "ecdsa-rdfc-2019",
        "verificationMethod": "keyid",
        "proofPurpose": "authentication",
        "proofValue": "z36JHqZryAWHbrBF7QScduTxbFSKTivdg3ms3N73wiSEMeyKHA3LCATDS8EDGS4ppNo9AcA6LysUucMBwHogbAN52YGtC3EpRh4u6UDtbv2EKAo9V172efC"
    }
}"#;

#[tokio::test]
async fn test_parse_presentation_multi_tokens() {
    let holder_did = DidValue::from("holder-did".to_string());

    let mut did_method_provider = MockDidMethodProvider::new();

    did_method_provider
        .expect_resolve()
        .withf({
            let holder_did = holder_did.clone();

            move |did| did == &holder_did
        })
        .returning(|holder_did| {
            Ok(DidDocument {
                context: json!({}),
                id: holder_did.to_owned(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                        r#use: None,
                        crv: "P-256".to_string(),
                        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                    }),
                }],
                authentication: None,
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                rest: Default::default(),
            })
        });

    let params = Params {
        leeway: Duration::seconds(60),
        embed_layout_properties: Some(true),
    };

    let key_algorithm = MockKeyAlgorithm::new();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_get_key_algorithm()
        .never()
        .returning({
            let key_algorithm = Arc::new(key_algorithm);
            move |_| Some(key_algorithm.clone())
        });

    let mut hasher = MockHasher::default();

    hasher.expect_hash().returning(|_| {
        Ok("WQnd2qlMku7G5ItM53QRvdUf4GacXGzLWvTN_wDharc"
            .as_bytes()
            .to_vec())
    });

    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let reqwest_client = reqwest::Client::builder()
        .https_only(false)
        .build()
        .expect("Failed to create reqwest::Client");

    let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new(reqwest_client));

    let formatter = JsonLdClassic::new(
        params,
        Arc::new(crypto),
        Some("http://base_url".into()),
        Arc::new(did_method_provider),
        prepare_caching_loader(Some((
            "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713",
            &json!(
                {
                    "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type",
                        "TestCredential": {
                            "@id": "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713/TestCredential",
                            "@context": {
                                "@version": 1.1,
                                "@protected": true,
                                "id": "@id",
                                "type": "@type"
                            }
                        },
                        "TestSubject": {
                            "@id": "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713/TestSubject",
                            "@context": {
                                "@version": 1.1,
                                "@protected": true,
                                "id": "@id",
                                "type": "@type",
                                "Key": "http://127.0.0.1:43741/ssi/context/v1/0f87b718-435a-4562-ae9a-b1a57eeec713/TestSchema#Key",
                            }
                        }
                    }
                }
            )
            .to_string()
        ))),
        client,
    );

    let mut token_verifier = MockTokenVerifier::new();
    token_verifier
        .expect_verify()
        .once()
        .returning(move |_, _, _, _, _| Ok(()));

    let presentation = formatter
        .extract_presentation(
            PRESENTATION_TOKEN,
            Box::new(token_verifier),
            ExtractPresentationCtx::default(),
        )
        .await
        .unwrap();

    let credentials = presentation.credentials;

    let json_ld_no_whitespace = JSONLD_TOKEN
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();

    assert_eq!(credentials, vec![JWT_TOKEN, &json_ld_no_whitespace]);
}
