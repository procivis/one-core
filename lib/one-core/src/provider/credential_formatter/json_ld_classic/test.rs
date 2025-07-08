use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use mockall::predicate::eq;
use one_crypto::{MockCryptoProvider, MockHasher};
use serde_json::{Value, json};
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};

use crate::config::core_config::KeyAlgorithmType;
use crate::model::credential_schema::{BackgroundProperties, LayoutProperties, LayoutType};
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::credential_formatter::json_ld_classic::{JsonLdClassic, Params};
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchema, CredentialSchemaMetadata, Issuer, MockSignatureProvider,
    PublishedClaim, PublishedClaimValue,
};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};
use crate::provider::credential_formatter::{CredentialFormatter, nest_claims};
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::util::test_utilities::prepare_caching_loader;

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

async fn create_token(include_layout: bool) -> Value {
    let issuer_did = Issuer::Url(
        "did:key:z6Mkw7WbDmMJ5X8w1V7D4eFFJoVqMdkaGZQuFkp5ZZ4r1W3y"
            .parse()
            .unwrap(),
    );

    let schema = CredentialSchema {
        id: "credential-schema-id".to_string(),
        r#type: "FallbackSchema2024".to_string(),
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
    };

    let claims = vec![PublishedClaim {
        key: "a/b/c".to_string(),
        value: PublishedClaimValue::String("15".to_string()),
        datatype: Some("STRING".to_string()),
        array_item: false,
    }];
    let now = OffsetDateTime::now_utc();

    let holder_did: DidValue = "did:holder:123".parse().unwrap();

    let credential_subject = VcdmCredentialSubject::new(nest_claims(claims.clone()).unwrap())
        .with_id(holder_did.clone().into_url());

    let vcdm = VcdmCredential::new_v2(issuer_did, credential_subject)
        .with_valid_from(now)
        .with_valid_until(now + Duration::seconds(10))
        .add_credential_schema(schema);

    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_did: Some(holder_did.clone()),
        holder_key_id: None,
        issuer_certificate: None,
    };

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
                        kid: None,
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
                also_known_as: None,
                service: None,
            })
        });

    let params = Params {
        leeway: Duration::seconds(60),
        embed_layout_properties: include_layout,
        allowed_contexts: None,
    };
    let key_algorithm = MockKeyAlgorithm::new();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
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
    auth_fn
        .expect_get_key_algorithm()
        .return_const(Ok(KeyAlgorithmType::Ecdsa));

    let formatted_credential = formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await
        .unwrap();

    let parsed_json: Value = serde_json::from_str(&formatted_credential).unwrap();
    parsed_json
}
