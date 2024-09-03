use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use mockall::predicate::eq;
use one_crypto::{MockCryptoProvider, MockHasher};
use one_providers::{
    common_models::{
        credential_schema::{OpenBackgroundProperties, OpenLayoutProperties, OpenLayoutType},
        did::DidValue,
        OpenPublicKeyJwk, OpenPublicKeyJwkEllipticData,
    },
    credential_formatter::{
        model::{
            CredentialData, CredentialSchemaData, CredentialSchemaMetadata, MockSignatureProvider,
            PublishedClaim, PublishedClaimValue,
        },
        CredentialFormatter,
    },
    did::{
        model::{DidDocument, DidVerificationMethod},
        provider::MockDidMethodProvider,
    },
    http_client::{imp::reqwest_client::ReqwestClient, HttpClient},
    key_algorithm::{provider::MockKeyAlgorithmProvider, MockKeyAlgorithm},
};
use serde_json::json;
use time::{Duration, OffsetDateTime};

use crate::{
    provider::credential_formatter::json_ld_classic::{JsonLdClassic, Params},
    service::test_utilities::prepare_caching_loader,
};

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
    let issuer_did =
        DidValue::from("did:key:z6Mkw7WbDmMJ5X8w1V7D4eFFJoVqMdkaGZQuFkp5ZZ4r1W3y".to_string());

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
                layout_type: OpenLayoutType::Card,
                layout_properties: OpenLayoutProperties {
                    background: Some(OpenBackgroundProperties {
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
                    public_key_jwk: OpenPublicKeyJwk::Ec(OpenPublicKeyJwkEllipticData {
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
        prepare_caching_loader(),
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
            &holder_did.to_owned(),
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
