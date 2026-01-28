use std::collections::HashSet;
use std::sync::Arc;

use maplit::hashset;
use mockall::predicate::eq;
use one_crypto::{MockCryptoProvider, MockHasher};
use serde_json::Value;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};

use super::{JsonLdClassic, Params};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::claim::Claim;
use crate::model::credential::CredentialRole;
use crate::model::credential_schema::{
    BackgroundProperties, CredentialSchemaClaim, LayoutProperties, LayoutType,
};
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::proto::http_client::HttpClient;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchema, CredentialSchemaMetadata, Issuer, MockSignatureProvider,
    PublishedClaim, PublishedClaimValue,
};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};
use crate::provider::credential_formatter::{CredentialFormatter, nest_claims};
use crate::provider::data_type::model::ExtractedClaim;
use crate::provider::data_type::provider::MockDataTypeProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::service::test_utilities::{dummy_did, dummy_identifier};
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
        .unwrap()
        .with_id(holder_did.clone().into_url());

    let vcdm = VcdmCredential::new_v2(issuer_did, credential_subject)
        .with_valid_from(now)
        .with_valid_until(now + Duration::seconds(10))
        .add_credential_schema(schema);

    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_identifier: Some(Identifier {
            did: Some(Did {
                did: holder_did.clone(),
                ..dummy_did()
            }),
            ..dummy_identifier()
        }),
        holder_key_id: None,
        issuer_certificate: None,
    };

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
        prepare_caching_loader(None),
        Arc::new(MockDataTypeProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
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

#[tokio::test]
async fn test_parse_credential() {
    const CREDENTIAL: &str = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\",\"https://core.dev.procivis-one.com/ssi/context/v1/lvvc.json\",\"https://core.dev.procivis-one.com/ssi/context/v1/3f77b7e5-5a82-4996-8a9f-f17938b074c5\"],\"id\":\"urn:uuid:248a4521-5a8d-4963-bc38-c4ff0f253aec\",\"type\":[\"VerifiableCredential\",\"7543JsonLdNested\"],\"issuer\":\"did:web:core.dev.procivis-one.com:ssi:did-web:v1:f6283305-667a-474b-a7e3-02c4ba998796\",\"validFrom\":\"2025-10-17T07:17:38.247509039Z\",\"validUntil\":\"2027-10-17T07:17:38.247509039Z\",\"credentialSubject\":{\"id\":\"did:key:zDnaeokW7xJYWFLNk5yA8W9LVVq7Ee2tYTQwMK2dJyC4e3rCr\",\"arr\":[\"a1\",\"a2\"],\"obj\":{\"nested\":\"n\"},\"str\":\"s\"},\"credentialStatus\":{\"id\":\"https://core.dev.procivis-one.com/ssi/revocation/v1/lvvc/248a4521-5a8d-4963-bc38-c4ff0f253aec\",\"type\":\"LVVC\"},\"proof\":{\"type\":\"DataIntegrityProof\",\"created\":\"2025-10-17T07:17:38.247556832Z\",\"cryptosuite\":\"ecdsa-rdfc-2019\",\"verificationMethod\":\"did:web:core.dev.procivis-one.com:ssi:did-web:v1:f6283305-667a-474b-a7e3-02c4ba998796#key-f0b46ab9-71db-42f6-8ab6-f09ee01b0be7\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3hMMeXnqipsaz8sFdjSj172jDaQ886iueYeGDrHKrk9L1ZmF8XAm4KN3PghuhNFXkpcbsV4cgDSY39FfwyNimN77\"},\"credentialSchema\":{\"id\":\"https://core.dev.procivis-one.com/ssi/schema/v1/3f77b7e5-5a82-4996-8a9f-f17938b074c5\",\"type\":\"ProcivisOneSchema2024\"}}";

    let mut datatype_provider = MockDataTypeProvider::new();
    datatype_provider
        .expect_extract_json_claim()
        .returning(|_| {
            Ok(ExtractedClaim {
                data_type: "STRING".to_string(),
                value: "value".to_string(),
            })
        });

    let reqwest_client = reqwest::Client::builder()
        .https_only(false)
        .build()
        .expect("Failed to create reqwest::Client");

    let formatter = JsonLdClassic::new(
        Params {
            leeway: Duration::seconds(60),
            embed_layout_properties: false,
            allowed_contexts: None,
        },
        Arc::new(MockCryptoProvider::default()),
        prepare_caching_loader(None),
        Arc::new(datatype_provider),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(ReqwestClient::new(reqwest_client)),
    );

    let credential = formatter.parse_credential(CREDENTIAL).await.unwrap();

    assert_eq!(credential.role, CredentialRole::Holder);
    assert!(credential.issuance_date.is_none());

    let issuer = credential.issuer_identifier.as_ref().unwrap();
    assert_eq!(
        issuer.did.as_ref().unwrap().did.to_string(),
        "did:web:core.dev.procivis-one.com:ssi:did-web:v1:f6283305-667a-474b-a7e3-02c4ba998796"
    );

    let holder = credential.holder_identifier.as_ref().unwrap();
    assert_eq!(
        holder.did.as_ref().unwrap().did.to_string(),
        "did:key:zDnaeokW7xJYWFLNk5yA8W9LVVq7Ee2tYTQwMK2dJyC4e3rCr"
    );

    let schema = credential.schema.as_ref().unwrap();
    assert_eq!(schema.revocation_method, Some("LVVC".into()));
    assert_eq!(schema.name, "7543JsonLdNested");
    assert_eq!(
        schema.schema_id,
        "https://core.dev.procivis-one.com/ssi/schema/v1/3f77b7e5-5a82-4996-8a9f-f17938b074c5"
    );

    let claims = credential.claims.as_ref().unwrap();
    assert_eq!(claims.len(), 10);

    let get_claim_paths = |filter: &dyn Fn(&Claim) -> bool| {
        HashSet::from_iter(
            claims
                .iter()
                .filter(|claim| filter(claim))
                .map(|claim| claim.path.as_str()),
        )
    };

    // intermediary
    assert_eq!(
        get_claim_paths(&|claim| claim.value.is_none() && !claim.schema.as_ref().unwrap().metadata),
        hashset! { "arr", "obj" }
    );
    // leaf
    assert_eq!(
        get_claim_paths(&|claim| claim.value == Some("value".to_string())
            && !claim.schema.as_ref().unwrap().metadata),
        hashset! { "str", "obj/nested", "arr/0", "arr/1" }
    );
    // metadata
    assert_eq!(
        get_claim_paths(&|claim| claim.schema.as_ref().unwrap().metadata),
        hashset! { "id", "type", "type/0", "type/1" }
    );

    let claim_schemas = schema.claim_schemas.as_ref().unwrap();
    assert_eq!(claim_schemas.len(), 6);

    let get_claim_schema_keys = |filter: &dyn Fn(&CredentialSchemaClaim) -> bool| {
        HashSet::from_iter(
            claim_schemas
                .iter()
                .filter(|schema| filter(schema))
                .map(|schema| schema.schema.key.as_str()),
        )
    };

    assert_eq!(
        get_claim_schema_keys(&|schema| !schema.schema.metadata),
        hashset! { "str", "arr", "obj", "obj/nested" }
    );

    assert_eq!(
        get_claim_schema_keys(&|schema| schema.schema.metadata),
        hashset! { "id", "type" }
    );
}
