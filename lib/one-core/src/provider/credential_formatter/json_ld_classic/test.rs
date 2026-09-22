use std::collections::HashSet;
use std::sync::Arc;

use assert2::let_assert;
use maplit::hashset;
use serde_json::{Value, json};
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::Duration;
use time::macros::datetime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::JsonLdClassic;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::CredentialRole;
use crate::model::credential_schema::{BackgroundProperties, LayoutProperties};
use crate::model::did::Did;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::proto::http_client::HttpClient;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchema, CredentialSchemaMetadata, Issuer, MockSignatureProvider,
    MockTokenVerifier, PublishedClaim, PublishedClaimValue,
};
use crate::provider::credential_formatter::vcdm::{
    ContextType, VcdmCredential, VcdmCredentialSubject,
};
use crate::provider::credential_formatter::{CredentialFormatter, nest_claims};
use crate::provider::data_type::model::ExtractedClaim;
use crate::provider::data_type::provider::MockDataTypeProvider;
use crate::provider::did_method::MockDidMethod;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::service::test_utilities::{dummy_did, dummy_identifier, dummy_organisation};
use crate::util::test_utilities::prepare_caching_loader;

#[tokio::test]
async fn test_format_with_layout() {
    let now = crate::clock::now_utc();
    let token = create_token(true, Some(now + Duration::seconds(10))).await;
    assert_eq!(
        token["credentialSchema"]["metadata"]["layoutProperties"]["background"]["color"].as_str(),
        Some("color"),
    );
    assert_eq!(
        token["validUntil"].as_str(),
        Some(
            (now + Duration::seconds(10))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        )
        .as_deref(),
    );
}

#[tokio::test]
async fn test_format_with_layout_disabled() {
    let token = create_token(false, Some(crate::clock::now_utc() + Duration::seconds(10))).await;
    assert!(token["credentialSchema"]["metadata"].is_null());
}

#[tokio::test]
async fn test_format_no_valid_until_has_no_valid_until_or_expiration_date() {
    let token = create_token(true, None).await;
    assert!(token.get("validUntil").is_none());
    assert!(token.get("expirationDate").is_none());
}

async fn create_token(include_layout: bool, valid_until: Option<time::OffsetDateTime>) -> Value {
    let issuer_did = Issuer::Url(
        "did:key:z6Mkw7WbDmMJ5X8w1V7D4eFFJoVqMdkaGZQuFkp5ZZ4r1W3y"
            .parse()
            .unwrap(),
    );

    let schema = CredentialSchema {
        id: "credential-schema-id".to_string(),
        r#type: "FallbackSchema2024".to_string(),
        metadata: Some(CredentialSchemaMetadata {
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
            layout_type: None,
        }),
    };

    // universal context for unknown claims expansion
    let schema_context = ContextType::Object(
        json!({
            "@vocab": "https://www.w3.org/ns/credentials/issuer-dependent#",
            "id": "@id",
            "type": "@type"
        })
        .as_object()
        .unwrap()
        .to_owned(),
    );

    let claims = vec![PublishedClaim {
        key: "a/b/c".to_string(),
        value: PublishedClaimValue::String("15".to_string()),
        datatype: Some("STRING".to_string()),
    }];
    let now = crate::clock::now_utc();

    let holder_did: DidValue = "did:holder:123".parse().unwrap();

    let credential_subject = VcdmCredentialSubject::new(nest_claims(claims.clone()).unwrap())
        .unwrap()
        .with_id(holder_did.clone().into_url());

    let mut vcdm = VcdmCredential::new_v2(issuer_did, credential_subject)
        .with_valid_from(now)
        .add_context(schema_context)
        .add_credential_schema(schema);
    vcdm.valid_until = valid_until;

    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_identifier: Some(Identifier {
            data: IdentifierData::Did(
                (Did {
                    did: holder_did.clone(),
                    ..dummy_did()
                })
                .into(),
            ),
            ..dummy_identifier()
        }),
        holder_key_id: None,
        issuer_certificate: None,
    };

    let params = json!({
        "leewaySeconds": 60,
        "embedLayoutProperties": include_layout,
        "expirationSeconds": 86_400,
    });
    let key_algorithm = MockKeyAlgorithm::new();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .never()
        .returning({
            let key_algorithm = Arc::new(key_algorithm);
            move |_| Ok(key_algorithm.clone())
        });

    let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::default());

    let formatter = JsonLdClassic::new(
        "JSON_LD_CLASSIC".into(),
        params,
        prepare_caching_loader(None),
        Arc::new(MockDataTypeProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockDidMethodProvider::new()),
        client,
    )
    .unwrap();

    let mut auth_fn = MockSignatureProvider::new();
    auth_fn.expect_sign().returning(|msg| Ok(msg.to_vec()));
    auth_fn
        .expect_get_key_id()
        .returning(|| Some("keyid".to_string()));
    auth_fn
        .expect_get_key_algorithm()
        .returning(|| Ok(KeyAlgorithmType::Ecdsa));

    let formatted_credential = formatter
        .format_credential(credential_data, Box::new(auth_fn))
        .await
        .unwrap();

    let parsed_json: Value = serde_json::from_str(formatted_credential.as_ref()).unwrap();
    parsed_json
}

#[tokio::test]
async fn test_parse_credential() {
    const CONTEXT: &str = r##"
    {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "ProcivisOneSchema2024": {
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "metadata": {
              "@id": "http://127.0.0.1:9876/ssi/context/v1/4224e72d-087c-4376-8dcd-b48e8095e647#metadata",
              "@type": "@json"
            }
          },
          "@id": "http://127.0.0.1:9876/ssi/context/v1/4224e72d-087c-4376-8dcd-b48e8095e647#ProcivisOneSchema2024"
        },
        "8761JsonLd": {
          "@id": "http://127.0.0.1:9876/ssi/context/v1/4224e72d-087c-4376-8dcd-b48e8095e647#8761JsonLd"
        },
        "value": {
          "@id": "http://127.0.0.1:9876/ssi/context/v1/4224e72d-087c-4376-8dcd-b48e8095e647#value"
        }
      }
    }
    "##;
    const CREDENTIAL: &str = r##"
    {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "http://127.0.0.1:9876/ssi/context/v1/4224e72d-087c-4376-8dcd-b48e8095e647"
      ],
      "type": [
        "VerifiableCredential",
        "8761JsonLd"
      ],
      "issuer": "did:tdw:QmPxAB6sCcNqVyvg7io53dumteRfUSWDqJNs742UPm3FZ5:core.dev.procivis-one.com:ssi:did-webvh:v1:7301784b-4fb1-44c7-9f73-71d1a4d7c4f7",
      "validFrom": "2026-02-19T09:18:33.007487222Z",
      "validUntil": "2028-02-19T09:18:33.007487222Z",
      "credentialSubject": {
        "id": "did:key:zDnaeQtSJWkb9qaCu3imWNh6HZqVdcDESDNGnZjMqFZykv3m5",
        "value": "val"
      },
      "credentialStatus": {
        "id": "urn:uuid:97242ddd-dab3-4c5a-bcb5-adb646b8ee54",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "0",
        "statusListCredential": "http://127.0.0.1:9876/ssi/revocation/v1/list/65dbba51-f2ad-4249-888f-5d0f5280f4f7"
      },
      "proof": {
        "type": "DataIntegrityProof",
        "created": "2026-02-19T09:18:33.007490458Z",
        "cryptosuite": "ecdsa-rdfc-2019",
        "verificationMethod": "did:tdw:QmPxAB6sCcNqVyvg7io53dumteRfUSWDqJNs742UPm3FZ5:core.dev.procivis-one.com:ssi:did-webvh:v1:7301784b-4fb1-44c7-9f73-71d1a4d7c4f7#key-7ec02a62-d61d-4838-b8e0-0c99ad1d6079",
        "proofPurpose": "assertionMethod",
        "proofValue": "z2sToy5rhNkV8WPGA8FfxDkYWyK5vR4etvSdWj3WPCbXpTYcQBUcgY6Xur6935Ks5VHHSASQyJhdketMmbpbeyJDu"
      },
      "credentialSchema": {
        "id": "http://127.0.0.1:9876/ssi/schema/v1/4224e72d-087c-4376-8dcd-b48e8095e647",
        "type": "ProcivisOneSchema2024"
      }
    }
    "##;

    let listener = std::net::TcpListener::bind("127.0.0.1:9876").unwrap();
    let mock_server = MockServer::builder().listener(listener).start().await;

    mock_server
        .register(
            Mock::given(method("GET"))
                .and(path("/ssi/context/v1/4224e72d-087c-4376-8dcd-b48e8095e647"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(CONTEXT, "application/json"))
                .named("credential_schema GET /"),
        )
        .await;

    let mut datatype_provider = MockDataTypeProvider::new();
    datatype_provider
        .expect_extract_json_claim()
        .returning(|_| {
            Ok(ExtractedClaim {
                data_type: "STRING".to_string(),
                value: "value".to_string(),
            })
        });

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_get_did_method_by_method_name()
        .times(2)
        .returning(|name| Ok((name.into(), Arc::new(MockDidMethod::new()))));

    let formatter = JsonLdClassic::new(
        "JSON_LD_CLASSIC".into(),
        json!({
            "leewaySeconds": 60,
            "embedLayoutProperties": false,
            "expirationSeconds": 86_400,
        }),
        prepare_caching_loader(None),
        Arc::new(datatype_provider),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(did_method_provider),
        Arc::new(ReqwestClient::default()),
    )
    .unwrap();

    let mut verify_mock = MockTokenVerifier::new();
    verify_mock.expect_verify().return_once(|_, _, _, _| Ok(()));

    let credential = formatter
        .parse_credential(
            &CREDENTIAL.into(),
            dummy_organisation(None),
            Box::new(verify_mock),
        )
        .await
        .unwrap();

    assert_eq!(credential.role, CredentialRole::Holder);
    assert!(credential.issuance_date.is_none());
    assert_eq!(
        credential.expires_at.unwrap(),
        datetime!(2028-02-19 09:18:33.007487222 UTC)
    );

    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    assert_eq!(
        issuer_did.as_ref().await.unwrap().did.to_string(),
        "did:tdw:QmPxAB6sCcNqVyvg7io53dumteRfUSWDqJNs742UPm3FZ5:core.dev.procivis-one.com:ssi:did-webvh:v1:7301784b-4fb1-44c7-9f73-71d1a4d7c4f7"
    );

    let holder_identifier = credential
        .holder_identifier
        .as_ref()
        .unwrap()
        .as_ref()
        .await
        .unwrap();
    let_assert!(IdentifierData::Did(holder_did) = &holder_identifier.data);
    assert_eq!(
        holder_did.as_ref().await.unwrap().did.to_string(),
        "did:key:zDnaeQtSJWkb9qaCu3imWNh6HZqVdcDESDNGnZjMqFZykv3m5"
    );

    let schema = credential.schema.as_ref().await.unwrap();
    assert_eq!(schema.allow_revocation, true);
    assert_eq!(schema.name, "8761JsonLd");
    assert_eq!(
        schema.schema_id().await.unwrap(),
        "http://127.0.0.1:9876/ssi/schema/v1/4224e72d-087c-4376-8dcd-b48e8095e647"
    );

    let claims = credential.claims.as_ref().await.unwrap();
    assert_eq!(claims.len(), 4);

    let mut metadata_paths: HashSet<&str> = HashSet::new();
    for claim in claims.iter() {
        if claim.schema.as_ref().await.unwrap().metadata {
            metadata_paths.insert(claim.path.as_str());
        }
    }

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
        get_claim_paths(
            &|claim| claim.value.is_none() && !metadata_paths.contains(claim.path.as_str())
        ),
        hashset! {}
    );
    // leaf
    assert_eq!(
        get_claim_paths(&|claim| claim.value == Some("value".to_string())
            && !metadata_paths.contains(claim.path.as_str())),
        hashset! { "value" }
    );
    // metadata
    assert_eq!(
        get_claim_paths(&|claim| metadata_paths.contains(claim.path.as_str())),
        hashset! { "type", "type/0", "type/1" }
    );

    let claim_schemas = schema.claim_schemas.as_ref().await.unwrap();
    assert_eq!(claim_schemas.len(), 2);

    let get_claim_schema_keys = |filter: &dyn Fn(&ClaimSchema) -> bool| {
        HashSet::from_iter(
            claim_schemas
                .iter()
                .filter(|schema| filter(schema))
                .map(|schema| schema.key.as_str()),
        )
    };

    assert_eq!(
        get_claim_schema_keys(&|schema| !schema.metadata),
        hashset! { "value" }
    );

    assert_eq!(
        get_claim_schema_keys(&|schema| schema.metadata),
        hashset! { "type" }
    );
}
