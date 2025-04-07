use std::sync::Arc;

use one_core::model::key::Key;
use one_core::provider::credential_formatter::model::{
    CredentialData, CredentialPresentation, Issuer, PublishedClaim,
};
use one_core::provider::credential_formatter::nest_claims;
use one_core::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};
use one_core::provider::did_method::DidCreateKeys;
use one_core::provider::http_client::reqwest_client::ReqwestClient;
use one_dev_services::model::{CredentialFormat, KeyAlgorithmType, StorageType};
use one_dev_services::service::error::CredentialServiceError;
use one_dev_services::OneDevCore;
use reqwest::Url;
use secrecy::ExposeSecret;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), CredentialServiceError> {
    let core = OneDevCore::new(None, Arc::new(ReqwestClient::default())).unwrap();

    let did_service = core.did_service;
    let did_method = did_service
        .get_did_method("KEY")
        .expect("Key method provider");

    let key_pair = core
        .signature_service
        .get_key_pair(&KeyAlgorithmType::Ecdsa)
        .expect("Key pair creation failed");

    let issuer_key = Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: key_pair.public,
        name: "My New Key".to_owned(),
        //Encryption is disabled so key_reference just holds private key
        key_reference: key_pair.private.expose_secret().to_vec(),
        storage_type: StorageType::Internal.to_string(),
        key_type: KeyAlgorithmType::Ecdsa.to_string(),
        organisation: None,
    };

    // We will use the same did value for both issuer and holder
    let keys = vec![issuer_key.clone()];
    let issuer_did = did_method
        .create(
            Some(Uuid::new_v4().into()),
            &None,
            Some(DidCreateKeys {
                authentication: keys.clone(),
                assertion_method: keys.clone(),
                key_agreement: keys.clone(),
                capability_invocation: keys.clone(),
                capability_delegation: keys,
                update_keys: None,
            }),
        )
        .await
        .expect("Did creation failed")
        .did;

    let credential_service = core.credential_service;

    let claims = vec![
        PublishedClaim {
            key: "root/array/0".into(),
            value: "array_item1".into(),
            datatype: Some("STRING".to_owned()),
            array_item: true,
        },
        PublishedClaim {
            key: "root/array/1".into(),
            value: "array_item2".into(),
            datatype: Some("STRING".to_owned()),
            array_item: true,
        },
        PublishedClaim {
            key: "root/nested".into(),
            value: "nested_item".into(),
            datatype: Some("STRING".to_owned()),
            array_item: false,
        },
        PublishedClaim {
            key: "root_item".into(),
            value: "root_item".into(),
            datatype: Some("STRING".to_owned()),
            array_item: false,
        },
    ];

    // We use the same did as issuer and holder in this example
    let holder_did = issuer_did.clone();
    let issuer = Issuer::Url(issuer_did.into_url());
    let credential_subject = VcdmCredentialSubject::new(nest_claims(claims.clone()).unwrap())
        .with_id(holder_did.clone().into_url());

    let vcdm = VcdmCredential::new_v2(issuer, credential_subject)
        .with_id("https://test-credential".parse::<Url>().unwrap())
        .with_valid_from(OffsetDateTime::now_utc())
        .with_valid_until(OffsetDateTime::now_utc() + Duration::days(365));

    let credential_data = CredentialData {
        vcdm,
        claims,
        holder_did: Some(holder_did),
        holder_key_id: None,
    };

    let token = credential_service
        .format_credential(credential_data, CredentialFormat::SdJwt, issuer_key)
        .await
        .expect("Credential formatting failed");
    println!("SDJWT token = {token}\n");

    let credential_presentation_config = CredentialPresentation {
        token,
        // We only disclose those two claims
        disclosed_keys: vec![
            "root/array".into(),
            // "root/nested".into(),
            "root_item".into(),
        ],
    };

    let credential_presentation = credential_service
        .format_credential_presentation(CredentialFormat::SdJwt, credential_presentation_config)
        .await
        .expect("Credential presentation creation failed");
    println!("SDJWT credential presentation = {credential_presentation}\n");

    let details = credential_service
        .extract_credential(CredentialFormat::SdJwt, &credential_presentation)
        .await
        .expect("Credential extraction failed");
    println!("Parsed presentation content: {:#?}\n", details);

    let values = details.claims.claims;

    assert_eq!(
        values.get("root_item").unwrap().as_str().unwrap(),
        "root_item"
    );
    let root = values.get("root").expect("root is missing");
    assert!(root["array"].is_array());
    assert!(root["nested"].is_null());

    println!("Array items: {:?}", root["array"].as_array().unwrap());

    Ok(())
}
