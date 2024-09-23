use std::sync::Arc;

use one_core::model::key::Key;
use one_core::provider::credential_formatter::model::{
    CredentialData, CredentialPresentation, CredentialSchemaData, Issuer, PublishedClaim,
};
use one_core::provider::http_client::reqwest_client::ReqwestClient;
use one_dev_services::model::{CredentialFormat, KeyAlgorithmType, StorageType};
use one_dev_services::service::error::CredentialServiceError;
use one_dev_services::OneDevCore;
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
        .get_key_pair(&KeyAlgorithmType::Es256)
        .expect("Key pair creation failed");

    let issuer_key = Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: key_pair.public,
        name: "My New Key".to_owned(),
        //Encryption is disabled so key_reference just holds private key
        key_reference: key_pair.private,
        storage_type: StorageType::Internal.to_string(),
        key_type: KeyAlgorithmType::Es256.to_string(),
        organisation: None,
    };

    // We will use the same did value for both issuer and holder
    let issuer_did = did_method
        .create(
            Some(Uuid::new_v4().into()),
            &None,
            Some(vec![issuer_key.clone()]),
        )
        .await
        .expect("Did creation failed");

    let credential_service = core.credential_service;

    let credential_data = CredentialData {
        id: Some("https://test-credential".to_string()),
        issuance_date: OffsetDateTime::now_utc(),
        valid_for: Duration::days(365),
        claims: vec![
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
        ],
        issuer_did: issuer_did.as_str().parse().map(Issuer::Url).unwrap(),
        status: vec![],
        schema: CredentialSchemaData {
            id: None,
            r#type: None,
            context: None,
            name: "".to_string(),
            metadata: None,
        },
        name: None,
        description: None,
        terms_of_use: vec![],
        evidence: vec![],
        related_resource: None,
    };

    // We use the same did as issuer and holder in this example
    let holder_did = issuer_did;

    let token = credential_service
        .format_credential(
            credential_data,
            CredentialFormat::SdJwt,
            KeyAlgorithmType::Es256,
            holder_did,
            issuer_key,
        )
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

    let values = details.claims.values;

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
