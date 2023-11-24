use std::str::FromStr;

use shared_types::DidId;
use uuid::Uuid;

use crate::provider::did_method::{web::WebDidMethod, DidMethod};

#[tokio::test]
async fn test_did_web_create() {
    let base_url = "https://test-domain.com";

    let did_web_method = WebDidMethod::new(base_url).unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result = did_web_method.create(&id, &None, &None).await;

    assert_eq!(
        result.unwrap().as_str(),
        "did:web:test-domain.com:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
    )
}

#[tokio::test]
async fn test_did_web_create_with_port() {
    let base_url = "https://test-domain.com:54812";

    let did_web_method = WebDidMethod::new(base_url).unwrap();

    let id = DidId::from(Uuid::from_str("2389ba3f-81d5-4931-9222-c23ec721deb7").unwrap());

    let result: Result<shared_types::DidValue, crate::provider::did_method::DidMethodError> =
        did_web_method.create(&id, &None, &None).await;

    assert_eq!(
        result.unwrap().as_str(),
        "did:web:test-domain.com%3A54812:ssi:did-web:v1:2389ba3f-81d5-4931-9222-c23ec721deb7"
    )
}
