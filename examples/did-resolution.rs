use std::sync::Arc;

use one_core::proto::http_client::reqwest_client::ReqwestClient;
use one_core::provider::did_method::DidMethod;
use one_core::provider::did_method::error::DidMethodError;
use one_core::provider::did_method::universal::{
    Params as UniversalDidMethodParams, UniversalDidMethod,
};
use one_dev_services::OneDevCore;

#[tokio::main]
async fn main() -> Result<(), DidMethodError> {
    let client = Arc::new(ReqwestClient::default());

    let core = OneDevCore::new(None, client.clone()).unwrap();
    let did_service = core.did_service;

    let example_did_values_implemented = vec![
        // did:key
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".parse().unwrap(),
        // did:jwk
        "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9".parse().unwrap(),
        // did:web
        "did:web:core.trial.procivis-one.com:ssi:did-web:v1:bcbfef61-cfd4-4d31-ae46-82f0a121463e".parse().unwrap(),
    ];
    let example_did_value_unimplemented = "did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0".parse().unwrap();

    //
    // Resolving DIDs using the core DID service
    //

    for did in example_did_values_implemented.into_iter() {
        // resolve DID using service without allowing fallback provider
        let result = did_service.resolve_did(&did, false).await;
        assert!(result.is_ok(), "expected to resolve DID {did}");
        println!("Resolved {did} into:\n{result:#?}\n");
    }

    // resolving an unimplemented DID method with fallback provider disabled will fail
    let result = did_service
        .resolve_did(&example_did_value_unimplemented, false)
        .await;
    assert!(result.is_err(), "expected not to resolve DID");

    // when enabling the fallback to an universal resolver, DID resolution should succeed however
    let result = did_service
        .resolve_did(&example_did_value_unimplemented, true)
        .await;
    assert!(result.is_ok(), "expected to resolve DID");

    //
    // Resolving DIDs using the DID method impolementation directly
    //

    let example_did_key = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        .parse()
        .unwrap();
    let did_key = did_service.get_did_method("KEY").unwrap();
    let result = did_key.resolve(&example_did_key).await;
    assert!(result.is_ok(), "expected to resolve DID");

    //
    // Resolving DIDs without initializing core - if desired, the DID methods
    // can also be instantiated and used directly
    //

    let universal_resolver = UniversalDidMethod::new(
        UniversalDidMethodParams {
            resolver_url: "https://dev.uniresolver.io".to_string(),
            supported_method_names: vec!["key".to_string()],
        },
        client,
    );
    let result = universal_resolver.resolve(&example_did_key).await;
    assert!(result.is_ok(), "expected to resolve DID");

    Ok(())
}
