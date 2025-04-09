use one_core::model::did::DidType;
use shared_types::DidValue;

use crate::fixtures::TestingDidParams;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_did_webvh_ok() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let log = r#"["1-QmQFP7EJRTuS8XDzu5twNacPkDUxZJYfbTLbqJ6sra9SRr","2024-07-29T17:00:27Z",{"method":"did:tdw:0.3","updateKeys":["z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV"],"scid":"QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A"},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com","verification_method":[{"id":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f","type":"JsonWebKey2020","controller":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"pR8PfwvDXESgqE33449iIUuj6R-8h8QLHZg_T7vhYU4","y":"u-RRNdMhPCwu9SiXcQ9xmokLroEq3XNfVUGOsFheHUQ"}},{"id":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f","type":"JsonWebKey2020","controller":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"pR8PfwvDXESgqE33449iIUuj6R-8h8QLHZg_T7vhYU4","y":"u-RRNdMhPCwu9SiXcQ9xmokLroEq3XNfVUGOsFheHUQ"}},{"id":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f","type":"JsonWebKey2020","controller":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"pR8PfwvDXESgqE33449iIUuj6R-8h8QLHZg_T7vhYU4","y":"u-RRNdMhPCwu9SiXcQ9xmokLroEq3XNfVUGOsFheHUQ"}},{"id":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f","type":"JsonWebKey2020","controller":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"pR8PfwvDXESgqE33449iIUuj6R-8h8QLHZg_T7vhYU4","y":"u-RRNdMhPCwu9SiXcQ9xmokLroEq3XNfVUGOsFheHUQ"}},{"id":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f","type":"JsonWebKey2020","controller":"did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"pR8PfwvDXESgqE33449iIUuj6R-8h8QLHZg_T7vhYU4","y":"u-RRNdMhPCwu9SiXcQ9xmokLroEq3XNfVUGOsFheHUQ"}}],"authentication":["did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f"],"assertion_method":["did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f"],"key_agreement":["did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f"],"capability_invocation":["did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f"],"capability_delegation":["did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com#key-763e6aea-b0ae-43f5-a54a-0d4cbadc2c6f"]}},{"type":"DataIntegrityProof","created":"2024-07-29T17:00:28Z","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV","proofPurpose":"authentication","proofValue":"zb67ii7ooNkmaADeD29LJdxECFy4gqkQAXN9L7QNNQrzQ86zU38HdK1dmDjeMz8Pgjxj6JutS1M9Y9mf4dRLGoRL","challenge":"1-QmQFP7EJRTuS8XDzu5twNacPkDUxZJYfbTLbqJ6sra9SRr"}]"#.to_string();
    let did_value: DidValue =
        "did:tdw:QmeZGQQV8uM9Mr74LyM3hS6JJHJD2a265xb9xJU8zZdo4A:test-domain.com"
            .parse()
            .unwrap();

    let did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                log: Some(log.clone()),
                did_type: Some(DidType::Local),
                did_method: Some("WEBVH".to_string()),
                did: Some(did_value),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.dids.get_did_webvh(&did.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/jsonl");

    let resp = resp.text().await;
    assert_eq!(resp, log);
}
