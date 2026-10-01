use similar_asserts::assert_eq;

use super::*;
use crate::provider::did_method::webvh::common::hash_update_key;

fn replacement_keys(setup: &Setup) -> DidKeys {
    DidKeys {
        authentication: vec![setup.new_document.clone()],
        assertion_method: vec![setup.new_document.clone()],
        key_agreement: vec![setup.new_document.clone()],
        capability_invocation: vec![setup.new_document.clone()],
        capability_delegation: vec![setup.new_document.clone()],
        update_keys: Some(vec![setup.new_update.clone()]),
    }
}

async fn create_log(setup: &Setup, id: DidId) -> DidCreated {
    setup
        .method
        .create(id, &None, did_keys(setup))
        .await
        .unwrap()
}

async fn update_after_previous_entry(
    setup: &Setup,
    id: DidId,
    keys: DidKeys,
    new_keys: DidKeys,
    log: String,
) -> DidUpdate {
    let previous: LogEntry = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    let update_time =
        OffsetDateTime::parse(&previous.version_time, &Rfc3339).unwrap() + Duration::seconds(1);
    crate::clock::run_with_mocked_time_async(
        update_time,
        setup.method.update(id, keys, new_keys, Some(log)),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn create_update_resolve_roundtrip() {
    let id = Uuid::new_v4().into();
    let mut setup = setup(MockHttpClient::new());
    assert!(
        setup
            .method
            .get_capabilities()
            .operations
            .contains(&Operation::UPDATE)
    );
    let created = create_log(&setup, id).await;
    let initial_log = created.log.unwrap();
    let new_keys = replacement_keys(&setup);
    let updated = update_after_previous_entry(
        &setup,
        id,
        did_keys(&setup),
        new_keys.clone(),
        initial_log.clone(),
    )
    .await;
    assert!(updated.deactivated.is_none());
    let log = updated.log.unwrap();
    assert!(log.starts_with(&initial_log));
    let verified = setup
        .method
        .verify_log(&log, Some(&created.did))
        .await
        .unwrap();
    assert_eq!(verified.entries.len(), 2);
    let old_signer = make_keyref(&setup.active, setup.method.key_provider.as_ref()).unwrap();
    let new_signer = make_keyref(&setup.new_update, setup.method.key_provider.as_ref()).unwrap();
    assert_eq!(verified.active_keys, vec![new_signer.multibase.clone()]);
    assert_eq!(
        verified.entries[1].proof[0].verification_method,
        format!("did:key:{}#{}", old_signer.multibase, old_signer.multibase)
    );

    // A subsequent document update must be signed by the newly authorized key.
    let updated =
        update_after_previous_entry(&setup, id, new_keys.clone(), new_keys.clone(), log).await;
    let log = updated.log.unwrap();
    let verified = setup
        .method
        .verify_log(&log, Some(&created.did))
        .await
        .unwrap();
    assert_eq!(verified.entries.len(), 3);
    assert_eq!(
        verified.entries[2].proof[0].verification_method,
        format!("did:key:{}#{}", new_signer.multibase, new_signer.multibase)
    );
    assert!(verified.entries[2].parameters.update_keys.is_none());

    let url = validate_did_parts(created.did.as_str())
        .unwrap()
        .to_string();
    let mut client = MockHttpClient::new();
    mock_webvh_log_request(
        &mut client,
        url.clone(),
        Response {
            body: log.as_bytes().to_vec(),
            headers: Default::default(),
            status: StatusCode(200),
            request: Request {
                body: None,
                headers: Default::default(),
                method: Method::Get,
                url,
                timeout: None,
            },
        },
    );
    setup.method.client = Arc::new(client);
    let document = setup.method.resolve(&created.did).await.unwrap();
    let reference = format!("{}#key-{}", created.did, setup.new_document.id);
    assert_eq!(document.id, created.did);
    assert_eq!(document.verification_method.len(), 1);
    assert_eq!(document.verification_method[0].id, reference);
    assert_ne!(
        document.verification_method[0].id,
        format!("{}#key-{}", created.did, setup.document.id)
    );
    let mut expected_jwk = make_keyref(&setup.new_document, setup.method.key_provider.as_ref())
        .unwrap()
        .handle
        .public_key_as_jwk()
        .unwrap();
    expected_jwk.set_kid(format!("key-{}", setup.new_document.id));
    assert_eq!(document.verification_method[0].public_key_jwk, expected_jwk);
    for relationship in [
        document.authentication,
        document.assertion_method,
        document.key_agreement,
        document.capability_invocation,
        document.capability_delegation,
    ] {
        assert_eq!(relationship, Some(vec![reference.clone()]));
    }

    let deactivated = setup
        .method
        .deactivate(id, new_keys, Some(log))
        .await
        .unwrap();
    let verified = setup
        .method
        .verify_log(&deactivated.log.unwrap(), Some(&created.did))
        .await
        .unwrap();
    assert!(verified.deactivated);
    assert_eq!(verified.entries.len(), 4);
}

#[tokio::test]
async fn update_preserves_document_fields_and_removes_old_relationships() {
    let id = Uuid::new_v4().into();
    let mut setup = setup(MockHttpClient::new());
    setup.method.params.include_swiss_profile_marker = true;
    let created = create_log(&setup, id).await;
    let log = created.log.unwrap();
    let mut state: Value = serde_json::from_str::<Value>(&log).unwrap()["state"].clone();
    state["alsoKnownAs"] = json!(["https://example.com/issuer"]);
    state["service"] = json!([{
        "id": format!("{}#service", created.did), "type": "LinkedDomains",
        "serviceEndpoint": "https://example.com"
    }]);
    state["@context"]
        .as_array_mut()
        .unwrap()
        .push(json!({"custom": "https://example.com/custom"}));
    let log = append_signed_state_update(
        &setup,
        &log,
        LogParameters {
            ttl: Some(60),
            ..Default::default()
        },
        &setup.active,
        state.clone(),
    )
    .await;
    let new_keys = DidKeys {
        key_agreement: vec![setup.new_document.clone()],
        update_keys: Some(vec![setup.active.clone()]),
        ..Default::default()
    };
    let updated = update_after_previous_entry(&setup, id, did_keys(&setup), new_keys, log).await;
    let verified = setup
        .method
        .verify_log(&updated.log.unwrap(), Some(&created.did))
        .await
        .unwrap();
    let entry = verified.entries.last().unwrap();
    for field in [
        "id",
        "@context",
        "alsoKnownAs",
        "service",
        "profile_version",
    ] {
        assert_eq!(entry.state[field], state[field]);
    }
    assert!(entry.state.get("authentication").is_none());
    assert!(entry.state.get("assertionMethod").is_none());
    assert_eq!(
        entry.state["keyAgreement"],
        json!([format!("{}#key-{}", created.did, setup.new_document.id)])
    );
    assert_eq!(serde_json::to_value(&entry.parameters).unwrap(), json!({}));
}

#[tokio::test]
async fn update_rejects_missing_log() {
    let setup = setup(MockHttpClient::new());
    let error = setup
        .method
        .update(
            Uuid::new_v4().into(),
            did_keys(&setup),
            replacement_keys(&setup),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, DidMethodError::CouldNotUpdate(_)));
}

#[tokio::test]
async fn update_rejects_tampered_log() {
    let setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    let mut log: Value = serde_json::from_str(&created.log.unwrap()).unwrap();
    log["state"]["alsoKnownAs"] = json!(["https://attacker.example"]);
    let error = setup
        .method
        .update(
            id,
            did_keys(&setup),
            replacement_keys(&setup),
            Some(log.to_string()),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, DidMethodError::ResolutionError(_)));
}

#[tokio::test]
async fn update_rejects_deactivated_did() {
    let setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    let deactivated = setup
        .method
        .deactivate(id, did_keys(&setup), created.log)
        .await
        .unwrap();
    let error = setup
        .method
        .update(
            id,
            did_keys(&setup),
            replacement_keys(&setup),
            deactivated.log,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, DidMethodError::Deactivated));
}

#[tokio::test]
async fn update_rejects_missing_signing_keys() {
    let setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    let mut keys = did_keys(&setup);
    keys.update_keys = None;
    let error = setup
        .method
        .update(id, keys, replacement_keys(&setup), created.log)
        .await
        .unwrap_err();
    assert!(matches!(error, DidMethodError::CouldNotUpdate(_)));
}

#[tokio::test]
async fn update_rejects_unauthorized_signing_key() {
    let setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    let error = setup
        .method
        .update(
            id,
            replacement_keys(&setup),
            replacement_keys(&setup),
            created.log,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, DidMethodError::CouldNotUpdate(_)));
}

#[tokio::test]
async fn update_selects_authorized_signing_key() {
    let setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    let mut keys = did_keys(&setup);
    keys.update_keys = Some(vec![setup.new_update.clone(), setup.active.clone()]);
    let updated = update_after_previous_entry(
        &setup,
        id,
        keys,
        replacement_keys(&setup),
        created.log.unwrap(),
    )
    .await;
    setup
        .method
        .verify_log(&updated.log.unwrap(), Some(&created.did))
        .await
        .unwrap();
}

#[rstest::rstest]
#[case(0)]
#[case(2)]
#[tokio::test]
async fn update_rejects_invalid_update_key_count(#[case] count: usize) {
    let setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    let mut new_keys = replacement_keys(&setup);
    new_keys.update_keys = Some(vec![setup.new_update.clone(); count]);
    let error = setup
        .method
        .update(id, did_keys(&setup), new_keys, created.log)
        .await
        .unwrap_err();
    assert!(matches!(error, DidMethodError::CouldNotUpdate(_)));
}

#[tokio::test]
async fn update_rejects_missing_replacement_update_key() {
    let setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    let mut new_keys = replacement_keys(&setup);
    new_keys.update_keys = None;
    let error = setup
        .method
        .update(id, did_keys(&setup), new_keys, created.log)
        .await
        .unwrap_err();
    assert!(matches!(error, DidMethodError::CouldNotUpdate(_)));
}

#[tokio::test]
async fn update_rejects_non_eddsa_update_key() {
    let setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    let mut new_keys = replacement_keys(&setup);
    new_keys.update_keys = Some(vec![setup.new_document.clone()]);
    let error = setup
        .method
        .update(id, did_keys(&setup), new_keys, created.log)
        .await
        .unwrap_err();
    assert!(matches!(error, DidMethodError::UnsupportedKeyType(_)));
}

#[tokio::test]
async fn update_rejects_active_pre_rotation() {
    let setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    let committed = make_keyref(&setup.new_update, setup.method.key_provider.as_ref()).unwrap();
    let log = append_signed_update(
        &setup,
        &created.log.unwrap(),
        LogParameters {
            next_key_hashes: Some(vec![hash_update_key(&committed.multibase).unwrap()]),
            ..Default::default()
        },
        &setup.active,
    )
    .await;
    let error = setup
        .method
        .update(id, did_keys(&setup), replacement_keys(&setup), Some(log))
        .await
        .unwrap_err();
    assert!(
        matches!(error, DidMethodError::CouldNotUpdate(message) if message.contains("pre-rotation"))
    );
}

#[tokio::test]
async fn update_allows_exceeding_resolution_entry_limit() {
    let mut setup = setup(MockHttpClient::new());
    let id = Uuid::new_v4().into();
    let created = create_log(&setup, id).await;
    setup.method.params.max_did_log_entry_check = Some(25);
    let mut log = created.log.unwrap();
    for _ in 1..25 {
        log = update_after_previous_entry(&setup, id, did_keys(&setup), did_keys(&setup), log)
            .await
            .log
            .unwrap();
    }
    setup
        .method
        .verify_log(&log, Some(&created.did))
        .await
        .unwrap();
    // Updates continue even after crossing the configured resolution limit.
    for expected_entries in 26..=27 {
        log = update_after_previous_entry(&setup, id, did_keys(&setup), did_keys(&setup), log)
            .await
            .log
            .unwrap();
        assert_eq!(log.lines().count(), expected_entries);
        assert!(matches!(
            setup.method.verify_log(&log, Some(&created.did)).await,
            Err(DidMethodError::ResolutionError(message)) if message.contains("too many entries")
        ));
    }
    setup.method.params.max_did_log_entry_check = None;
    setup
        .method
        .verify_log(&log, Some(&created.did))
        .await
        .unwrap();
}
