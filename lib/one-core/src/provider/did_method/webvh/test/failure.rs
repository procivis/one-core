use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use similar_asserts::assert_eq;

use super::*;

#[tokio::test]
async fn rejects_failure_vectors() {
    let expected: HashMap<&str, &str> = HashMap::from([
        ("invalid_scid.jsonl", "SCID mismatch"),
        ("entry_hash_mismatch.jsonl", "Entry hash mismatch"),
        ("invalid_signature.jsonl", "Invalid log entry proof"),
        ("wrong_index.jsonl", "Invalid version number"),
        (
            "version_time_not_increasing.jsonl",
            "Invalid versionTime sequence",
        ),
        ("state_id_changed.jsonl", "DID portability is not supported"),
        (
            "portable_true_after_first_entry.jsonl",
            "Unsupported did:webvh parameter",
        ),
        ("witness_enabled.jsonl", "Unsupported did:webvh parameter"),
        ("watchers_enabled.jsonl", "Unsupported did:webvh parameter"),
        (
            "unsupported_method.jsonl",
            "Unsupported did:webvh parameter",
        ),
        ("ttl_out_of_range.jsonl", "Invalid ttl"),
        (
            "unauthorized_proof_key.jsonl",
            "Proof key is not an active update key",
        ),
        (
            "missing_prerotation_update_keys.jsonl",
            "Pre-rotation requires explicit updateKeys",
        ),
        (
            "missing_prerotation_next_key_hashes.jsonl",
            "Pre-rotation requires explicit nextKeyHashes",
        ),
        (
            "uncommitted_prerotation_key.jsonl",
            "Update key has no prior commitment",
        ),
        ("entry_after_deactivation.jsonl", "Entry after deactivation"),
    ]);
    let folder = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/provider/did_method/webvh/test/vectors/failure");
    let mut seen = HashSet::new();
    for path in fs::read_dir(folder).unwrap() {
        let path = path.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "jsonl") {
            continue;
        }
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(seen.insert(name.to_string()), "Duplicate vector: {name}");
        let log = fs::read_to_string(&path).unwrap();
        let first: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        let did: DidValue = first["state"]["id"].as_str().unwrap().parse().unwrap();
        let url = validate_did_parts(did.as_str()).unwrap().to_string();
        let mut client = MockHttpClient::new();
        mock_webvh_log_request(
            &mut client,
            url.clone(),
            Response {
                body: log.into_bytes(),
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
        let mut provider = MockDidMethodProvider::new();
        provider.expect_resolve().returning(|did| {
            let multibase = did.as_str().strip_prefix("did:key:").unwrap();
            Ok(did_key_document(&Eddsa.parse_multibase(multibase).unwrap()))
        });
        let mut setup = setup(client);
        setup.method.did_method_provider = Arc::new(provider);
        let error = setup.method.resolve(&did).await.expect_err(name);
        if name == "deactivated.jsonl" {
            assert!(
                matches!(error, DidMethodError::Deactivated),
                "{name}: {error}"
            );
        } else {
            let reason = expected.get(name).expect("Unexpected failure vector");
            assert!(
                error.to_string().contains(reason),
                "{name}: expected {reason}, got {error}"
            );
        }
    }
    assert_eq!(seen.len(), expected.len() + 1, "Missing failure vectors");
}
