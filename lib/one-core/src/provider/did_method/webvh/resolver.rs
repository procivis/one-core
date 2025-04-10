use std::io::BufRead;

use itertools::Itertools;
use shared_types::DidValue;
use url::Url;

use super::common::DidLogEntry;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::model::DidDocument;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::did_method::webvh::verification::verify_did_log;
use crate::provider::did_method::webvh::Params;
use crate::provider::http_client::HttpClient;

pub async fn resolve(
    did: &DidValue,
    client: &dyn HttpClient,
    did_method_provider: &dyn DidMethodProvider,
    use_http: bool,
    params: &Params,
) -> Result<DidDocument, DidMethodError> {
    let TransformedDid { mut url, .. } = transform_did_to_https(did.as_str())?;
    if use_http {
        url.set_scheme("http").expect("http is a valid scheme");
    }

    let resp = client
        .get(url.as_str())
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|err| {
            DidMethodError::ResolutionError(format!("Failed resolving did:webvh: {err}"))
        })?;

    let lines = resp.body.lines().peekable();
    let entries: Vec<_> = lines
        .map(|line| {
            let line = line.map_err(|err| {
                DidMethodError::ResolutionError(format!("Invalid did log line: {err}"))
            })?;

            let entry: DidLogEntry = serde_json::from_str(&line).map_err(|err| {
                DidMethodError::ResolutionError(format!("Invalid did log entry: {err}"))
            })?;

            Ok((entry, line))
        })
        .collect::<Result<_, _>>()?;

    verify_did_log(&entries, did_method_provider, params).await?;

    let Some((entry, _)) = entries.into_iter().next_back() else {
        return Err(DidMethodError::ResolutionError(
            "Did log contains no entries".to_string(),
        ));
    };

    Ok(entry.state.value.document.into())
}

struct TransformedDid<'a> {
    #[allow(dead_code)]
    scid: &'a str,
    url: Url,
}

// https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation
fn transform_did_to_https(did: &str) -> Result<TransformedDid, DidMethodError> {
    const METHOD_PREFIX: &str = "did:tdw:";

    let Some(did_suffix) = did.strip_prefix(METHOD_PREFIX) else {
        return Err(DidMethodError::ResolutionError(format!(
            "Invalid did value. Expected `{METHOD_PREFIX}` prefix",
        )));
    };

    let mut parts = did_suffix.split(':');

    // scid
    let Some(scid) = parts.next() else {
        return Err(DidMethodError::ResolutionError(
            "Invalid did:webvh. missing `scid`".to_string(),
        ));
    };

    // domain segment
    let Some(domain) = parts.next() else {
        return Err(DidMethodError::ResolutionError(
            "Invalid did:webvh. missing domain segment".to_string(),
        ));
    };
    // percent decode the domain segment in case there's a port
    let domain = domain.replacen("%3A", ":", 1);

    let mut url: Url = format!("https://{domain}").parse().map_err(|err| {
        DidMethodError::ResolutionError(format!("Invalid did:webh domain part: {err}"))
    })?;

    // append /did.jsonl to the path segment
    let mut path = parts.join("/");
    if path.is_empty() {
        path = ".well-known/did.jsonl".to_string();
    } else {
        path.push_str("/did.jsonl");
    }

    url.set_path(&path);

    Ok(TransformedDid { scid, url })
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::fs;
    use std::fs::{File, ReadDir};
    use std::io::Read;
    use std::sync::Arc;

    use indexmap::IndexMap;
    use maplit::hashmap;
    use serde_json::json;
    use serde_json_path::JsonPath;
    use time::macros::datetime;
    use time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::config::core_config::KeyAlgorithmType;
    use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
    use crate::provider::credential_formatter::vcdm::VcdmProof;
    use crate::provider::did_method::dto::DidDocumentDTO;
    use crate::provider::did_method::error::DidMethodError::ResolutionError;
    use crate::provider::did_method::jwk::JWKDidMethod;
    use crate::provider::did_method::key::KeyDidMethod;
    use crate::provider::did_method::keys::Keys;
    use crate::provider::did_method::model::DidVerificationMethod;
    use crate::provider::did_method::provider::DidMethodProviderImpl;
    use crate::provider::did_method::resolver::DidCachingLoader;
    use crate::provider::did_method::webvh::common::{DidLogParameters, DidMethodVersion};
    use crate::provider::did_method::DidMethod;
    use crate::provider::http_client::reqwest_client::ReqwestClient;
    use crate::provider::key_algorithm::eddsa::Eddsa;
    use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
    use crate::provider::remote_entity_storage::RemoteEntityType;

    #[test]
    fn test_transform_did_webvh_to_https() {
        for (did, expected) in [
            (
                "did:tdw:{SCID}:example.com",
                "https://example.com/.well-known/did.jsonl",
            ),
            (
                "did:tdw:{SCID}:issuer.example.com",
                "https://issuer.example.com/.well-known/did.jsonl",
            ),
            (
                "did:tdw:{SCID}:example.com:dids:issuer",
                "https://example.com/dids/issuer/did.jsonl",
            ),
            (
                "did:tdw:{SCID}:example.com%3A3000:dids:issuer",
                "https://example.com:3000/dids/issuer/did.jsonl",
            ),
        ] {
            let TransformedDid { url, scid } = transform_did_to_https(did).unwrap();
            assert_eq!(url.as_str(), expected);
            assert_eq!(scid, "{SCID}");
        }
    }

    #[test]
    fn test_deserialize_did_log_entry() {
        let line = r#"[
                "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ",
                "2024-07-29T17:00:27Z",
                { "prerotation":true,
                  "updateKeys": ["z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"],
                  "nextKeyHashes": ["QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv"],
                  "method":"did:tdw:0.3",
                  "scid":"Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu"
                },
                { "value": {
                    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
                    "id": "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:domain.example"
                  }
                },
                [{
                    "type":"DataIntegrityProof",
                    "cryptosuite":"eddsa-jcs-2022",
                    "verificationMethod":"did:key:z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc#z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc",
                    "created": "2024-07-29T17:00:27Z",
                    "proofPurpose": "authentication",
                    "challenge": "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ",
                    "proofValue":"zDk24L4vbVrFm5CPQjRD9KoGFNcV6C3ub1ducPQEvDQ39U68GiofAndGbdG9azV6r78gHr1wKnKNPbMz87xtjZtcq9iwN5hjLptM9Lax4UeMWm9Xz7PP4crToj7sZnvyb3x4"
                }]
            ]"#;

        let entry: DidLogEntry = serde_json::from_str(line).unwrap();

        assert_eq!(
            entry.version_id,
            "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ"
        );
        assert_eq!(entry.version_time, datetime!(2024-07-29 17:00:27 UTC));
        assert_eq!(
            entry.parameters,
            DidLogParameters {
                method: Some(DidMethodVersion::V3),
                prerotation: Some(true),
                update_keys: Some(vec![
                    "z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"
                        .to_string()
                ]),
                next_key_hashes: vec!["QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv".to_string()],
                scid: Some("Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu".to_string()),
                witness: vec![],
                portable: None,
                deactivated: None,
                ttl: None
            }
        );
        assert_eq!(
            entry.state.value.document,
            DidDocumentDTO {
                context: json!([
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/multikey/v1"
                ]),
                id: "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:domain.example"
                    .parse()
                    .unwrap(),
                verification_method: vec![],
                authentication: None,
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            }
        );
        assert_eq!(
            entry.proof,
            vec![
                VcdmProof {
                    context: None,
                    r#type: "DataIntegrityProof".to_string(),
                    cryptosuite: "eddsa-jcs-2022".to_string(),
                    verification_method: "did:key:z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc#z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc".to_string(),
                    created: Some(datetime!(2024-07-29 17:00:27 UTC)),
                    proof_purpose: "authentication".to_string(),
                    challenge: Some("1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ".to_string()),
                    proof_value: Some("zDk24L4vbVrFm5CPQjRD9KoGFNcV6C3ub1ducPQEvDQ39U68GiofAndGbdG9azV6r78gHr1wKnKNPbMz87xtjZtcq9iwN5hjLptM9Lax4UeMWm9Xz7PP4crToj7sZnvyb3x4".to_string()),
                    nonce: None,
                    domain: None,
                }
            ]
        );
    }

    #[tokio::test]
    async fn test_didwebvh_resolver_returns_last_document() {
        let did_method_provider = test_did_method_provider();

        let did_log = include_str!("test_data/success/did_long_log.jsonl");
        let did: DidValue = "did:tdw:QmRXEKqsStiagD4DBZG1gwrtpoNfxSUwHd8vxQMBytR5zW:example.com"
            .parse()
            .unwrap();

        let mock_server = MockServer::start().await;
        // adjust port for the resolution using the mock server
        let address = mock_server.address().to_string().replace(":", "%3A");
        let did_dynamic_port: DidValue =
            format!("did:tdw:QmRXEKqsStiagD4DBZG1gwrtpoNfxSUwHd8vxQMBytR5zW:{address}")
                .parse()
                .unwrap();
        Mock::given(method("GET"))
            .and(path("/.well-known/did.jsonl"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(did_log, "text/jsonl"))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        let client = ReqwestClient::default();

        let document = resolve(
            &did_dynamic_port,
            &client,
            &did_method_provider,
            true,
            &Default::default(),
        )
        .await
        .unwrap();

        let verification_method_1 = DidVerificationMethod {
            id: format!("{did}#auth-key-01"),
            r#type: "JsonWebKey2020".to_string(),
            controller: did.to_string(),
            public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                r#use: None,
                kid: Some("auth-key-01".to_string()),
                crv: "P-256".to_string(),
                x: "GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs".to_string(),
                y: Some("l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ".to_string()),
            }),
        };
        assert_eq!(
            document,
            DidDocument {
                context: json!([
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/jwk/v1"
                ]),
                id: did.clone(),
                verification_method: vec![verification_method_1],
                authentication: Some(vec![format!("{did}#auth-key-01")]),
                assertion_method: Some(vec![format!("{did}#auth-key-01")]),
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            }
        )
    }

    #[tokio::test]
    async fn test_didwebvh_resolver_fail_too_many_entries() {
        let did_method_provider = test_did_method_provider();

        let did_log = include_str!("test_data/success/did_long_log.jsonl");
        let mock_server = MockServer::start().await;
        // adjust port for the resolution using the mock server
        let address = mock_server.address().to_string().replace(":", "%3A");
        let did_dynamic_port: DidValue =
            format!("did:tdw:QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A:{address}")
                .parse()
                .unwrap();
        Mock::given(method("GET"))
            .and(path("/.well-known/did.jsonl"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(did_log, "text/jsonl"))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        let client = ReqwestClient::default();

        let document = resolve(
            &did_dynamic_port,
            &client,
            &did_method_provider,
            true,
            &Params {
                keys: Keys::default(),
                max_did_log_entry_check: Some(2),
                resolve_to_insecure_http: false,
            },
        )
        .await;
        assert!(matches!(document, Err(ResolutionError(_))));
    }

    /// Test that runs through the files in the success test data folder and checks everything resolves.
    ///
    /// Note, the following keys were used to sign the entries:
    /// - Key1
    ///     - public key bytes: 0x14bb5dd69734a472b6693fd947a579d9b714f49a771dc1a0933bbc823aed6a80, multibase: z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV
    ///     - private key bytes: 0xa3f88f2bc284a8f1ff94d30c83a8b42a4155c4c38da501183731cbf977b3c3e914bb5dd69734a472b6693fd947a579d9b714f49a771dc1a0933bbc823aed6a80
    /// - Key2
    ///     - public key bytes: 0x5fdef8f02b852787f802c4f53d04c48183ef5b766d5e6f3d28ff10204b0cd61c, multibase: z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH
    ///     - private key bytes: 0x2d922fd47cda6d5adb72c9d33b63153adf38ee05980da13ce1878704e9f410a55fdef8f02b852787f802c4f53d04c48183ef5b766d5e6f3d28ff10204b0cd61c
    #[tokio::test]
    async fn test_didwebvh_success() {
        let folder = fs::read_dir("src/provider/did_method/webvh/test_data/success").unwrap();
        resolve_log_files(folder, |result, file_name| {
            assert!(
                result.is_ok(),
                "Failed resolving did! Did log file: {}, result: {:#?}",
                file_name,
                result
            )
        })
        .await;
    }

    #[tokio::test]
    async fn test_didwebvh_failure() {
        let expected_error_messages = hashmap! {
            "entry_hash_mismatch.jsonl" => "Entry hash mismatch, expected QmQikVGn3cLzaQ8PwqS4KNXtrfCr9Rbf5kTz9ayWXDAZZo, got QmVdZgk73vwTHX7wbNd7bd6jcMZeae88gxCuNqwMTT6PCQ.",
            "invalid_proof_verification_method_key.jsonl" => "Proof verification failed: verification method did:key:z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH#z6MkkuVyV9TbCGwhoJyJfhsFwFZjJ1833oWYtbh5mXGZxDTH is not allowed update_key",
            "wrong_index.jsonl" => "Unexpected versionId '1-QmUcfiZ4jTAYXuMjo4Fxoi3BHP2fjyZVeXCyugYYgdA4hW', expected index 2, got 1.",
            "invalid_sig.jsonl" => "Failed to verify integrity proof for log entry 1-QmQ5sMLi5vKyHhdaL1LaD3b2C1JY2rCckr2uyGN9KyxMy2: Invalid signature",
            "invalid_scid.jsonl" => "Invalid SCID: expected QmRXEKqsStiagD4DBZG1gwrtpoNfxSUwHd8vxQMBytR5zY, got QmRXEKqsStiagD4DBZG1gwrtpoNfxSUwHd8vxQMBytR5zW",
            "proof_too_old.jsonl" => "Invalid proof: created time is before entry time.",
            "portable_true_after_first_entry.jsonl" => "portable flag can only be set to true in first entry",
            "entry_timestamp_too_old.jsonl" => "Invalid log entry 2-QmaidiuDMxyJc8rXAVv8QEY3k4yj96rTW1mzJjxagpNMTF: version time 2025-03-24 16:27:36.0 +00:00:00 is before version time of the previous entry",
            "challenge_mismatch.jsonl" => "Proof challenge mismatch, expected 2-QmUcfiZ4jTAYXuMjo4Fxoi3BHP2fjyZVeXCyugYYgdA4hW, got 1-QmUcfiZ4jTAYXuMjo4Fxoi3BHP2fjyZVeXCyugYYgdA4hW.",
            "invalid_update_key_for_prerotation.jsonl" => "Update key z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV not found in nextKeyHashes",
        };
        let folder = fs::read_dir("src/provider/did_method/webvh/test_data/failure").unwrap();
        resolve_log_files(folder, |result, file_name| {
            assert2::let_assert!(
                Err(ResolutionError(msg)) = result,
                "Failed resolving did! Did log file: {file_name}"
            );
            let expected_msg = *expected_error_messages.get(&file_name as &str).unwrap();
            assert_eq!(msg, expected_msg, "Failed for file: {file_name}");
        })
        .await;
    }

    async fn resolve_log_files<T: Fn(Result<DidDocument, DidMethodError>, String)>(
        paths: ReadDir,
        check: T,
    ) {
        let did_matcher = JsonPath::parse("$[3].value.id").unwrap();
        let mock_server = MockServer::start().await;
        // adjust port for the resolution using the mock server
        let address = mock_server.address().to_string().replace(":", "%3A");

        let client = ReqwestClient::default();
        let did_method_provider = test_did_method_provider();

        for path in paths {
            let path_buf = path.unwrap().path();
            let mut file = File::open(path_buf.clone()).unwrap();
            let mut did_log = String::new();
            file.read_to_string(&mut did_log).unwrap();

            let did = did_matcher
                .query(&serde_json::from_str(did_log.lines().next().unwrap()).unwrap())
                .first()
                .unwrap()
                .to_string()
                .replace("\"", "");

            Mock::given(method("GET"))
                .and(wiremock::matchers::path("/.well-known/did.jsonl"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(did_log, "text/jsonl"))
                .up_to_n_times(1)
                .mount(&mock_server)
                .await;

            let did_dynamic_port = format!("{}:{address}", did.rsplit_once(":").unwrap().0)
                .parse()
                .unwrap();
            let result = resolve(
                &did_dynamic_port,
                &client,
                &did_method_provider,
                true,
                &Default::default(),
            )
            .await;

            check(
                result,
                path_buf.file_name().unwrap().to_str().unwrap().to_string(),
            );
        }
    }

    fn test_did_method_provider() -> DidMethodProviderImpl {
        let caching_loader = DidCachingLoader::new(
            RemoteEntityType::DidDocument,
            Arc::new(InMemoryStorage::new(HashMap::new())),
            100,
            Duration::minutes(1),
            Duration::minutes(1),
        );
        let key_algorithm_provider =
            Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter(vec![(
                KeyAlgorithmType::Eddsa,
                Arc::new(Eddsa) as Arc<dyn KeyAlgorithm>,
            )])));
        DidMethodProviderImpl::new(
            caching_loader,
            IndexMap::from_iter(vec![
                (
                    "JWK".to_owned(),
                    Arc::new(JWKDidMethod::new(key_algorithm_provider.clone()))
                        as Arc<dyn DidMethod>,
                ),
                (
                    "KEY".to_owned(),
                    Arc::new(KeyDidMethod::new(key_algorithm_provider)) as Arc<dyn DidMethod>,
                ),
            ]),
        )
    }
}
