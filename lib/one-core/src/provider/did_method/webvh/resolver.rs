use std::io::BufRead;

use itertools::Itertools;
use serde::de::IntoDeserializer;
use serde::Deserialize;
use shared_types::DidValue;
use time::OffsetDateTime;
use url::Url;

use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::model::DidDocument;
use crate::provider::http_client::HttpClient;

pub async fn resolve(
    did: &DidValue,
    client: &dyn HttpClient,
    use_http: bool,
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

    let entries: Vec<_> = resp
        .body
        .lines()
        .map(|line| {
            let line = line.map_err(|err| {
                DidMethodError::ResolutionError(format!("Invalid did log line: {err}"))
            })?;

            let entry: DidLogEntry = serde_json::from_str(&line).map_err(|err| {
                DidMethodError::ResolutionError(format!("Invalid did log entry: {err}"))
            })?;

            Ok(entry)
        })
        .collect::<Result<_, _>>()?;

    let Some(entry) = entries.into_iter().next_back() else {
        return Err(DidMethodError::ResolutionError(
            "Did log contains no entries".to_string(),
        ));
    };

    Ok(entry.state.value.document.into())
}

// https://identity.foundation/didwebvh/v0.3/#the-did-log-file
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidLogEntry {
    version_id: String,
    #[serde(with = "time::serde::iso8601")]
    version_time: OffsetDateTime,
    parameters: DidLogParameters,
    state: DidDocState,
    #[serde(default)]
    proof: Vec<VcdmProof>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct DidLogParameters {
    method: Option<DidMethodVersion>,
    prerotation: Option<bool>,
    portable: Option<bool>,
    #[serde(default)]
    update_keys: Vec<String>,
    #[serde(default)]
    next_key_hashes: Vec<String>,
    scid: Option<String>,
    #[serde(default)]
    witness: Vec<String>,
    deactivated: Option<bool>,
    ttl: Option<u32>,
}

#[derive(Debug, Deserialize, PartialEq, Clone, Copy)]
enum DidMethodVersion {
    #[serde(rename = "did:tdw:0.3")]
    V3,
}

#[derive(Debug, Deserialize)]
struct DidDocState {
    value: Document,
}

#[derive(Debug)]
struct Document {
    #[allow(dead_code)]
    source: json_syntax::Value,
    document: DidDocumentDTO,
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let source = json_syntax::Value::deserialize(deserializer)?;
        let document = DidDocumentDTO::deserialize(source.clone().into_deserializer())
            .map_err(serde::de::Error::custom)?;

        Ok(Self { source, document })
    }
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

    use serde_json::json;
    use time::macros::datetime;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::provider::http_client::reqwest_client::ReqwestClient;

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
                update_keys: vec![
                    "z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc"
                        .to_string()
                ],
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
        let did_log = include_str!("test_data/did.jsonl");

        let mock_server = MockServer::start().await;
        let address = mock_server.address().to_string().replace(":", "%3A");
        let did_webvh: DidValue =
            format!("did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:{address}")
                .parse()
                .unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/did.jsonl"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(did_log, "text/jsonl"))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        let client = ReqwestClient::default();

        let last_document = resolve(&did_webvh, &client, true).await.unwrap();

        assert_eq!(
            last_document,
            DidDocument {
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
        )
    }
}
