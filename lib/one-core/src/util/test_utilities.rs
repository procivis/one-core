use std::collections::HashMap;
use std::sync::Arc;

use mockall::predicate::{always, eq};
use time::{Duration, OffsetDateTime};

use crate::provider::credential_formatter::json_ld::context::caching_loader::JsonLdCachingLoader;
use crate::provider::http_client::{Method, MockHttpClient, RequestBuilder, Response};
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntity, RemoteEntityType};

pub fn mock_http_get_request(http_client: &mut MockHttpClient, url: String, response: Response) {
    let mut new_client = MockHttpClient::new();
    new_client
        .expect_send()
        .with(eq(url.clone()), always(), always(), eq(Method::Get))
        .return_once(move |_, _, _, _| Ok(response));

    http_client
        .expect_get()
        .with(eq(url))
        .return_once(move |url| RequestBuilder::new(Arc::new(new_client), Method::Get, url));
}

pub fn prepare_caching_loader(additional: Option<(&str, &str)>) -> JsonLdCachingLoader {
    let mut contexts = vec![
        (
            "https://www.w3.org/ns/credentials/v2".to_string(),
            RemoteEntity {
                last_modified: OffsetDateTime::now_utc(),
                entity_type: RemoteEntityType::JsonLdContext,
                key: "https://www.w3.org/ns/credentials/v2".to_string(),
                value: W3_ORG_NS_CREDENTIALS_V2.to_string().into_bytes(),
                hit_counter: 0,
                media_type: None,
                persistent: false,
            },
        ),
        (
            "https://www.w3.org/ns/credentials/examples/v2".to_string(),
            RemoteEntity {
                last_modified: OffsetDateTime::now_utc(),
                entity_type: RemoteEntityType::JsonLdContext,
                key: "https://www.w3.org/ns/credentials/examples/v2".to_string(),
                value: W3_ORG_NS_CREDENTIALS_EXAMPLES_V2.to_string().into_bytes(),
                hit_counter: 0,
                media_type: None,
                persistent: false,
            },
        ),
    ];

    if let Some((id, content)) = additional {
        contexts.push((
            id.to_string(),
            RemoteEntity {
                last_modified: OffsetDateTime::now_utc(),
                entity_type: RemoteEntityType::JsonLdContext,
                key: id.to_string(),
                value: content.to_string().into_bytes(),
                hit_counter: 0,
                media_type: None,
                persistent: false,
            },
        ))
    }

    JsonLdCachingLoader::new(
        RemoteEntityType::JsonLdContext,
        Arc::new(InMemoryStorage::new(HashMap::from_iter(contexts))),
        10000,
        Duration::seconds(999999),
        Duration::seconds(300),
    )
}

const W3_ORG_NS_CREDENTIALS_EXAMPLES_V2: &str = r#"{
  "@context": {
    "@vocab": "https://www.w3.org/ns/credentials/examples#"
  }
}"#;

const W3_ORG_NS_CREDENTIALS_V2: &str = r#"{
  "@context": {
    "@protected": true,
    "@vocab": "https://www.w3.org/ns/credentials/issuer-dependent#",
    "id": "@id",
    "type": "@type",
    "kid": {
      "@id": "https://www.iana.org/assignments/jose#kid",
      "@type": "@id"
    },
    "iss": {
      "@id": "https://www.iana.org/assignments/jose#iss",
      "@type": "@id"
    },
    "sub": {
      "@id": "https://www.iana.org/assignments/jose#sub",
      "@type": "@id"
    },
    "jku": {
      "@id": "https://www.iana.org/assignments/jose#jku",
      "@type": "@id"
    },
    "x5u": {
      "@id": "https://www.iana.org/assignments/jose#x5u",
      "@type": "@id"
    },
    "aud": {
      "@id": "https://www.iana.org/assignments/jwt#aud",
      "@type": "@id"
    },
    "exp": {
      "@id": "https://www.iana.org/assignments/jwt#exp",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "nbf": {
      "@id": "https://www.iana.org/assignments/jwt#nbf",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "iat": {
      "@id": "https://www.iana.org/assignments/jwt#iat",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "cnf": {
      "@id": "https://www.iana.org/assignments/jwt#cnf",
      "@context": {
        "@protected": true,
        "kid": {
          "@id": "https://www.iana.org/assignments/jwt#kid",
          "@type": "@id"
        },
        "jwk": {
          "@id": "https://www.iana.org/assignments/jwt#jwk",
          "@type": "@json"
        }
      }
    },
    "_sd_alg": {
      "@id": "https://www.iana.org/assignments/jwt#_sd_alg"
    },
    "_sd": {
      "@id": "https://www.iana.org/assignments/jwt#_sd"
    },
    "...": {
      "@id": "https://www.iana.org/assignments/jwt#..."
    },
    "digestSRI": {
      "@id": "https://www.w3.org/2018/credentials#digestSRI",
      "@type": "https://www.w3.org/2018/credentials#sriString"
    },
    "digestMultibase": {
      "@id": "https://w3id.org/security#digestMultibase",
      "@type": "https://w3id.org/security#multibase"
    },
    "mediaType": {
      "@id": "https://schema.org/encodingFormat"
    },
    "description": "https://schema.org/description",
    "name": "https://schema.org/name",
    "EnvelopedVerifiableCredential": "https://www.w3.org/2018/credentials#EnvelopedVerifiableCredential",
    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "credentialSchema": {
          "@id": "https://www.w3.org/2018/credentials#credentialSchema",
          "@type": "@id"
        },
        "credentialStatus": {
          "@id": "https://www.w3.org/2018/credentials#credentialStatus",
          "@type": "@id"
        },
        "credentialSubject": {
          "@id": "https://www.w3.org/2018/credentials#credentialSubject",
          "@type": "@id"
        },
        "description": "https://schema.org/description",
        "evidence": {
          "@id": "https://www.w3.org/2018/credentials#evidence",
          "@type": "@id"
        },
        "validFrom": {
          "@id": "https://www.w3.org/2018/credentials#validFrom",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "validUntil": {
          "@id": "https://www.w3.org/2018/credentials#validUntil",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "issuer": {
          "@id": "https://www.w3.org/2018/credentials#issuer",
          "@type": "@id"
        },
        "name": "https://schema.org/name",
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@type": "@id",
          "@container": "@graph"
        },
        "refreshService": {
          "@id": "https://www.w3.org/2018/credentials#refreshService",
          "@type": "@id"
        },
        "termsOfUse": {
          "@id": "https://www.w3.org/2018/credentials#termsOfUse",
          "@type": "@id"
        },
        "confidenceMethod": {
          "@id": "https://www.w3.org/2018/credentials#confidenceMethod",
          "@type": "@id"
        },
        "relatedResource": {
          "@id": "https://www.w3.org/2018/credentials#relatedResource",
          "@type": "@id"
        }
      }
    },
    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "holder": {
          "@id": "https://www.w3.org/2018/credentials#holder",
          "@type": "@id"
        },
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@type": "@id",
          "@container": "@graph"
        },
        "verifiableCredential": {
          "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
          "@type": "@id",
          "@container": "@graph",
          "@context": null
        },
        "termsOfUse": {
          "@id": "https://www.w3.org/2018/credentials#termsOfUse",
          "@type": "@id"
        }
      }
    },
    "JsonSchemaCredential": "https://www.w3.org/2018/credentials#JsonSchemaCredential",
    "JsonSchema": {
      "@id": "https://www.w3.org/2018/credentials#JsonSchema",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "jsonSchema": {
          "@id": "https://w3.org/2018/credentials#jsonSchema",
          "@type": "@json"
        }
      }
    },
    "BitstringStatusListCredential": "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential",
    "BitstringStatusList": {
      "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusList",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
        "encodedList": {
          "@id": "https://www.w3.org/ns/credentials/status#encodedList",
          "@type": "https://w3id.org/security#multibase"
        },
        "ttl": "https://www.w3.org/ns/credentials/status#ttl",
        "statusReference": {
          "@id": "https://www.w3.org/ns/credentials/status#statusReference",
          "@type": "@id"
        },
        "statusSize": {
          "@id": "https://www.w3.org/ns/credentials/status#statusSize",
          "@type": "https://www.w3.org/2001/XMLSchema#positiveInteger"
        },
        "statusMessage": {
          "@id": "https://www.w3.org/ns/credentials/status#statusMessage",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "status": "https://www.w3.org/ns/credentials/status#status",
            "message": "https://www.w3.org/ns/credentials/status#message"
          }
        }
      }
    },
    "BitstringStatusListEntry": {
      "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
        "statusListIndex": "https://www.w3.org/ns/credentials/status#statusListIndex",
        "statusListCredential": {
          "@id": "https://www.w3.org/ns/credentials/status#statusListCredential",
          "@type": "@id"
        }
      }
    },
    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "previousProof": {
          "@id": "https://w3id.org/security#previousProof",
          "@type": "@id"
        },
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "cryptosuite": {
          "@id": "https://w3id.org/security#cryptosuite",
          "@type": "https://w3id.org/security#cryptosuiteString"
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}"#;
