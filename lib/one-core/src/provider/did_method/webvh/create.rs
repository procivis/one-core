use common::update_version;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use shared_types::DidValue;
use time::OffsetDateTime;

use super::common::{
    CRYPTOSUITE, DidLogParameters, canonicalize_multihash_encode, multihash_b58_encode, now_utc,
};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::provider::did_method::dto::DidVerificationMethodDTO;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::webvh::common;
use crate::provider::did_method::webvh::deserialize::DidMethodVersion;
use crate::provider::did_method::webvh::serialize::{DidDocState, DidDocument, DidLogEntry};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_storage::provider::KeyProvider;

const SCID_PLACEHOLDER: &str = "{SCID}";
pub struct DidDocKeys {
    pub authentication: Vec<Key>,
    pub assertion_method: Vec<Key>,
    pub key_agreement: Vec<Key>,
    pub capability_invocation: Vec<Key>,
    pub capability_delegation: Vec<Key>,
}

pub struct UpdateKeys<'a> {
    pub active: &'a Key,
    pub next: &'a [Key],
}

#[derive(Default)]
struct Options {
    version_time: Option<OffsetDateTime>,
    proof_created: Option<OffsetDateTime>,
}

pub async fn create(
    domain: &str,
    did_doc_keys: DidDocKeys,
    update_keys: UpdateKeys<'_>,
    key_provider: &dyn KeyProvider,
) -> Result<(DidValue, String), DidMethodError> {
    create_with_options(
        domain,
        did_doc_keys,
        update_keys,
        key_provider,
        Options::default(),
    )
    .await
}

async fn create_with_options(
    domain: &str,
    did_doc_keys: DidDocKeys,
    update_keys: UpdateKeys<'_>,
    key_provider: &dyn KeyProvider,
    options: Options,
) -> Result<(DidValue, String), DidMethodError> {
    check_keys(&update_keys)?;
    let did_placeholder = format!("did:tdw:{SCID_PLACEHOLDER}:{domain}");
    let active_key = common::make_keyref(update_keys.active, key_provider)?;

    let prerotation = !update_keys.next.is_empty();
    let next_key_hashes = update_keys
        .next
        .iter()
        .map(|key| {
            let key_ref = common::make_keyref(key, key_provider)?;
            let hash = SHA256.hash(key_ref.multibase.as_bytes()).map_err(|err| {
                DidMethodError::CouldNotCreate(format!("Failed to hash next key: {err}"))
            })?;

            multihash_b58_encode(&hash)
                .map_err(|err| DidMethodError::CouldNotCreate(format!("{err:#}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let parameters = DidLogParameters {
        method: Some(DidMethodVersion::V3),
        prerotation: prerotation.then_some(prerotation),
        portable: None,
        update_keys: Some(vec![active_key.multibase.clone()]),
        next_key_hashes,
        scid: Some(SCID_PLACEHOLDER.to_owned()),
        witness: vec![],
        deactivated: None,
        ttl: None,
    };

    let did_doc = create_did_doc(did_placeholder, did_doc_keys, key_provider)?;
    let state = DidDocState { value: did_doc };
    let log = DidLogEntry {
        version_id: SCID_PLACEHOLDER.to_string(),
        version_time: options.version_time.unwrap_or(now_utc()),
        parameters,
        state,
        proof: vec![],
    };
    // replace {SCID} with it's value
    let scid = canonicalize_multihash_encode(&log)?;
    let mut log = replace_scid(log, scid)?;
    // update version field
    let entry_hash = canonicalize_multihash_encode(&log)?;
    update_version(&mut log, 1, &entry_hash);

    let proof = common::build_proof(
        &log,
        &active_key,
        options.proof_created.unwrap_or(now_utc()),
    )
    .await?;
    log.proof = vec![proof];

    let line = serde_json::to_string(&log).map_err(|err| {
        DidMethodError::CouldNotCreate(format!("Failed serializing did log: {err}"))
    })?;
    let did = log.state.value.id.parse().map_err(|err| {
        DidMethodError::CouldNotCreate(format!("Failed parsing webvh did as did value: {err:#}"))
    })?;

    Ok((did, line))
}

fn check_keys(keys: &UpdateKeys<'_>) -> Result<(), DidMethodError> {
    for key in std::iter::once(keys.active).chain(keys.next) {
        if key.key_type != KeyAlgorithmType::Eddsa.as_ref() {
            return Err(DidMethodError::CouldNotCreate(format!(
                "invalid key type `{}`. expected EDDSA key for cryptosuite {CRYPTOSUITE}",
                key.key_type,
            )));
        }
    }

    Ok(())
}

fn create_did_doc(
    did: String,
    did_doc_keys: DidDocKeys,
    key_provider: &dyn KeyProvider,
) -> Result<DidDocument, DidMethodError> {
    fn map_keys(
        did: String,
        keys: Vec<Key>,
        verification_methods: &mut Vec<DidVerificationMethodDTO>,
        key_provider: &dyn KeyProvider,
    ) -> Result<Vec<String>, DidMethodError> {
        let mut purpose = vec![];
        for key in keys {
            let key_ref = common::make_keyref(&key, key_provider)?;
            let verification_method_id = format!("{did}#key-{}", key.id);
            if !verification_methods
                .iter()
                .any(|vm| vm.id == verification_method_id)
            {
                let verification_method = create_verification_method(
                    verification_method_id.clone(),
                    did.clone(),
                    &key_ref.handle,
                )?;
                verification_methods.push(verification_method);
            }
            purpose.push(verification_method_id);
        }

        Ok(purpose)
    }

    let mut verification_methods: Vec<DidVerificationMethodDTO> = vec![];

    let authentication: Vec<String> = map_keys(
        did.clone(),
        did_doc_keys.authentication,
        &mut verification_methods,
        key_provider,
    )?;
    let assertion_method: Vec<String> = map_keys(
        did.clone(),
        did_doc_keys.assertion_method,
        &mut verification_methods,
        key_provider,
    )?;
    let key_agreement: Vec<String> = map_keys(
        did.clone(),
        did_doc_keys.key_agreement,
        &mut verification_methods,
        key_provider,
    )?;
    let capability_invocation: Vec<String> = map_keys(
        did.clone(),
        did_doc_keys.capability_invocation,
        &mut verification_methods,
        key_provider,
    )?;
    let capability_delegation: Vec<String> = map_keys(
        did.clone(),
        did_doc_keys.capability_delegation,
        &mut verification_methods,
        key_provider,
    )?;

    Ok(DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/jwk/v1".to_string(),
        ],
        id: did,
        verification_method: verification_methods,
        authentication,
        assertion_method,
        key_agreement,
        capability_invocation,
        capability_delegation,
    })
}

fn create_verification_method(
    id: String,
    did: String,
    key_handle: &KeyHandle,
) -> Result<DidVerificationMethodDTO, DidMethodError> {
    let public_key_jwk = key_handle.public_key_as_jwk().map_err(|err| {
        DidMethodError::CouldNotCreate(format!("Cannot convert PK to JWK: {err}"))
    })?;

    Ok(DidVerificationMethodDTO {
        id,
        r#type: "JsonWebKey2020".to_string(),
        controller: did,
        public_key_jwk: public_key_jwk.into(),
    })
}

fn replace_scid(mut entry: DidLogEntry, scid: String) -> Result<DidLogEntry, DidMethodError> {
    // replace {SCID} with it's value
    entry.version_id = scid.clone();

    {
        let did_doc = &mut entry.state.value;
        // replace in document id
        did_doc.id = did_doc
            .id
            .as_str()
            .replace(SCID_PLACEHOLDER, &scid)
            .parse()
            .map_err(|err| {
                DidMethodError::CouldNotCreate(format!(
                    "Invalid did:webvh after replacing SCID: {err}"
                ))
            })?;

        // replace verification id for each key role
        for v in did_doc
            .authentication
            .iter_mut()
            .chain(did_doc.assertion_method.iter_mut())
            .chain(did_doc.key_agreement.iter_mut())
            .chain(did_doc.capability_delegation.iter_mut())
            .chain(did_doc.capability_invocation.iter_mut())
        {
            *v = v.replace(SCID_PLACEHOLDER, &scid);
        }

        // replace verification id and controller in verification method
        for v in did_doc.verification_method.iter_mut() {
            v.id = v.id.replace(SCID_PLACEHOLDER, &scid);
            v.controller = v.controller.replace(SCID_PLACEHOLDER, &scid);
        }
    }

    entry.parameters.scid = Some(scid);

    Ok(entry)
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use secrecy::SecretSlice;
    use shared_types::KeyId;
    use similar_asserts::assert_eq;
    use time::format_description::well_known::Iso8601;

    use super::*;
    use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
    use crate::provider::did_method::provider::MockDidMethodProvider;
    use crate::provider::did_method::webvh::verification::verify_did_log;
    use crate::provider::did_method::webvh::{Params, deserialize};
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::key_algorithm::ecdsa::Ecdsa;
    use crate::provider::key_algorithm::eddsa::Eddsa;
    use crate::provider::key_storage::MockKeyStorage;
    use crate::provider::key_storage::provider::MockKeyProvider;

    #[tokio::test]
    async fn test_create_fails_for_non_eddsa_update_keys() {
        let update_keys = UpdateKeys {
            active: &make_key(
                "8586BC4B-0085-4976-B95D-F591B00DD067".parse().unwrap(),
                vec![],
                KeyAlgorithmType::Ecdsa,
            ),
            next: &[],
        };
        let did_doc_keys = DidDocKeys {
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
        };
        let provider = MockKeyProvider::new();
        assert!(
            create("test-domain", did_doc_keys, update_keys, &provider)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_create_did_webvh_ok() {
        let KeyProviderSetup {
            mock: key_provider,
            active_key_setup: (active_key, _),
            document_key,
            ..
        } = setup_key_provider();

        let did_doc_keys = DidDocKeys {
            authentication: vec![document_key.clone()],
            assertion_method: vec![document_key.clone()],
            key_agreement: vec![document_key.clone()],
            capability_invocation: vec![document_key.clone()],
            capability_delegation: vec![document_key],
        };
        let update_keys = UpdateKeys {
            active: &active_key,
            next: &[],
        };

        let options = Options {
            version_time: OffsetDateTime::parse("2024-07-29T17:00:27Z", &Iso8601::DATE_TIME_OFFSET)
                .ok(),
            proof_created: OffsetDateTime::parse(
                "2024-07-29T17:00:28Z",
                &Iso8601::DATE_TIME_OFFSET,
            )
            .ok(),
        };
        let (did, log) = create_with_options(
            "test-domain.com",
            did_doc_keys,
            update_keys,
            &key_provider,
            options,
        )
        .await
        .unwrap();

        assert_eq!(
            did.to_string(),
            "did:tdw:QmbbXWLTC8nCFRbZq9ZzGQLW9pbzWTvjX128beHDNQRgBA:test-domain.com"
        );

        let expected_log = include_str!("test_data/success/create_did_web_ok.jsonl");
        assert_eq!(log, expected_log);
    }

    #[tokio::test]
    async fn test_create_did_webvh_ok_only_authentication_assertion() {
        let KeyProviderSetup {
            mock: key_provider,
            active_key_setup: (active_key, _),
            document_key,
            ..
        } = setup_key_provider();

        let did_doc_keys = DidDocKeys {
            authentication: vec![document_key.clone()],
            assertion_method: vec![document_key.clone()],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
        };
        let update_keys = UpdateKeys {
            active: &active_key,
            next: &[],
        };

        let options = Options {
            version_time: OffsetDateTime::parse("2024-07-29T17:00:27Z", &Iso8601::DATE_TIME_OFFSET)
                .ok(),
            proof_created: OffsetDateTime::parse(
                "2024-07-29T17:00:28Z",
                &Iso8601::DATE_TIME_OFFSET,
            )
            .ok(),
        };
        let (did, log) = create_with_options(
            "test-domain.com",
            did_doc_keys,
            update_keys,
            &key_provider,
            options,
        )
        .await
        .unwrap();

        assert_eq!(
            did.to_string(),
            "did:tdw:QmQ6bD4CoN2o6FAxJyHFM2Xx22LKWK1Ux8Hru1k9Q9yTcW:test-domain.com"
        );

        let expected_log =
            include_str!("test_data/success/create_did_web_ok_only_authentication_assertion.jsonl");
        assert_eq!(log, expected_log);
    }

    #[tokio::test]
    async fn test_create_did_webvh_with_prerotation_enabled_ok() {
        let KeyProviderSetup {
            mock: key_provider,
            active_key_setup: (active_key, _),
            document_key,
            next_key,
        } = setup_key_provider();

        let did_doc_keys = DidDocKeys {
            authentication: vec![document_key.clone()],
            assertion_method: vec![document_key.clone()],
            key_agreement: vec![document_key.clone()],
            capability_invocation: vec![document_key.clone()],
            capability_delegation: vec![document_key],
        };
        let update_keys = UpdateKeys {
            active: &active_key,
            next: &[next_key],
        };

        let options = Options {
            version_time: OffsetDateTime::parse("2024-07-29T17:00:27Z", &Iso8601::DATE_TIME_OFFSET)
                .ok(),
            proof_created: OffsetDateTime::parse(
                "2024-07-29T17:00:28Z",
                &Iso8601::DATE_TIME_OFFSET,
            )
            .ok(),
        };
        let (did, log) = create_with_options(
            "test-domain.com",
            did_doc_keys,
            update_keys,
            &key_provider,
            options,
        )
        .await
        .unwrap();

        assert_eq!(
            did.to_string(),
            "did:tdw:QmRuwExX7ouarvGrEBb6UaajjmWRzVLFDnNYTzQNxsXJfj:test-domain.com"
        );

        let expected_log =
            include_str!("test_data/success/create_did_web_with_prerotation_enabled.jsonl");
        assert_eq!(log, expected_log);
    }

    #[tokio::test]
    async fn test_create_then_verify() {
        let KeyProviderSetup {
            mock: key_provider,
            active_key_setup: (active_key, active_key_handle),
            document_key,
            ..
        } = setup_key_provider();

        let did_doc_keys = DidDocKeys {
            authentication: vec![document_key.clone()],
            assertion_method: vec![document_key.clone()],
            key_agreement: vec![document_key.clone()],
            capability_invocation: vec![document_key.clone()],
            capability_delegation: vec![document_key],
        };
        let update_keys = UpdateKeys {
            active: &active_key,
            next: &[],
        };

        let (_did, log) = create("test-domain.ch", did_doc_keys, update_keys, &key_provider)
            .await
            .unwrap();
        let entry: deserialize::DidLogEntry = serde_json::from_str(&log).unwrap();

        let mut did_method_provider = MockDidMethodProvider::new();
        let public_key_jwk = active_key_handle.public_key_as_jwk().unwrap();
        did_method_provider.expect_resolve().once().returning(
            move |_| {
            let doc = DidDocument {
                context: serde_json::Value::Null,
                id: "did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV"
                    .parse()
                    .unwrap(),
                verification_method: vec![
                    DidVerificationMethod {
                        id: "did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV".to_string(), 
                        r#type: "JsonWebKey2020".to_string(), 
                        controller: "did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV".to_string(),
                        public_key_jwk: public_key_jwk.clone(),
                    }
                ],
                authentication: Some(vec!["did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV".to_string()]),
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            };

            Ok(doc)
        });

        assert2::assert!(let Ok(()) = verify_did_log(&[(entry, log)], &did_method_provider, &Params::default()).await);
    }

    #[track_caller]
    fn make_key_handle(pk: &[u8], sk: Vec<u8>, key_alg: &dyn KeyAlgorithm) -> KeyHandle {
        let sk = SecretSlice::from(sk.to_vec());
        key_alg.reconstruct_key(pk, Some(sk), None).unwrap()
    }

    fn make_key(id: KeyId, public_key: Vec<u8>, key_type: KeyAlgorithmType) -> Key {
        Key {
            id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key,
            name: "test-key".to_string(),
            key_reference: vec![],
            storage_type: "INTERNAL".to_string(),
            key_type: key_type.to_string(),
            organisation: None,
        }
    }

    struct KeyProviderSetup {
        mock: MockKeyProvider,
        active_key_setup: (Key, KeyHandle),
        next_key: Key,
        document_key: Key,
    }

    #[track_caller]
    fn setup_key_provider() -> KeyProviderSetup {
        let active_key_handle = make_key_handle(
            &hex_literal::hex!("14bb5dd69734a472b6693fd947a579d9b714f49a771dc1a0933bbc823aed6a80"),
            hex_literal::hex!("a3f88f2bc284a8f1ff94d30c83a8b42a4155c4c38da501183731cbf977b3c3e914bb5dd69734a472b6693fd947a579d9b714f49a771dc1a0933bbc823aed6a80").to_vec(),
            &Eddsa,
        );
        let active_key_id = uuid::uuid!("577B894A-D37C-4415-ACB0-43237F962BE4").into();
        let active_key = make_key(
            active_key_id,
            active_key_handle.public_key_as_raw(),
            KeyAlgorithmType::Eddsa,
        );

        let next_key_handle = make_key_handle(
            &hex_literal::hex!("5fdef8f02b852787f802c4f53d04c48183ef5b766d5e6f3d28ff10204b0cd61c"),
            hex_literal::hex!("2d922fd47cda6d5adb72c9d33b63153adf38ee05980da13ce1878704e9f410a55fdef8f02b852787f802c4f53d04c48183ef5b766d5e6f3d28ff10204b0cd61c").to_vec(),
            &Eddsa,
        );
        let next_key_kid = uuid::uuid!("3497ED3D-4BA8-4273-84D0-D2AB60603999").into();
        let next_key = make_key(
            next_key_kid,
            next_key_handle.public_key_as_raw(),
            KeyAlgorithmType::Eddsa,
        );

        let did_doc_key_handle = make_key_handle(
            &hex_literal::hex!(
                "04a51f0f7f0bc35c44a0a84df7e38f62214ba3e91fbc87c40b1d983f4fbbe1614ebbe45135d3213c2c2ef52897710f719a890bae812add735f55418eb0585e1d44"
            ),
            hex_literal::hex!("cddd4dcf9de47ee105b1f6058f04ba88d2327d977511568eb52f9f2c93652574")
                .to_vec(),
            &Ecdsa,
        );
        let did_doc_key_kid = uuid::uuid!("763E6AEA-B0AE-43F5-A54A-0D4CBADC2C6F").into();
        let did_doc_key = make_key(
            did_doc_key_kid,
            did_doc_key_handle.public_key_as_raw(),
            KeyAlgorithmType::Ecdsa,
        );

        let mut key_storage = MockKeyStorage::new();
        key_storage
            .expect_key_handle()
            .withf(move |key| key.id == active_key_id)
            .returning({
                let key_handle = active_key_handle.clone();
                move |_| Ok(key_handle.clone())
            });
        key_storage
            .expect_key_handle()
            .withf(move |key| key.id == next_key_kid)
            .returning(move |_| Ok(next_key_handle.clone()));
        key_storage
            .expect_key_handle()
            .withf(move |key| key.id == did_doc_key_kid)
            .returning(move |_| Ok(did_doc_key_handle.clone()));

        let mut key_provider = MockKeyProvider::new();
        let key_storage = Arc::new(key_storage);
        key_provider
            .expect_get_key_storage()
            .returning(move |_| Some(key_storage.clone()));

        KeyProviderSetup {
            mock: key_provider,
            active_key_setup: (active_key, active_key_handle),
            next_key,
            document_key: did_doc_key,
        }
    }
}
