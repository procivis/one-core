use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    ExchangeProtocolError, ExchangeProtocolImpl, FormatMapper, ProcivisTemp, TypeToDescriptorMapper,
};
use crate::common_mapper::get_encryption_key_jwk_from_proof;
use crate::model::credential::{Credential, CredentialRole};
use crate::model::did::{Did, KeyRole, RelatedKey};
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::proof::Proof;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::exchange_protocol::openid4vc::mapper::{
    create_format_map, create_open_id_for_vp_formats,
};
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::service::test_utilities::{dummy_did, dummy_key, generic_config};

#[derive(Default)]
struct Repositories {
    pub formatter_provider: MockCredentialFormatterProvider,
    pub key_provider: MockKeyProvider,
}

fn setup_protocol(base_url: Option<String>, repositories: Repositories) -> ProcivisTemp {
    ProcivisTemp::new(
        base_url,
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.key_provider),
        Arc::new(generic_config().core),
        Arc::new(ReqwestClient::default()),
    )
}

fn generate_credential(redirect_uri: Option<String>) -> Credential {
    Credential {
        id: Uuid::default().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: vec![],
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri,
        role: CredentialRole::Issuer,
        state: None,
        claims: None,
        issuer_did: None,
        holder_did: None,
        schema: None,
        interaction: None,
        key: None,
        revocation_list: None,
    }
}

fn generate_proof(redirect_uri: Option<String>) -> Proof {
    Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri,
        state: None,
        schema: None,
        claims: None,
        verifier_did: None,
        holder_did: None,
        verifier_key: None,
        interaction: None,
    }
}

#[tokio::test]
async fn test_share_credential_no_base_url() {
    let protocol = setup_protocol(None, Repositories::default());
    let credential = generate_credential(None);

    let result = protocol.share_credential(&credential, "jwt_vc_json").await;
    assert!(matches!(result, Err(ExchangeProtocolError::MissingBaseUrl)));
}

#[tokio::test]
async fn test_share_credential_success_no_redirect_uri() {
    let protocol = setup_protocol(Some("http://base_url".to_string()), Repositories::default());
    let credential = generate_credential(None);

    let result = protocol
        .share_credential(&credential, "jwt_vc_json")
        .await
        .unwrap();
    assert_eq!("http://base_url/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential=00000000-0000-0000-0000-000000000000", result.url);
}

#[tokio::test]
async fn test_share_credential_success_with_redirect_uri_is_percent_encoded() {
    let protocol = setup_protocol(Some("http://base_url".to_string()), Repositories::default());
    let credential = generate_credential(Some("http://base_url/redirect?queryParam=1".to_string()));

    let result = protocol
        .share_credential(&credential, "jwt_vc_json")
        .await
        .unwrap();
    assert_eq!("http://base_url/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential=00000000-0000-0000-0000-000000000000&redirect_uri=http%3A%2F%2Fbase_url%2Fredirect%3FqueryParam%3D1", result.url);
}

#[tokio::test]
async fn test_share_proof_no_base_url() {
    let protocol = setup_protocol(None, Repositories::default());
    let mut proof = generate_proof(None);

    let did = Did {
        keys: Some(vec![RelatedKey {
            role: KeyRole::KeyAgreement,
            key: dummy_key(),
        }]),
        ..dummy_did()
    };

    proof.verifier_did = Some(did);

    let mut key_alg = MockKeyAlgorithm::default();
    key_alg.expect_bytes_to_jwk().return_once(|_, _| {
        Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
            r#use: Some("enc".to_string()),
            crv: "123".to_string(),
            x: "456".to_string(),
            y: None,
        }))
    });

    let key_alg = Arc::new(key_alg);

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_get_key_algorithm()
        .once()
        .withf(move |alg| {
            assert_eq!(alg, "bar");
            true
        })
        .returning(move |_| Some(key_alg.clone()));

    let formats = create_open_id_for_vp_formats();
    let jwk = get_encryption_key_jwk_from_proof(&proof, &key_algorithm_provider).unwrap();

    let format_type_mapper: FormatMapper = Arc::new(move |input| Ok(input.to_owned()));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(create_format_map);

    let result = protocol
        .share_proof(
            &proof,
            format_type_mapper,
            jwk.key_id,
            jwk.jwk.into(),
            formats,
            type_to_descriptor_mapper,
        )
        .await;
    assert!(matches!(result, Err(ExchangeProtocolError::MissingBaseUrl)));
}

#[tokio::test]
async fn test_share_proof_success_no_redirect_uri() {
    let protocol = setup_protocol(Some("http://base_url".to_string()), Repositories::default());
    let mut proof = generate_proof(None);

    let did = Did {
        keys: Some(vec![RelatedKey {
            role: KeyRole::KeyAgreement,
            key: dummy_key(),
        }]),
        ..dummy_did()
    };

    proof.verifier_did = Some(did);

    let mut key_alg = MockKeyAlgorithm::default();
    key_alg.expect_bytes_to_jwk().return_once(|_, _| {
        Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
            r#use: Some("enc".to_string()),
            crv: "123".to_string(),
            x: "456".to_string(),
            y: None,
        }))
    });

    let key_alg = Arc::new(key_alg);

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_get_key_algorithm()
        .once()
        .withf(move |alg| {
            assert_eq!(alg, "bar");
            true
        })
        .returning(move |_| Some(key_alg.clone()));

    let formats = create_open_id_for_vp_formats();
    let jwk = get_encryption_key_jwk_from_proof(&proof, &key_algorithm_provider).unwrap();

    let format_type_mapper: FormatMapper = Arc::new(move |input| Ok(input.to_owned()));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(create_format_map);

    let result = protocol
        .share_proof(
            &proof,
            format_type_mapper,
            jwk.key_id,
            jwk.jwk.into(),
            formats,
            type_to_descriptor_mapper,
        )
        .await
        .unwrap();
    assert_eq!(format!("http://base_url/ssi/temporary-verifier/v1/connect?protocol=PROCIVIS_TEMPORARY&proof={}", proof.id), result.url);
}

#[tokio::test]
async fn test_share_proof_success_with_redirect_uri_is_percent_encoded() {
    let protocol = setup_protocol(Some("http://base_url".to_string()), Repositories::default());
    let mut proof = generate_proof(Some("http://base_url/redirect?queryParam=1".to_string()));

    let did = Did {
        keys: Some(vec![RelatedKey {
            role: KeyRole::KeyAgreement,
            key: dummy_key(),
        }]),
        ..dummy_did()
    };

    proof.verifier_did = Some(did);

    let mut key_alg = MockKeyAlgorithm::default();
    key_alg.expect_bytes_to_jwk().return_once(|_, _| {
        Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
            r#use: Some("enc".to_string()),
            crv: "123".to_string(),
            x: "456".to_string(),
            y: None,
        }))
    });

    let key_alg = Arc::new(key_alg);

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_get_key_algorithm()
        .once()
        .withf(move |alg| {
            assert_eq!(alg, "bar");
            true
        })
        .returning(move |_| Some(key_alg.clone()));

    let formats = create_open_id_for_vp_formats();
    let jwk = get_encryption_key_jwk_from_proof(&proof, &key_algorithm_provider).unwrap();

    let format_type_mapper: FormatMapper = Arc::new(move |input| Ok(input.to_owned()));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(create_format_map);

    let result = protocol
        .share_proof(
            &proof,
            format_type_mapper,
            jwk.key_id,
            jwk.jwk.into(),
            formats,
            type_to_descriptor_mapper,
        )
        .await
        .unwrap();

    assert_eq!(format!("http://base_url/ssi/temporary-verifier/v1/connect?protocol=PROCIVIS_TEMPORARY&proof={}&redirect_uri=http%3A%2F%2Fbase_url%2Fredirect%3FqueryParam%3D1", proof.id), result.url);
}
