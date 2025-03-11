use std::collections::HashSet;
use std::sync::Arc;

use assert2::let_assert;
use one_crypto::hasher::sha256::SHA256;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::key::Key;
use crate::provider::credential_formatter::json_ld::json_ld_processor_options;
use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::test_data::{
    document_loader, vc_permanent_resident_card,
};
use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::{
    add_derived_proof, create_base_proof, verify_base_proof, verify_derived_proof,
};
use crate::provider::credential_formatter::model::{
    MockTokenVerifier, SignatureProvider, TokenVerifier,
};
use crate::provider::credential_formatter::vcdm::VcdmCredential;
use crate::provider::key_algorithm::bbs::BBS;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_storage::provider::SignatureProviderImpl;

#[tokio::test]
async fn test_create_and_verify_base_and_derived_proof() {
    let vcdm: VcdmCredential = json_syntax::from_value(vc_permanent_resident_card()).unwrap();
    let mandatory_pointers = ["/issuer", "/credentialSubject/birthDate"]
        .map(ToString::to_string)
        .to_vec();
    let loader = &document_loader();
    let hasher = SHA256 {};
    let auth_fn = &auth_fn();

    // create base proof
    let mut base_proof = create_base_proof(
        &vcdm,
        mandatory_pointers,
        verification_method(),
        loader,
        &hasher,
        auth_fn,
        json_ld_processor_options(),
    )
    .await
    .unwrap();
    base_proof.context = Some(vcdm.context.clone());

    // verify base proof
    verify_base_proof(
        &vcdm,
        base_proof.clone(),
        loader,
        &hasher,
        &verifier(),
        json_ld_processor_options(),
    )
    .await
    .unwrap();

    // create derived proof
    let selective_pointers = [
        "/credentialSubject/givenName",
        "/credentialSubject/familyName",
        "/credentialSubject/permanentResidentCard/lprNumber",
    ]
    .map(ToString::to_string)
    .to_vec();

    let mut vcdm = add_derived_proof(
        &vcdm,
        &base_proof,
        selective_pointers,
        None,
        loader,
        json_ld_processor_options(),
    )
    .await
    .unwrap();

    let_assert!([credential_subject] = vcdm.credential_subject.as_slice());
    let revealed_claims: HashSet<&str> = credential_subject
        .claims
        .keys()
        .map(String::as_str)
        .chain(
            credential_subject.claims["permanentResidentCard"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str),
        )
        .collect();
    assert_eq!(
        revealed_claims,
        maplit::hashset![
            "type",
            "birthDate",
            "givenName",
            "familyName",
            "permanentResidentCard",
            // permanentResidentCard/lprNumber
            "lprNumber",
        ]
    );

    // verify derived proof
    let proof = vcdm.proof.take().unwrap();
    verify_derived_proof(
        &vcdm,
        proof,
        &public_key(),
        &document_loader(),
        &hasher,
        json_ld_processor_options(),
    )
    .await
    .unwrap();
}

fn auth_fn() -> impl SignatureProvider {
    let public_key = public_key();
    let key_handle = BBS
        .reconstruct_key(&public_key, Some(private_key().into()), None)
        .unwrap();

    SignatureProviderImpl {
        key: Key {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key,
            name: "test".to_string(),
            key_reference: vec![],
            storage_type: "test".to_string(),
            key_type: "test".to_string(),
            organisation: None,
        },
        key_handle,
        jwk_key_id: None,
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
    }
}

fn verifier() -> impl TokenVerifier {
    let mut verifier = MockTokenVerifier::new();
    let key_handle = BBS.reconstruct_key(&public_key(), None, None).unwrap();

    verifier
        .expect_verify()
        .returning(move |_, _, _, token, signature| key_handle.verify(token, signature));

    verifier
}

fn public_key() -> Vec<u8> {
    hex::decode("a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f").unwrap()
}

fn private_key() -> Vec<u8> {
    hex::decode("66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0").unwrap()
}

fn verification_method() -> String {
    "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ"
        .to_string()
}
