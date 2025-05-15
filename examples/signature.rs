use std::sync::Arc;

use hex_literal::hex;
use one_core::provider::http_client::reqwest_client::ReqwestClient;
use one_dev_services::OneDevCore;
use one_dev_services::model::KeyAlgorithmType;

fn main() {
    let core = OneDevCore::new(None, Arc::new(ReqwestClient::default())).unwrap();

    let key_pair = core
        .signature_service
        .get_key_pair(KeyAlgorithmType::Ecdsa)
        .expect("Key pair creation failed");

    let bytes = hex!("d14ccebdae5153c916d82168c1e2a9e39ab056cfd197c64242151773ce1c61f8");

    let signature = core
        .signature_service
        .sign(
            KeyAlgorithmType::Ecdsa,
            &key_pair.public,
            key_pair.private,
            &bytes,
        )
        .expect("Signing failed");

    let verification = core.signature_service.verify(
        KeyAlgorithmType::Ecdsa,
        &key_pair.public,
        &signature,
        &bytes,
    );

    match verification {
        Ok(_) => println!("Successfully verified"),
        Err(_) => println!("Signature is incorrect"),
    };
}
