use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    EncodedPoint,
};

pub fn p_256_sk_vk_pair_from_bytes(private_key: &[u8]) -> Option<(SigningKey, VerifyingKey)> {
    let sk = SigningKey::from_bytes(private_key.into()).ok()?;
    let pk = VerifyingKey::from(&sk);
    Some((sk, pk))
}

pub fn p_256_vk_from_bytes(public_key: &[u8]) -> Option<VerifyingKey> {
    let point = EncodedPoint::from_bytes(public_key).ok()?;
    VerifyingKey::from_encoded_point(&point).ok()
}

pub fn random_p_256() -> Option<(SigningKey, VerifyingKey)> {
    let seed: [u8; 32] = rand::random();
    p_256_sk_vk_pair_from_bytes(&seed)
}
