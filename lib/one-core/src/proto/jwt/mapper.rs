use ct_codecs::{Base64UrlSafeNoPadding, Encoder, Error};

pub fn bin_to_b64url_string(bin: &[u8]) -> Result<String, Error> {
    Base64UrlSafeNoPadding::encode_to_string(bin)
}

pub fn string_to_b64url_string(string: &str) -> Result<String, Error> {
    Base64UrlSafeNoPadding::encode_to_string(string)
}
