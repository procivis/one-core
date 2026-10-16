use standardized_types::csc::{
    ConformanceLevel, HashAlgorithm, SignatureAlgorithm, SignatureFormat, SignatureQualifier,
};

pub struct AuthorizationUrlRequest<'a> {
    pub oauth_url: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub account_token: &'a str,
    pub signature_qualifier: SignatureQualifier,
    pub hash: &'a [u8],
    pub hash_algorithm: HashAlgorithm,
}

#[derive(Debug)]
pub struct Authorization {
    pub authorization_url: String,
    pub code_verifier: String,
}

pub struct AuthorizeTlsRequest<'a> {
    pub oauth_url: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub account_token: &'a str,
    pub credential_id: &'a str,
    pub hashes: &'a [&'a [u8]],
    pub hash_algorithm: HashAlgorithm,
}

#[derive(Debug)]
pub struct AuthorizationCode {
    pub code: String,
    pub code_verifier: String,
}

pub struct ClientCredentialsRequest<'a> {
    pub token_url: &'a str,
    pub client_id: &'a str,
    pub client_assertion: &'a str,
    pub scope: &'a str,
    pub authorization_details: Option<&'a str>,
}

pub struct TokenRequest<'a> {
    pub oauth_url: &'a str,
    pub code: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
}

#[derive(Debug)]
pub struct CredentialToken {
    pub access_token: String,
    pub credential_id: String,
}

pub struct SignDocumentRequest<'a> {
    pub api_url: &'a str,
    pub access_token: &'a str,
    pub credential_id: &'a str,
    pub document: &'a [u8],
    pub sign_algo: &'a str,
    pub signature_format: SignatureFormat,
    pub conformance_level: ConformanceLevel,
}

pub struct SignHashesRequest<'a> {
    pub api_url: &'a str,
    pub access_token: &'a str,
    pub credential_id: &'a str,
    pub hashes: &'a [&'a [u8]],
    pub sign_algo: SignatureAlgorithm,
    pub hash_algo: HashAlgorithm,
}
