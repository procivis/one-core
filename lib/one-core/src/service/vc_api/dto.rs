use one_providers::credential_formatter::imp::json_ld::model::{LdCredential, LdPresentation};

#[derive(Debug)]
pub struct CredentialIssueRequest {
    pub credential: LdCredential,
    pub options: Option<CredentialIssueOptions>,
}

#[derive(Debug)]
pub struct CredentialIssueOptions {
    pub signature_algorithm: String,
    pub credential_format: String,
}

#[derive(Debug)]
pub struct CredentialIssueResponse {
    pub verifiable_credential: LdCredential,
}

#[derive(Debug)]
pub struct CredentialVerifiyRequest {
    pub verifiable_credential: LdCredential,
    pub options: Option<VerifyOptions>,
}

#[derive(Debug)]
pub struct VerifyOptions {
    pub checks: Vec<String>,
}

#[derive(Debug)]
pub struct CredentialVerifyResponse {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub credential: LdCredential,
}

#[derive(Debug)]
pub struct PresentationVerifyRequest {
    pub verifiable_presentation: LdPresentation,
    pub options: Option<VerifyOptions>,
}

#[derive(Debug)]
pub struct PresentationVerifyResponse {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
