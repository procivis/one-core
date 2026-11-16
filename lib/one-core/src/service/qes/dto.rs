use shared_types::{DocumentSignerProviderId, OrganisationId};

#[derive(Clone, Debug)]
pub struct QesAuthorizeRequestDTO {
    pub provider: DocumentSignerProviderId,
    pub document: Vec<u8>,
    pub redirect_uri: Option<String>,
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Clone, Debug)]
pub struct QesAuthorizeResponseDTO {
    pub authorization_url: String,
    pub code_verifier: String,
}

#[derive(Clone, Debug)]
pub struct QesSignRequestDTO {
    pub provider: DocumentSignerProviderId,
    pub code: String,
    pub code_verifier: String,
    pub document: Vec<u8>,
    pub redirect_uri: Option<String>,
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Clone, Debug)]
pub struct QesSignResponseDTO {
    pub signed_document: Vec<u8>,
}
