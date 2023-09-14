pub enum CredentialStateBindingEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

pub type VersionBindingDTO = one_core::Version;

pub struct ListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
}

pub struct CredentialListBindingDTO {
    pub values: Vec<CredentialListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

pub struct CredentialDetailBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: String,
    pub last_modified: String,
    pub issuer_did: Option<String>,
    pub state: CredentialStateBindingEnum,
    pub claims: Vec<ClaimBindingDTO>,
    pub schema: CredentialSchemaBindingDTO,
}

pub struct CredentialListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: String,
    pub last_modified: String,
    pub issuer_did: Option<String>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
}

pub struct CredentialSchemaBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
}

pub struct ClaimBindingDTO {
    pub id: String,
    pub key: String,
    pub data_type: String,
    pub value: String,
}

pub enum HandleInvitationResponseBindingEnum {
    CredentialIssuance {
        issued_credential_id: String,
    },
    ProofRequest {
        proof_request: ProofRequestBindingDTO,
    },
}

pub struct ProofRequestBindingDTO {
    pub claims: Vec<ProofRequestClaimBindingDTO>,
    pub verifier_did: String,
}

pub struct ProofRequestClaimBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub key: String,
    pub data_type: String,
    pub required: bool,
    pub credential_schema: CredentialSchemaBindingDTO,
}
